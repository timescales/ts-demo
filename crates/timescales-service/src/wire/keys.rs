//! Epoch-key dealing: announcements, member acks, bundles and share
//! deliveries.
//!
//! ```text
//! EpochKeyAnnouncement = ver u8 (1) || market32 || epoch u64 || committee_digest32 || scheme u8
//!                        || epoch_pk32 || seq<[32]> (len = t <= 16, 0 for Dev)
//! EpochKeyAck          = member u8 || policy_digest32 || sig64
//! EpochKeyBundle       = announcement || seq<EpochKeyAck> (<= 16, strictly increasing member)
//! ShareDelivery        = announcement || member u8 || SealedBox
//! AnnouncementQuery    = market32 || epoch u64
//! AnnouncementReply    = u8 present || [EpochKeyAnnouncement || EpochKeyAck]
//! ```
//!
//! A member acks with its identity key over
//! `H(EPOCH_KEY_ACK, announcement digest || policy digest)`, so an ack also
//! names the release policy the member applies to that key. A share is
//! sealed to the member's transport key with info
//! `KRC_SHARE || market32 || epoch || member` and the announcement digest as
//! AAD, so it opens only for that member, that epoch and that announcement.

use curve25519_dalek::scalar::Scalar;
use rand_core::CryptoRngCore;
use timescales_core::crypto::threshold::ScalarShare;
use timescales_core::crypto::{
    Hasher, Keypair, SealSecret, SealedBox, Signature, domain, open, seal, verify_digest,
};
use timescales_core::{
    Decode, DecodeError, Encode, EpochId, Hash32, Reader,
    encoding::{put_bool, put_seq, put_u8},
};
use timescales_executor::tee::codec::{SHARE_CIPHERTEXT_LEN, SHARE_PLAINTEXT_LEN};
use zeroize::{Zeroize, Zeroizing};

use crate::wire::committee::MAX_COMMITTEE;
use crate::wire::points::{decompress_canonical, is_prime_order};
use crate::wire::{CommitteeDescription, CommitteeMember, WireError};

/// Encoded share box: ephemeral key, length prefix and the ciphertext of
/// `index u8 || scalar32`, the plaintext a released share carries too.
const SHARE_BOX_LEN: usize = 32 + 4 + SHARE_CIPHERTEXT_LEN;

#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyScheme {
    /// Simulation only.
    DevX25519 = 0,
    FeldmanEd25519 = 1,
}

impl Encode for KeyScheme {
    fn encode(&self, out: &mut Vec<u8>) {
        put_u8(out, *self as u8);
    }
}

impl Decode for KeyScheme {
    fn decode(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        match r.u8()? {
            0 => Ok(KeyScheme::DevX25519),
            1 => Ok(KeyScheme::FeldmanEd25519),
            tag => Err(DecodeError::InvalidTag {
                ty: "KeyScheme",
                tag,
            }),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EpochKeyAnnouncement {
    pub version: u8,
    pub market: [u8; 32],
    pub epoch: EpochId,
    pub committee_digest: Hash32,
    pub scheme: KeyScheme,
    pub epoch_pk: [u8; 32],
    /// Compressed Edwards points, `len = t`.
    pub commitments: Vec<[u8; 32]>,
}

impl EpochKeyAnnouncement {
    pub const VERSION: u8 = 1;
    /// No commitments (the dev scheme).
    pub const MIN_ENCODED_LEN: usize = 1 + 32 + 8 + 32 + 1 + 32 + 4;

    /// `H(EPOCH_KEY, encoding)`.
    pub fn digest(&self) -> Hash32 {
        Hasher::new(domain::EPOCH_KEY)
            .chain(&self.to_bytes())
            .finalize()
    }

    /// Feldman: commitments.len == t, every C_j decompresses, C_0
    /// torsion-free and != identity, u(C_0) == epoch_pk.
    ///
    /// The later commitments must be prime-order points other than the
    /// identity as well (checks each commitment). An honest dealer's
    /// `a_j*B` always is. An identity `C_{t-1}` would mean a polynomial of
    /// lower degree, which fewer than `t` shares reconstruct.
    pub fn check_structure(&self, threshold: u8, allow_dev: bool) -> Result<(), WireError> {
        if self.version != Self::VERSION {
            return Err(WireError::Version(self.version));
        }
        match self.scheme {
            KeyScheme::DevX25519 => {
                if !allow_dev {
                    return Err(WireError::Scheme);
                }
                if !self.commitments.is_empty() {
                    return Err(WireError::Committee(
                        "dev announcements carry no commitments",
                    ));
                }
                Ok(())
            }
            KeyScheme::FeldmanEd25519 => {
                if threshold == 0 || self.commitments.len() != usize::from(threshold) {
                    return Err(WireError::Committee(
                        "commitment count differs from the threshold",
                    ));
                }
                let points = self
                    .commitments
                    .iter()
                    .map(decompress_canonical)
                    .collect::<Option<Vec<_>>>()
                    .ok_or(WireError::BadPoint("commitment is not a canonical point"))?;
                let (c0, rest) = points
                    .split_first()
                    .ok_or(WireError::Committee("no commitments"))?;
                if !is_prime_order(c0) {
                    return Err(WireError::BadPoint(
                        "C_0 is the identity or has a torsion component",
                    ));
                }
                if !rest.iter().all(is_prime_order) {
                    return Err(WireError::BadPoint(
                        "commitment is the identity or has a torsion component",
                    ));
                }
                if c0.to_montgomery().to_bytes() != self.epoch_pk {
                    return Err(WireError::BadPoint("epoch_pk is not u(C_0)"));
                }
                Ok(())
            }
        }
    }
}

impl Encode for EpochKeyAnnouncement {
    fn encode(&self, out: &mut Vec<u8>) {
        put_u8(out, self.version);
        out.extend_from_slice(&self.market);
        self.epoch.encode(out);
        self.committee_digest.encode(out);
        self.scheme.encode(out);
        out.extend_from_slice(&self.epoch_pk);
        put_seq(out, &self.commitments);
    }
}

impl Decode for EpochKeyAnnouncement {
    fn decode(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        if r.u8()? != Self::VERSION {
            return Err(DecodeError::InvalidValue("EpochKeyAnnouncement.version"));
        }
        Ok(EpochKeyAnnouncement {
            version: Self::VERSION,
            market: r.array()?,
            epoch: EpochId::decode(r)?,
            committee_digest: Hash32::decode(r)?,
            scheme: KeyScheme::decode(r)?,
            epoch_pk: r.array()?,
            commitments: r.seq(MAX_COMMITTEE)?,
        })
    }
}

/// `H(EPOCH_KEY_ACK, announcement digest || policy digest)`, what a member
/// signs to vouch for an epoch key under its release policy.
pub fn ack_digest(announcement_digest: &Hash32, policy_digest: &Hash32) -> Hash32 {
    Hasher::new(domain::EPOCH_KEY_ACK)
        .chain(announcement_digest.as_bytes())
        .chain(policy_digest.as_bytes())
        .finalize()
}

/// A member's ack: signature over H(EPOCH_KEY_ACK, announcement digest ||
/// policy digest).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EpochKeyAck {
    pub member: u8,
    pub policy_digest: Hash32,
    pub signature: Signature,
}

impl EpochKeyAck {
    pub const ENCODED_LEN: usize = 1 + 32 + 64;
    pub const MIN_ENCODED_LEN: usize = Self::ENCODED_LEN;

    pub fn sign(
        member: u8,
        announcement_digest: &Hash32,
        policy_digest: Hash32,
        identity: &Keypair,
    ) -> Self {
        EpochKeyAck {
            member,
            policy_digest,
            signature: identity.sign_digest(&ack_digest(announcement_digest, &policy_digest)),
        }
    }

    pub fn verify(
        &self,
        announcement_digest: &Hash32,
        identity: &[u8; 32],
    ) -> Result<(), WireError> {
        verify_digest(
            identity,
            &ack_digest(announcement_digest, &self.policy_digest),
            &self.signature,
        )
        .map_err(|_| WireError::BadSignature)
    }
}

impl Encode for EpochKeyAck {
    fn encode(&self, out: &mut Vec<u8>) {
        put_u8(out, self.member);
        self.policy_digest.encode(out);
        self.signature.encode(out);
    }
}

impl Decode for EpochKeyAck {
    fn decode(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        Ok(EpochKeyAck {
            member: r.u8()?,
            policy_digest: Hash32::decode(r)?,
            signature: Signature::decode(r)?,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EpochKeyBundle {
    pub announcement: EpochKeyAnnouncement,
    pub acks: Vec<EpochKeyAck>,
}

impl EpochKeyBundle {
    /// The dev-scheme announcement and no acks.
    pub const MIN_ENCODED_LEN: usize = EpochKeyAnnouncement::MIN_ENCODED_LEN + 4;

    /// committee.digest == announcement.committee_digest in
    /// allowed_committee_digests (current or previous on chain). Structure.
    /// At least t distinct valid acks. Returns epoch_pk and the policy digest per
    /// acking member.
    ///
    /// The committee is validated and must be for the announcement's
    /// market. Every ack must come from a committee member, in strictly
    /// increasing member order, with a valid signature: a bundle with one bad
    /// ack is refused even if `t` others are good.
    #[allow(clippy::type_complexity)]
    pub fn verify(
        &self,
        committee: &CommitteeDescription,
        allowed_committee_digests: &[Hash32],
        allow_dev: bool,
    ) -> Result<([u8; 32], Vec<(u8, Hash32)>), WireError> {
        committee.validate()?;
        let ann = &self.announcement;
        let digest = committee.digest();
        if ann.committee_digest != digest
            || !allowed_committee_digests.contains(&digest)
            || ann.market != committee.market
        {
            return Err(WireError::CommitteeMismatch);
        }
        ann.check_structure(committee.threshold, allow_dev)?;
        let got = u8::try_from(self.acks.len()).unwrap_or(u8::MAX);
        if got < committee.threshold {
            return Err(WireError::Threshold {
                got,
                need: committee.threshold,
            });
        }
        let ann_digest = ann.digest();
        let mut vouched = Vec::with_capacity(self.acks.len());
        let mut last = None;
        for ack in &self.acks {
            if last.is_some_and(|l| l >= ack.member) {
                return Err(WireError::Committee(
                    "acks are not in increasing member order",
                ));
            }
            last = Some(ack.member);
            let member = committee
                .member(ack.member)
                .ok_or(WireError::UnknownMember(ack.member))?;
            ack.verify(&ann_digest, &member.identity)?;
            vouched.push((ack.member, ack.policy_digest));
        }
        Ok((ann.epoch_pk, vouched))
    }
}

impl Encode for EpochKeyBundle {
    fn encode(&self, out: &mut Vec<u8>) {
        self.announcement.encode(out);
        put_seq(out, &self.acks);
    }
}

impl Decode for EpochKeyBundle {
    fn decode(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        let announcement = EpochKeyAnnouncement::decode(r)?;
        let acks: Vec<EpochKeyAck> = r.seq(MAX_COMMITTEE)?;
        if acks.windows(2).any(|w| w[0].member >= w[1].member) {
            return Err(DecodeError::InvalidValue("EpochKeyBundle.acks"));
        }
        Ok(EpochKeyBundle { announcement, acks })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ShareDelivery {
    pub announcement: EpochKeyAnnouncement,
    pub member: u8,
    pub sealed: SealedBox,
}

fn share_info(market: &[u8; 32], epoch: EpochId, member: u8) -> Vec<u8> {
    let mut info = Vec::with_capacity(domain::KRC_SHARE.len() + 32 + 8 + 1);
    info.extend_from_slice(domain::KRC_SHARE);
    info.extend_from_slice(market);
    epoch.encode(&mut info);
    put_u8(&mut info, member);
    info
}

impl ShareDelivery {
    /// The dev-scheme announcement, the member and a share box.
    pub const MIN_ENCODED_LEN: usize = EpochKeyAnnouncement::MIN_ENCODED_LEN + 1 + SHARE_BOX_LEN;

    /// Seals `share` to `to`'s transport key. The share must be `to`'s.
    pub fn seal(
        rng: &mut impl CryptoRngCore,
        ann: EpochKeyAnnouncement,
        to: &CommitteeMember,
        share: &ScalarShare,
    ) -> Result<Self, WireError> {
        if share.index == 0 || share.index != to.index {
            return Err(WireError::UnknownMember(share.index));
        }
        let mut pt = Zeroizing::new([0u8; SHARE_PLAINTEXT_LEN]);
        pt[0] = share.index;
        pt[1..].copy_from_slice(share.value.as_bytes());
        let sealed = seal(
            rng,
            &to.transport,
            &share_info(&ann.market, ann.epoch, to.index),
            ann.digest().as_bytes(),
            &pt[..],
        )
        .map_err(|_| WireError::BadPoint("member transport key"))?;
        Ok(ShareDelivery {
            announcement: ann,
            member: to.index,
            sealed,
        })
    }

    /// The returned share zeroizes on drop.
    pub fn open(&self, transport: &SealSecret) -> Result<ScalarShare, WireError> {
        let mut pt = open(
            transport,
            &self.sealed.ephemeral,
            &share_info(
                &self.announcement.market,
                self.announcement.epoch,
                self.member,
            ),
            self.announcement.digest().as_bytes(),
            &self.sealed.ciphertext,
        )
        .map_err(|_| WireError::Decode(DecodeError::InvalidValue("ShareDelivery.sealed")))?;
        let share = share_from_plaintext(&pt, self.member);
        pt.zeroize();
        share
    }
}

fn share_from_plaintext(pt: &[u8], member: u8) -> Result<ScalarShare, WireError> {
    let malformed = || WireError::Decode(DecodeError::InvalidValue("ShareDelivery plaintext"));
    let (&index, value) = pt.split_first().ok_or_else(malformed)?;
    if index != member {
        return Err(WireError::UnknownMember(index));
    }
    let bytes = Zeroizing::new(<[u8; 32]>::try_from(value).map_err(|_| malformed())?);
    let value =
        Option::<Scalar>::from(Scalar::from_canonical_bytes(*bytes)).ok_or_else(malformed)?;
    Ok(ScalarShare { index, value })
}

impl Encode for ShareDelivery {
    fn encode(&self, out: &mut Vec<u8>) {
        self.announcement.encode(out);
        put_u8(out, self.member);
        self.sealed.encode(out);
    }
}

impl Decode for ShareDelivery {
    fn decode(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        let announcement = EpochKeyAnnouncement::decode(r)?;
        let member = r.u8()?;
        let sealed = SealedBox::decode(r)?;
        if sealed.ciphertext.len() != SHARE_CIPHERTEXT_LEN {
            return Err(DecodeError::InvalidValue("ShareDelivery.sealed"));
        }
        Ok(ShareDelivery {
            announcement,
            member,
            sealed,
        })
    }
}

/// Dealer -> member during recovery.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AnnouncementQuery {
    pub market: [u8; 32],
    pub epoch: EpochId,
}

impl AnnouncementQuery {
    pub const ENCODED_LEN: usize = 32 + 8;
    pub const MIN_ENCODED_LEN: usize = Self::ENCODED_LEN;
}

impl Encode for AnnouncementQuery {
    fn encode(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.market);
        self.epoch.encode(out);
    }
}

impl Decode for AnnouncementQuery {
    fn decode(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        Ok(AnnouncementQuery {
            market: r.array()?,
            epoch: EpochId::decode(r)?,
        })
    }
}

/// The member's stored announcement and its own ack, if it holds one.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AnnouncementReply(pub Option<(EpochKeyAnnouncement, EpochKeyAck)>);

impl AnnouncementReply {
    /// Nothing held.
    pub const MIN_ENCODED_LEN: usize = 1;
}

impl Encode for AnnouncementReply {
    fn encode(&self, out: &mut Vec<u8>) {
        put_bool(out, self.0.is_some());
        if let Some((ann, ack)) = &self.0 {
            ann.encode(out);
            ack.encode(out);
        }
    }
}

impl Decode for AnnouncementReply {
    fn decode(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        if !r.bool()? {
            return Ok(AnnouncementReply(None));
        }
        let ann = EpochKeyAnnouncement::decode(r)?;
        let ack = EpochKeyAck::decode(r)?;
        Ok(AnnouncementReply(Some((ann, ack))))
    }
}
