//! The key-release committee and its members' release policies.
//!
//! ```text
//! CommitteeDescription   = ver u8 (1) || market32 || t u8 || seq<(index u8 || identity32 || transport32)> (1..= 16)
//! ReleasePolicyStatement = ver u8 (1) || market32 || member u8 || committee_digest32 || platforms u8
//!                          || measurement_set_digest32 || allow_debug bool || min_tcb u8
//!                          || mr_config_id48 || from_epoch u64 || sig64
//! ```
//!
//! The committee digest is `H(COMMITTEE, encoding)` and is anchored on chain.
//! A policy statement is signed by the member's identity key over
//! `H(RELEASE_POLICY, bytes before sig)`. That digest is what every epoch-key
//! ack carries.

use std::collections::BTreeSet;

use timescales_core::crypto::{Hasher, Keypair, Signature, domain, verify_digest};
use timescales_core::{
    Decode, DecodeError, Encode, EpochId, Hash32, Reader,
    encoding::{put_bool, put_seq, put_u8},
};

use crate::wire::WireError;
use crate::wire::points::decompress_canonical;

/// Most members (and so commitments and acks) a committee can have.
pub const MAX_COMMITTEE: usize = 16;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CommitteeMember {
    pub index: u8,
    /// Ed25519 key: signs acks, responses and nothing else.
    pub identity: [u8; 32],
    /// X25519 key: receives shares.
    pub transport: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CommitteeDescription {
    pub version: u8,
    pub market: [u8; 32],
    pub threshold: u8,
    pub members: Vec<CommitteeMember>,
}

impl CommitteeMember {
    pub const ENCODED_LEN: usize = 1 + 32 + 32;
    pub const MIN_ENCODED_LEN: usize = Self::ENCODED_LEN;
}

impl CommitteeDescription {
    pub const VERSION: u8 = 1;
    /// One member.
    pub const MIN_ENCODED_LEN: usize = 1 + 32 + 1 + 4 + CommitteeMember::ENCODED_LEN;

    /// 1 <= t <= n <= 16. n <= 2t - 1 (no two disjoint quorums). Indices 1..=n
    /// strictly increasing. Keys distinct, non-zero, valid points.
    pub fn validate(&self) -> Result<(), WireError> {
        if self.version != Self::VERSION {
            return Err(WireError::Version(self.version));
        }
        let n = self.members.len();
        let t = usize::from(self.threshold);
        if t == 0 || t > n || n > MAX_COMMITTEE {
            return Err(WireError::Committee("threshold out of range"));
        }
        if n > 2 * t - 1 {
            return Err(WireError::Committee(
                "two disjoint quorums are possible (n > 2t - 1)",
            ));
        }
        for (i, m) in self.members.iter().enumerate() {
            if usize::from(m.index) != i + 1 {
                return Err(WireError::Committee(
                    "member indices must be 1..=n in order",
                ));
            }
            if m.identity == [0; 32] || m.transport == [0; 32] {
                return Err(WireError::Committee("zero member key"));
            }
            if decompress_canonical(&m.identity).is_none() {
                return Err(WireError::Committee("member identity is not a valid point"));
            }
        }
        let keys: BTreeSet<&[u8; 32]> = self
            .members
            .iter()
            .flat_map(|m| [&m.identity, &m.transport])
            .collect();
        if keys.len() != 2 * n {
            return Err(WireError::Committee("duplicate member key"));
        }
        Ok(())
    }

    /// `H(COMMITTEE, encoding)`.
    pub fn digest(&self) -> Hash32 {
        Hasher::new(domain::COMMITTEE)
            .chain(&self.to_bytes())
            .finalize()
    }

    pub fn member(&self, index: u8) -> Option<&CommitteeMember> {
        self.members.iter().find(|m| m.index == index)
    }
}

impl Encode for CommitteeMember {
    fn encode(&self, out: &mut Vec<u8>) {
        put_u8(out, self.index);
        out.extend_from_slice(&self.identity);
        out.extend_from_slice(&self.transport);
    }
}

impl Decode for CommitteeMember {
    fn decode(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        Ok(CommitteeMember {
            index: r.u8()?,
            identity: r.array()?,
            transport: r.array()?,
        })
    }
}

impl Encode for CommitteeDescription {
    fn encode(&self, out: &mut Vec<u8>) {
        put_u8(out, self.version);
        out.extend_from_slice(&self.market);
        put_u8(out, self.threshold);
        put_seq(out, &self.members);
    }
}

impl Decode for CommitteeDescription {
    fn decode(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        if r.u8()? != Self::VERSION {
            return Err(DecodeError::InvalidValue("CommitteeDescription.version"));
        }
        let market = r.array()?;
        let threshold = r.u8()?;
        let members: Vec<CommitteeMember> = r.seq(MAX_COMMITTEE)?;
        if members.is_empty() {
            return Err(DecodeError::InvalidValue("CommitteeDescription.members"));
        }
        Ok(CommitteeDescription {
            version: Self::VERSION,
            market,
            threshold,
            members,
        })
    }
}

/// What a member promises about its release policy. Signed by the member
/// identity. Its digest is in every ack.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReleasePolicyStatement {
    pub version: u8,
    pub market: [u8; 32],
    pub member: u8,
    pub committee_digest: Hash32,
    /// Bit 0 simulated, bit 1 intel_tdx.
    pub platforms: u8,
    pub measurement_set_digest: Hash32,
    pub allow_debug: bool,
    pub min_tcb: u8,
    pub mr_config_id: [u8; 48],
    pub from_epoch: EpochId,
    pub signature: Signature,
}

impl ReleasePolicyStatement {
    pub const VERSION: u8 = 1;
    pub const ENCODED_LEN: usize = 1 + 32 + 1 + 32 + 1 + 32 + 1 + 1 + 48 + 8 + 64;
    pub const MIN_ENCODED_LEN: usize = Self::ENCODED_LEN;
    pub const PLATFORM_SIMULATED: u8 = 1;
    pub const PLATFORM_INTEL_TDX: u8 = 2;
    const PLATFORM_BITS: u8 = Self::PLATFORM_SIMULATED | Self::PLATFORM_INTEL_TDX;

    /// Fills in the signature by `identity`. Every other field is kept.
    pub fn sign(mut self, identity: &Keypair) -> Self {
        self.signature = identity.sign_digest(&self.digest());
        self
    }

    /// `H(RELEASE_POLICY, bytes before sig)`.
    pub fn digest(&self) -> Hash32 {
        Hasher::new(domain::RELEASE_POLICY)
            .chain(&self.bytes_before_sig())
            .finalize()
    }

    /// Version, known platform bits and the signature by `identity`. The
    /// caller compares `market`, `member` and `committee_digest` with the
    /// member it expects.
    pub fn verify(&self, identity: &[u8; 32]) -> Result<(), WireError> {
        if self.version != Self::VERSION {
            return Err(WireError::Version(self.version));
        }
        if self.platforms & !Self::PLATFORM_BITS != 0 {
            return Err(WireError::Policy("unknown platform bits"));
        }
        verify_digest(identity, &self.digest(), &self.signature)
            .map_err(|_| WireError::BadSignature)
    }

    fn bytes_before_sig(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(Self::ENCODED_LEN - 64);
        put_u8(&mut out, self.version);
        out.extend_from_slice(&self.market);
        put_u8(&mut out, self.member);
        self.committee_digest.encode(&mut out);
        put_u8(&mut out, self.platforms);
        self.measurement_set_digest.encode(&mut out);
        put_bool(&mut out, self.allow_debug);
        put_u8(&mut out, self.min_tcb);
        out.extend_from_slice(&self.mr_config_id);
        self.from_epoch.encode(&mut out);
        out
    }
}

impl Encode for ReleasePolicyStatement {
    fn encode(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.bytes_before_sig());
        self.signature.encode(out);
    }
}

impl Decode for ReleasePolicyStatement {
    fn decode(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        if r.u8()? != Self::VERSION {
            return Err(DecodeError::InvalidValue("ReleasePolicyStatement.version"));
        }
        let market = r.array()?;
        let member = r.u8()?;
        let committee_digest = Hash32::decode(r)?;
        let platforms = r.u8()?;
        if platforms & !Self::PLATFORM_BITS != 0 {
            return Err(DecodeError::InvalidValue(
                "ReleasePolicyStatement.platforms",
            ));
        }
        Ok(ReleasePolicyStatement {
            version: Self::VERSION,
            market,
            member,
            committee_digest,
            platforms,
            measurement_set_digest: Hash32::decode(r)?,
            allow_debug: r.bool()?,
            min_tcb: r.u8()?,
            mr_config_id: r.array()?,
            from_epoch: EpochId::decode(r)?,
            signature: Signature::decode(r)?,
        })
    }
}
