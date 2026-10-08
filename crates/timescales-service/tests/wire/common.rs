//! Builders shared by the wire tests: keys, committees, a Feldman dealing
//! computed directly on the curve, and batches.

use curve25519_dalek::constants::ED25519_BASEPOINT_POINT;
use curve25519_dalek::edwards::EdwardsPoint;
use curve25519_dalek::scalar::Scalar;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use timescales_auction::{BatchHeader, BatchLeaf};
use timescales_core::crypto::threshold::ScalarShare;
use timescales_core::crypto::{Keypair, SealSecret, Signature};
use timescales_core::intent::{CIPHERTEXT_LEN, SealedEnvelope};
use timescales_core::{
    CommitmentScheme, Decode, EpochId, FeeBps, FlowMode, Hash32, MarketId, MarketParams,
    OrderCommitment, Rationing, Tick,
};
use timescales_executor::ExecutionBatch;
use timescales_service::wire::{
    CommitteeDescription, CommitteeMember, EpochKeyAck, EpochKeyAnnouncement, EpochKeyBundle,
    KeyScheme, ReleasePolicyStatement,
};

pub(crate) const MARKET: [u8; 32] = [0x4d; 32];
pub(crate) const EPOCH: EpochId = EpochId(17);

pub(crate) fn rng(seed: u64) -> ChaCha20Rng {
    ChaCha20Rng::seed_from_u64(seed)
}

pub(crate) fn keypair(seed: u8) -> Keypair {
    Keypair::from_seed([seed; 32])
}

/// A committee with its members' identity and transport secrets.
pub(crate) struct Committee {
    pub(crate) desc: CommitteeDescription,
    pub(crate) identities: Vec<Keypair>,
    pub(crate) transports: Vec<SealSecret>,
}

impl Committee {
    pub(crate) fn new(t: u8, n: u8) -> Self {
        let mut r = rng(u64::from(t) << 8 | u64::from(n));
        let identities: Vec<Keypair> = (0..n).map(|_| Keypair::generate(&mut r)).collect();
        let transports: Vec<SealSecret> = (0..n).map(|_| SealSecret::generate(&mut r)).collect();
        let members = (1..=n)
            .zip(identities.iter().zip(&transports))
            .map(|(index, (id, tr))| CommitteeMember {
                index,
                identity: id.public(),
                transport: tr.public(),
            })
            .collect();
        Committee {
            desc: CommitteeDescription {
                version: CommitteeDescription::VERSION,
                market: MARKET,
                threshold: t,
                members,
            },
            identities,
            transports,
        }
    }

    pub(crate) fn identity(&self, member: u8) -> &Keypair {
        &self.identities[usize::from(member) - 1]
    }

    pub(crate) fn transport(&self, member: u8) -> &SealSecret {
        &self.transports[usize::from(member) - 1]
    }

    /// Member `member`'s signed release policy.
    pub(crate) fn policy(&self, member: u8) -> ReleasePolicyStatement {
        policy_statement(member, self.desc.digest()).sign(self.identity(member))
    }

    /// `ann` acked by `members`, each under its own policy digest.
    pub(crate) fn bundle(&self, ann: &EpochKeyAnnouncement, members: &[u8]) -> EpochKeyBundle {
        let d = ann.digest();
        EpochKeyBundle {
            announcement: ann.clone(),
            acks: members
                .iter()
                .map(|m| EpochKeyAck::sign(*m, &d, self.policy(*m).digest(), self.identity(*m)))
                .collect(),
        }
    }
}

pub(crate) fn policy_statement(member: u8, committee_digest: Hash32) -> ReleasePolicyStatement {
    ReleasePolicyStatement {
        version: ReleasePolicyStatement::VERSION,
        market: MARKET,
        member,
        committee_digest,
        platforms: ReleasePolicyStatement::PLATFORM_INTEL_TDX,
        measurement_set_digest: Hash32([0x6d; 32]),
        allow_debug: false,
        min_tcb: 0,
        mr_config_id: [0x5c; 48],
        from_epoch: EpochId(1),
        signature: Signature([0; 64]),
    }
}

/// A Feldman dealing `f(x) = a_0 + a_1 x +... + a_{t-1} x^{t-1}`.
pub(crate) struct Dealing {
    pub(crate) coefficients: Vec<Scalar>,
}

impl Dealing {
    pub(crate) fn new(seed: u64, t: u8) -> Self {
        let mut r = rng(seed);
        Dealing {
            coefficients: (0..t).map(|_| Scalar::random(&mut r)).collect(),
        }
    }

    pub(crate) fn commitments(&self) -> Vec<[u8; 32]> {
        self.coefficients
            .iter()
            .map(|a| (a * ED25519_BASEPOINT_POINT).compress().to_bytes())
            .collect()
    }

    /// `u(a_0*B)`, the X25519 public key of the epoch secret.
    pub(crate) fn epoch_pk(&self) -> [u8; 32] {
        (self.coefficients[0] * ED25519_BASEPOINT_POINT)
            .to_montgomery()
            .to_bytes()
    }

    pub(crate) fn share(&self, index: u8) -> ScalarShare {
        let x = Scalar::from(u64::from(index));
        let value = self
            .coefficients
            .iter()
            .rev()
            .fold(Scalar::ZERO, |acc, a| acc * x + a);
        ScalarShare { index, value }
    }

    pub(crate) fn announcement(&self, committee: &CommitteeDescription) -> EpochKeyAnnouncement {
        EpochKeyAnnouncement {
            version: EpochKeyAnnouncement::VERSION,
            market: committee.market,
            epoch: EPOCH,
            committee_digest: committee.digest(),
            scheme: KeyScheme::FeldmanEd25519,
            epoch_pk: self.epoch_pk(),
            commitments: self.commitments(),
        }
    }
}

/// `value*B == sum_j C_j*index^j`.
pub(crate) fn share_matches(share: &ScalarShare, commitments: &[[u8; 32]]) -> bool {
    let x = Scalar::from(u64::from(share.index));
    let mut power = Scalar::ONE;
    let mut sum = EdwardsPoint::default();
    for c in commitments {
        let point = curve25519_dalek::edwards::CompressedEdwardsY(*c)
            .decompress()
            .unwrap();
        sum += point * power;
        power *= x;
    }
    share.value * ED25519_BASEPOINT_POINT == sum
}

pub(crate) fn params() -> MarketParams {
    MarketParams {
        market: MarketId(21),
        base_lot_size: 1_000,
        tick_size: 10,
        band_half_width: 8,
        max_order_lots_log2: 20,
        max_orders_per_trader: 16,
        max_batch_envelopes: 1024,
        max_order_lifetime: 32,
        maker_fee: FeeBps(1),
        taker_fee: FeeBps(4),
        flow: FlowMode::DualFlow,
        rationing: Rationing::ProRata,
        commitment_scheme: CommitmentScheme::Sha256,
    }
}

/// Envelope bytes do not have to open for codec tests.
pub(crate) fn envelope(i: usize) -> SealedEnvelope {
    let b = u8::try_from(i % 251).unwrap();
    SealedEnvelope {
        version: 1,
        market: params().market,
        epoch: EPOCH,
        commitment: OrderCommitment([b; 32]),
        ephemeral: [b ^ 0x55; 32],
        ciphertext: [b ^ 0xaa; CIPHERTEXT_LEN],
    }
}

pub(crate) fn header_v2(envelopes: &[SealedEnvelope], binding: Hash32) -> BatchHeader {
    let p = params();
    let leaves: Vec<BatchLeaf> = envelopes.iter().map(BatchLeaf::of).collect();
    BatchHeader::assemble_v2(
        p,
        EPOCH,
        p.band(Tick(1_000)).unwrap(),
        binding,
        &leaves,
        Hash32([0xbe; 32]),
        Hash32([0x5a; 32]),
        Hash32([0xba; 32]),
        Hash32([0x9e; 32]),
    )
}

/// `count u32 || (trader32 || base u64 || quote u64)*`, traders increasing.
pub(crate) fn balance_sheet_bytes(traders: usize) -> Vec<u8> {
    let mut b = u32::try_from(traders).unwrap().to_le_bytes().to_vec();
    for i in 0..traders {
        let mut trader = [0u8; 32];
        trader[..8].copy_from_slice(&u64::try_from(i).unwrap().to_be_bytes());
        b.extend_from_slice(&trader);
        b.extend_from_slice(&(1_000 * u64::try_from(i).unwrap()).to_le_bytes());
        b.extend_from_slice(&7u64.to_le_bytes());
    }
    b
}

pub(crate) fn batch(envelopes: usize, traders: usize) -> ExecutionBatch {
    let envelopes: Vec<SealedEnvelope> = (0..envelopes).map(envelope).collect();
    ExecutionBatch {
        header: header_v2(&envelopes, Hash32([0xb1; 32])),
        envelopes,
        masked: Vec::new(),
        balances: Decode::decode_exact(&balance_sheet_bytes(traders)).unwrap(),
        prior_state: Default::default(),
    }
}
