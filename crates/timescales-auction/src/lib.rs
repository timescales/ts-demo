//! Auction epochs and batch sealing.
//!
//! A market runs one batch per epoch. During the open window the relay
//! collects sealed envelopes. At the cutoff it stops accepting, commits the
//! batch root on chain, and the batch becomes immutable. Execution only
//! begins after that commitment, so nothing an executor learns can influence
//! which envelopes are in the batch.
//!
//! Canonical order inside a batch is by *priority key*
//! `H(seed || commitment)`. The batch root is a function of the *set* of
//! envelopes, not of their arrival order, and a trader cannot aim its salt at
//! a position because the seed is unknown when it commits. Whether the relay
//! can grind the order depends on the seed:
//!
//! * Header version 1: `seed = H(market || epoch || root || beacon)`. The
//!   version 1 program took the beacon from the newest slot hash when the
//!   root was committed, a value the relay can read before it commits. The
//!   relay also chooses the cover envelopes and so the root, so it could
//!   re-roll cover until the order suited it. Version 1 headers remain for
//!   simulations.
//! * Header version 2: the beacon comes from two slot hashes at
//!   `commit_slot + d` and `commit_slot + 2d` ([`beacon_v2`]), which do not
//!   exist when the root is committed, and the seed ([`BatchHeader::seed_v2`])
//!   also mixes [`epoch_seed`], which needs the epoch secret. The leader of
//!   the first produced slot at or after the second target can still bias
//!   the beacon, and the relay can time its commit towards such a leader, but
//!   without the epoch secret neither can tell what a bias does to the order.
//!   Holders of the epoch secret (the dealer, a threshold of key-release
//!   members, the host of a simulated enclave) could grind together with the
//!   relay. They can already read every order.

#![cfg_attr(test, allow(clippy::unwrap_used, clippy::cast_possible_truncation))]

pub mod beacon;
pub mod chain;
mod lifecycle;

pub use beacon::{beacon_v2, slot_hashes_entry};
#[cfg(feature = "simulation")]
pub use chain::InMemoryChain;
pub use chain::{BatchCommitter, ChainView, CommitError, CommittedBatch, CommittedStatus};
pub use lifecycle::{Auction, AuctionEpoch, AuctionError, Phase};

use timescales_core::crypto::{Hasher, domain};
use timescales_core::intent::SealedEnvelope;
use timescales_core::merkle::MerkleTree;
use timescales_core::{
    Decode, DecodeError, Encode, EpochId, HEADER_VERSION_ENVELOPE_BOUND, Hash32, MarketId,
    MarketParams, OrderCommitment, PROTOCOL_VERSION, PriceBand, Reader, encoding::put_u8,
    encoding::put_u32,
};

/// Whether this build includes simulation-only components.
pub const SIMULATION_BUILD: bool = cfg!(feature = "simulation");

#[cfg(feature = "simulation")]
#[used]
static SIMULATION_MARKER: [u8; 29] = *b"timescales:SIMULATION_BUILD=1";

/// Everything an executor needs to know about a batch besides the inputs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BatchHeader {
    pub version: u8,
    pub market: MarketId,
    pub epoch: EpochId,
    pub params: MarketParams,
    pub band: PriceBand,
    /// Version 1: digest of the external-data proof the band was derived
    /// from. Version 2: the epoch binding over that digest, the epoch-key
    /// announcement and the committee ([`epoch_binding`]).
    pub price_commitment: Hash32,
    pub envelope_count: u32,
    /// Merkle root over the batch's commitments in ascending byte order.
    pub batch_root: Hash32,
    /// Unpredictable value fixed after `batch_root` is committed on chain.
    pub beacon: Hash32,
    /// Root of the cross-epoch order state the batch executes against.
    pub prior_state_root: Hash32,
    /// Root of the balance snapshot the batch executes against.
    pub balances_root: Hash32,
    /// Digest of the previous epoch's receipt. Chains receipts together.
    pub prev_receipt: Hash32,
}

impl BatchHeader {
    /// Build the header for a sealed set of commitments.
    #[allow(clippy::too_many_arguments)]
    pub fn assemble(
        params: MarketParams,
        epoch: EpochId,
        band: PriceBand,
        price_commitment: Hash32,
        commitments: &[OrderCommitment],
        beacon: Hash32,
        prior_state_root: Hash32,
        balances_root: Hash32,
        prev_receipt: Hash32,
    ) -> Self {
        Self {
            version: PROTOCOL_VERSION,
            market: params.market,
            epoch,
            params,
            band,
            price_commitment,
            envelope_count: u32::try_from(commitments.len()).unwrap_or(u32::MAX),
            batch_root: batch_root(commitments),
            beacon,
            prior_state_root,
            balances_root,
            prev_receipt,
        }
    }

    /// Header version 2: the root is over [`BatchLeaf`]s and the
    /// `price_commitment` slot (bytes `[87..119]`) carries the epoch binding.
    #[allow(clippy::too_many_arguments)]
    pub fn assemble_v2(
        params: MarketParams,
        epoch: EpochId,
        band: PriceBand,
        binding: Hash32,
        leaves: &[BatchLeaf],
        beacon: Hash32,
        prior_state_root: Hash32,
        balances_root: Hash32,
        prev_receipt: Hash32,
    ) -> Self {
        Self {
            version: HEADER_VERSION_ENVELOPE_BOUND,
            market: params.market,
            epoch,
            params,
            band,
            price_commitment: binding,
            envelope_count: u32::try_from(leaves.len()).unwrap_or(u32::MAX),
            batch_root: batch_root_v2(leaves),
            beacon,
            prior_state_root,
            balances_root,
            prev_receipt,
        }
    }

    pub fn seed(&self) -> Hash32 {
        Hasher::new(domain::BATCH_SEED)
            .chain(&self.market.to_bytes())
            .chain(&self.epoch.to_bytes())
            .chain(self.batch_root.as_bytes())
            .chain(self.beacon.as_bytes())
            .finalize()
    }

    /// Priority seed of a version 2 header: mixes in the secret epoch seed,
    /// so only holders of the epoch secret can evaluate the order.
    pub fn seed_v2(&self, epoch_seed: &Hash32) -> Hash32 {
        Hasher::new(domain::BATCH_SEED)
            .chain(b"v2")
            .chain(&self.market.to_bytes())
            .chain(&self.epoch.to_bytes())
            .chain(self.batch_root.as_bytes())
            .chain(self.beacon.as_bytes())
            .chain(epoch_seed.as_bytes())
            .finalize()
    }

    pub fn digest(&self) -> Hash32 {
        Hasher::new(domain::BATCH_HEADER)
            .chain(&self.to_bytes())
            .finalize()
    }
}

/// A header v2 batch leaf: the order commitment and the digest of the exact
/// envelope that carries it.
///
/// The derived order compares the commitment first, then the digest, which is
/// the byte order of [`BatchLeaf::to_bytes`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct BatchLeaf {
    pub commitment: OrderCommitment,
    pub envelope_digest: Hash32,
}

impl BatchLeaf {
    pub const LEN: usize = 64;

    pub fn of(envelope: &SealedEnvelope) -> Self {
        Self {
            commitment: envelope.commitment,
            envelope_digest: envelope.digest(),
        }
    }

    /// `commitment || envelope_digest`, the leaf data and the sort key.
    pub fn to_bytes(&self) -> [u8; 64] {
        let mut b = [0u8; 64];
        b[..32].copy_from_slice(self.commitment.as_bytes());
        b[32..].copy_from_slice(self.envelope_digest.as_bytes());
        b
    }

    pub fn from_bytes(b: &[u8; 64]) -> Self {
        let mut c = [0u8; 32];
        let mut d = [0u8; 32];
        c.copy_from_slice(&b[..32]);
        d.copy_from_slice(&b[32..]);
        Self {
            commitment: OrderCommitment(c),
            envelope_digest: Hash32(d),
        }
    }
}

/// Header v2 root: leaves sorted by their 64-byte encoding, so the root is a
/// function of the set and not of arrival order.
pub fn batch_root_v2(leaves: &[BatchLeaf]) -> Hash32 {
    let mut sorted: Vec<[u8; 64]> = leaves.iter().map(BatchLeaf::to_bytes).collect();
    sorted.sort_unstable();
    MerkleTree::from_data(&sorted).root()
}

/// The header v2 leaves of `envelopes`, sorted as [`batch_root_v2`] hashes
/// them (the order of the published `leaves.bin`).
pub fn batch_leaves(envelopes: &[SealedEnvelope]) -> Vec<BatchLeaf> {
    let mut leaves: Vec<BatchLeaf> = envelopes.iter().map(BatchLeaf::of).collect();
    leaves.sort_unstable();
    leaves
}

/// `H(EPOCH_BINDING, price_commitment || key_digest || committee_digest)`: ties
/// the epoch key and the key-release committee to the committed terms.
pub fn epoch_binding(
    price_commitment: &Hash32,
    key_digest: &Hash32,
    committee_digest: &Hash32,
) -> Hash32 {
    Hasher::new(domain::EPOCH_BINDING)
        .chain(price_commitment.as_bytes())
        .chain(key_digest.as_bytes())
        .chain(committee_digest.as_bytes())
        .finalize()
}

/// `H(EPOCH_TERMS, band || binding)`, which equals the program's check over
/// header bytes `[63..119]` of a version 2 header.
pub fn terms_digest(band: &PriceBand, binding: &Hash32) -> Hash32 {
    Hasher::new(domain::EPOCH_TERMS)
        .chain(&band.to_bytes())
        .chain(binding.as_bytes())
        .finalize()
}

/// `H(EPOCH_SEED, s || market address || epoch)`, where `s` is the 32-byte
/// epoch secret (a scalar, or the dev X25519 secret).
pub fn epoch_seed(secret: &[u8; 32], market: &[u8; 32], epoch: EpochId) -> Hash32 {
    Hasher::new(domain::EPOCH_SEED)
        .chain(secret)
        .chain(market)
        .chain(&epoch.to_bytes())
        .finalize()
}

pub fn priority_key(seed: &Hash32, commitment: &OrderCommitment) -> Hash32 {
    Hasher::new(domain::PRIORITY_KEY)
        .chain(seed.as_bytes())
        .chain(commitment.as_bytes())
        .finalize()
}

/// Root over a set of commitments. Independent of the order they arrived in.
pub fn batch_root(commitments: &[OrderCommitment]) -> Hash32 {
    let mut sorted: Vec<&OrderCommitment> = commitments.iter().collect();
    sorted.sort_unstable();
    let leaves: Vec<&[u8]> = sorted.iter().map(|c| c.as_bytes().as_slice()).collect();
    MerkleTree::from_data(&leaves).root()
}

/// Indices of `envelopes` in canonical execution order, with their keys.
///
/// Ties (only possible for byte-identical commitments) are broken by the
/// envelope's own encoding so the order is total and reproducible.
pub fn canonical_order(seed: &Hash32, envelopes: &[SealedEnvelope]) -> Vec<(usize, Hash32)> {
    canonical_order_by(seed, envelopes, |e| e.commitment, |e| e.to_bytes())
}

/// [`canonical_order`] for any input encoding that carries a commitment.
pub fn canonical_order_by<T>(
    seed: &Hash32,
    items: &[T],
    commitment: impl Fn(&T) -> OrderCommitment,
    tiebreak: impl Fn(&T) -> Vec<u8>,
) -> Vec<(usize, Hash32)> {
    let mut idx: Vec<(usize, Hash32)> = items
        .iter()
        .enumerate()
        .map(|(i, e)| (i, priority_key(seed, &commitment(e))))
        .collect();
    idx.sort_by(|a, b| {
        a.1.cmp(&b.1)
            .then_with(|| tiebreak(&items[a.0]).cmp(&tiebreak(&items[b.0])))
    });
    idx
}

impl Encode for BatchHeader {
    fn encode(&self, out: &mut Vec<u8>) {
        put_u8(out, self.version);
        self.market.encode(out);
        self.epoch.encode(out);
        self.params.encode(out);
        self.band.encode(out);
        self.price_commitment.encode(out);
        put_u32(out, self.envelope_count);
        self.batch_root.encode(out);
        self.beacon.encode(out);
        self.prior_state_root.encode(out);
        self.balances_root.encode(out);
        self.prev_receipt.encode(out);
    }
}

impl Decode for BatchHeader {
    fn decode(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        let h = BatchHeader {
            version: r.u8()?,
            market: MarketId::decode(r)?,
            epoch: EpochId::decode(r)?,
            params: MarketParams::decode(r)?,
            band: PriceBand::decode(r)?,
            price_commitment: Hash32::decode(r)?,
            envelope_count: r.u32()?,
            batch_root: Hash32::decode(r)?,
            beacon: Hash32::decode(r)?,
            prior_state_root: Hash32::decode(r)?,
            balances_root: Hash32::decode(r)?,
            prev_receipt: Hash32::decode(r)?,
        };
        if h.version != PROTOCOL_VERSION && h.version != HEADER_VERSION_ENVELOPE_BOUND {
            return Err(DecodeError::InvalidValue("BatchHeader.version"));
        }
        if h.params.market != h.market {
            return Err(DecodeError::InvalidValue("BatchHeader.market"));
        }
        Ok(h)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn root_ignores_arrival_order() {
        let a = OrderCommitment([1; 32]);
        let b = OrderCommitment([2; 32]);
        let c = OrderCommitment([3; 32]);
        assert_eq!(batch_root(&[a, b, c]), batch_root(&[c, a, b]));
        assert_ne!(batch_root(&[a, b]), batch_root(&[a, b, c]));
    }

    #[test]
    fn priority_depends_on_seed() {
        let c = OrderCommitment([7; 32]);
        assert_ne!(
            priority_key(&Hash32([0; 32]), &c),
            priority_key(&Hash32([1; 32]), &c)
        );
    }
}

pub mod clearing;
pub mod collateral;
pub mod orderbook;
pub mod risk;
