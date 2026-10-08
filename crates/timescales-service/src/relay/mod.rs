//! The confidential relay.
//!
//! Sits between traders and the chain. It never sees plaintext. Its jobs:
//!
//! * **check** each submission without state ([`verify_submission`]):
//!   signature, market, envelope version, masked encodings.
//! * **enforce the window**: nothing enters before the epoch opens or after
//!   the cutoff.
//! * **deduplicate** on (commitment, submitting wallet), so no wallet can
//!   keep another wallet's envelope out by submitting under its commitment
//!   first.
//! * **promise** inclusion with an [`InclusionPromiseV2`] that signs the
//!   market address and the digest of the exact envelope.
//! * **close** the epoch at the cutoff ([`Relay::close`]): pad the batch with
//!   cover to a coarse bucket, so the published count is not the real count,
//!   and fix the envelope set and its leaves `C || H(envelope)`. Closing is
//!   idempotent, so a retried commit always carries the same root.
//! * **assemble** the header v2 batch once the beacon is revealed
//!   ([`ClosedBatch::assemble`]).
//! * **refuse** with signed evidence ([`Relay::refusal`]).
//!
//! The node commits the root, persists the closed batch and drives the rest.
//! This relay holds no committer. A promise plus the committed leaves is a
//! transferable proof that the relay left out, or substituted, an envelope it
//! accepted ([`prove_exclusion_v2`]).
//!
//! Cover comes from a fresh OS-seeded RNG for every epoch. Simulation builds
//! keep the version 1 path: `Relay::new_seeded` (a seeded cover RNG, so
//! anyone with the seed can tell cover from real envelopes), `Relay::seal`
//! (commits through a `BatchCommitter` and assembles a header v1) and
//! gossip between relay replicas over the in-memory network.

#![cfg_attr(test, allow(clippy::unwrap_used, clippy::cast_possible_truncation))]

mod close;
pub mod codec;
mod cover;

pub use close::ClosedBatch;
pub use cover::{CarryingCover, CoverSource, EpochKeyCover};

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

#[cfg(feature = "simulation")]
use crate::p2p::Endpoint;
use crate::wire::RelayRefusal;
#[cfg(feature = "simulation")]
use rand::SeedableRng;
use rand::distributions::Bernoulli;
#[cfg(feature = "simulation")]
use rand_chacha::ChaCha20Rng;
use thiserror::Error;
#[cfg(feature = "simulation")]
use timescales_auction::collateral::BalanceSheet;
#[cfg(feature = "simulation")]
use timescales_auction::orderbook::OrderStateTable;
use timescales_auction::{
    Auction, AuctionEpoch, AuctionError, BatchLeaf, CommitError, batch_root, batch_root_v2,
};
#[cfg(feature = "simulation")]
use timescales_auction::{BatchCommitter, BatchHeader};
use timescales_core::crypto::{Hasher, Keypair, Signature, domain, verify_digest};
use timescales_core::identity::{Registry, verify_trader};
use timescales_core::intent::{MaskedIntent, SealedEnvelope};
use timescales_core::{
    Decode, DecodeError, Encode, EpochId, Hash32, MarketId, MarketParams, OrderCommitment,
    PROTOCOL_VERSION, PriceBand, Reader, Tick, TraderId, encoding::put_u8,
};
use timescales_executor::ExecutionBatch;

/// Whether this build includes simulation-only components.
pub const SIMULATION_BUILD: bool = cfg!(feature = "simulation");

#[cfg(feature = "simulation")]
#[used]
static SIMULATION_MARKER: [u8; 29] = *b"timescales:SIMULATION_BUILD=1";

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum RelayError {
    #[error("submitter not authorised")]
    Unauthorised,
    #[error("submission signature invalid")]
    BadSignature,
    #[error("masked encoding does not match envelope")]
    EncodingMismatch,
    #[error("no epoch open")]
    NoEpoch,
    #[error(transparent)]
    Auction(#[from] AuctionError),
    #[error(transparent)]
    Commit(#[from] CommitError),
    #[error("band: {0}")]
    Band(String),
    #[error("cover traffic: {0}")]
    Cover(String),
    #[error("masked encodings are not accepted by this relay")]
    MaskedNotAllowed,
    #[error("an epoch is already open")]
    EpochOpen,
    #[error("commitment already submitted by this submitter")]
    DuplicateForSubmitter,
    #[error("no closed batch")]
    NotClosed,
    #[error("submission refused on restore: {0}")]
    Restore(String),
    #[error("unsupported envelope version {0}")]
    UnsupportedVersion(u8),
    #[error("epoch has no epoch binding: it was opened for header v1 only")]
    Unbound,
    #[error("envelope digest does not match the envelope")]
    DigestMismatch,
}

/// How the published envelope count is coarsened.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Padding {
    None,
    /// Round up to the next power of two, at least `min`.
    PowerOfTwo {
        min: u32,
    },
    /// Always exactly this many (excess submissions are refused).
    Fixed(u32),
}

impl Padding {
    pub fn target(&self, real: usize) -> usize {
        match *self {
            Padding::None => real,
            Padding::PowerOfTwo { min } => real.max(min as usize).next_power_of_two(),
            Padding::Fixed(n) => (n as usize).max(real),
        }
    }
}

/// When version 1 promises from [`Relay::submit`] are released.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AckPolicy {
    Immediate,
    /// Promises are released together when the batch is sealed.
    AtCutoff,
}

/// What a trader hands the relay.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Submission {
    pub envelope: SealedEnvelope,
    /// Optional MPC encoding carrying the same commitment.
    pub masked: Option<MaskedIntent>,
    pub trader: TraderId,
    pub signature: Signature,
}

impl Submission {
    pub fn digest(
        envelope: &SealedEnvelope,
        masked: Option<&MaskedIntent>,
        trader: &TraderId,
    ) -> Hash32 {
        let mut h = Hasher::new(domain::RELAY_SUBMISSION)
            .chain(&envelope.to_bytes())
            .chain(trader.as_bytes());
        if let Some(m) = masked {
            h.update(&m.to_bytes());
        }
        h.finalize()
    }

    pub fn sign(
        key: &timescales_core::identity::TraderKey,
        envelope: SealedEnvelope,
        masked: Option<MaskedIntent>,
    ) -> Self {
        let trader = key.id();
        let signature = key.sign(&Self::digest(&envelope, masked.as_ref(), &trader));
        Self {
            envelope,
            masked,
            trader,
            signature,
        }
    }
}

impl Encode for Submission {
    fn encode(&self, out: &mut Vec<u8>) {
        self.envelope.encode(out);
        match &self.masked {
            None => put_u8(out, 0),
            Some(m) => {
                put_u8(out, 1);
                m.encode(out);
            }
        }
        self.trader.encode(out);
        self.signature.encode(out);
    }
}

impl Decode for Submission {
    fn decode(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        let envelope = SealedEnvelope::decode(r)?;
        let masked = if r.bool()? {
            Some(MaskedIntent::decode(r)?)
        } else {
            None
        };
        Ok(Submission {
            envelope,
            masked,
            trader: TraderId::decode(r)?,
            signature: Signature::decode(r)?,
        })
    }
}

/// The relay's signed commitment to include an envelope in a batch
/// (version 1, legacy: binds the commitment only).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InclusionPromise {
    pub market: MarketId,
    pub epoch: EpochId,
    pub commitment: OrderCommitment,
    pub relay: [u8; 32],
    pub signature: Signature,
}

impl InclusionPromise {
    /// `H(RELAY_SUBMISSION, "promise" || market || epoch || C)`.
    pub fn digest(market: MarketId, epoch: EpochId, c: &OrderCommitment) -> Hash32 {
        Hasher::new(domain::RELAY_SUBMISSION)
            .chain(b"promise")
            .chain(&market.to_bytes())
            .chain(&epoch.to_bytes())
            .chain(c.as_bytes())
            .finalize()
    }

    fn sign(key: &Keypair, market: MarketId, epoch: EpochId, commitment: OrderCommitment) -> Self {
        Self {
            market,
            epoch,
            commitment,
            relay: key.public(),
            signature: key.sign_digest(&Self::digest(market, epoch, &commitment)),
        }
    }

    pub fn verify(&self) -> bool {
        verify_digest(
            &self.relay,
            &Self::digest(self.market, self.epoch, &self.commitment),
            &self.signature,
        )
        .is_ok()
    }
}

/// Evidence check: `promise` is genuine, `committed` hashes to `root`, and
/// the promised commitment is not in it.
///
/// Nothing ties `root` to the promise's market and epoch, so a root read for
/// another batch passes too.
#[deprecated(
    note = "binds neither market nor epoch; use prove_exclusion_for (v1) or prove_exclusion_v2"
)]
pub fn prove_exclusion(
    promise: &InclusionPromise,
    committed: &[OrderCommitment],
    root: &Hash32,
) -> bool {
    promise.verify() && batch_root(committed) == *root && !committed.contains(&promise.commitment)
}

/// Version 1 evidence check against the batch (`market`, `epoch`) whose
/// committed root is `root`: the promise is genuine and for that batch,
/// `committed` hashes to `root`, and the promised commitment is not in it.
pub fn prove_exclusion_for(
    promise: &InclusionPromise,
    market: MarketId,
    epoch: EpochId,
    committed: &[OrderCommitment],
    root: &Hash32,
) -> bool {
    promise.market == market
        && promise.epoch == epoch
        && promise.verify()
        && batch_root(committed) == *root
        && !committed.contains(&promise.commitment)
}

/// Version 2 promise: binds the market address and the digest of the
/// exact envelope, so a substituted envelope is evidence against the relay.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InclusionPromiseV2 {
    pub market: [u8; 32],
    pub epoch: EpochId,
    pub commitment: OrderCommitment,
    pub envelope_digest: Hash32,
    pub relay: [u8; 32],
    pub signature: Signature,
}

impl InclusionPromiseV2 {
    /// `H(RELAY_SUBMISSION, "promise/v2" || market32 || epoch || C || d)`.
    pub fn digest(
        market: &[u8; 32],
        epoch: EpochId,
        commitment: &OrderCommitment,
        envelope_digest: &Hash32,
    ) -> Hash32 {
        Hasher::new(domain::RELAY_SUBMISSION)
            .chain(b"promise/v2")
            .chain(market)
            .chain(&epoch.to_bytes())
            .chain(commitment.as_bytes())
            .chain(envelope_digest.as_bytes())
            .finalize()
    }

    /// `key`'s promise to include the envelope with digest `envelope_digest`
    /// in the batch of (`market`, `epoch`).
    pub fn sign(
        key: &Keypair,
        market: [u8; 32],
        epoch: EpochId,
        commitment: OrderCommitment,
        envelope_digest: Hash32,
    ) -> Self {
        let signature =
            key.sign_digest(&Self::digest(&market, epoch, &commitment, &envelope_digest));
        Self {
            market,
            epoch,
            commitment,
            envelope_digest,
            relay: key.public(),
            signature,
        }
    }

    /// The leaf the promised envelope contributes to the batch root.
    pub fn leaf(&self) -> BatchLeaf {
        BatchLeaf {
            commitment: self.commitment,
            envelope_digest: self.envelope_digest,
        }
    }

    pub fn verify(&self) -> bool {
        verify_digest(
            &self.relay,
            &Self::digest(
                &self.market,
                self.epoch,
                &self.commitment,
                &self.envelope_digest,
            ),
            &self.signature,
        )
        .is_ok()
    }
}

/// Evidence check for a v2 promise against the committed leaves: the
/// promise is genuine and for (`market`, `epoch`), the leaves are the
/// `count` leaves that hash to `root`, and the promised leaf is absent.
///
/// `root` and `count` must be read from the on-chain batch of (`market`,
/// `epoch`). A leaf with the promised commitment but another envelope digest
/// does not count as included: that is a substituted envelope. The caller
/// also checks that `promise.relay` was the market's relay when it signed.
pub fn prove_exclusion_v2(
    promise: &InclusionPromiseV2,
    leaves: &[BatchLeaf],
    market: &[u8; 32],
    epoch: EpochId,
    root: &Hash32,
    count: u32,
) -> bool {
    promise.market == *market
        && promise.epoch == epoch
        && u32::try_from(leaves.len()) == Ok(count)
        && promise.verify()
        && batch_root_v2(leaves) == *root
        && !leaves.contains(&promise.leaf())
}

/// A submission that passed [`verify_submission`]: signature, encoding and
/// market checks, with its envelope digest computed once.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedSubmission {
    pub submission: Submission,
    pub envelope_digest: Hash32,
}

/// Stateless checks of one submission against the relay configuration:
/// masked encodings are refused unless `allow_masked`, the envelope is for
/// the configured market and has a version executors can open, the
/// submission signature verifies (strictly), and a masked encoding carries
/// the envelope's market, epoch and commitment, names the signer as its
/// trader and is signed by it.
pub fn verify_submission(
    cfg: &RelayConfig,
    s: &Submission,
) -> Result<VerifiedSubmission, RelayError> {
    if s.masked.is_some() && !cfg.allow_masked {
        return Err(RelayError::MaskedNotAllowed);
    }
    let env = &s.envelope;
    if env.market != cfg.params.market {
        return Err(AuctionError::WrongMarket {
            expected: cfg.params.market,
            got: env.market,
        }
        .into());
    }
    if env.version != PROTOCOL_VERSION {
        return Err(RelayError::UnsupportedVersion(env.version));
    }
    verify_trader(
        &s.trader,
        &Submission::digest(env, s.masked.as_ref(), &s.trader),
        &s.signature,
    )
    .map_err(|_| RelayError::BadSignature)?;
    if let Some(m) = &s.masked {
        if m.commitment != env.commitment || m.market != env.market || m.epoch != env.epoch {
            return Err(RelayError::EncodingMismatch);
        }
        if m.trader().is_some_and(|t| t != s.trader) {
            return Err(RelayError::Unauthorised);
        }
        m.verify_signature().map_err(|_| RelayError::BadSignature)?;
    }
    Ok(VerifiedSubmission {
        envelope_digest: env.digest(),
        submission: s.clone(),
    })
}

#[derive(Clone, Debug)]
pub struct RelayConfig {
    pub params: MarketParams,
    /// Address of the market account. v2 promises and exclusion proofs bind it.
    pub market_address: [u8; 32],
    pub padding: Padding,
    pub allow_masked: bool,
    /// Most real submissions per epoch.
    pub max_real: u32,
    /// Probability, per cover slot, of carrying a cover intent from the
    /// previous epoch instead of sealing a fresh one ([`CarryingCover`]).
    /// Must lie in `[0, 1]`.
    pub carry_p: f64,
}

/// Everything the node persisted about an open epoch, to rebuild the relay
/// after a restart.
#[derive(Clone, Debug)]
pub struct OpenSnapshot {
    pub epoch: EpochId,
    pub opens_at_ms: u64,
    pub cutoff_ms: u64,
    pub band: PriceBand,
    pub price_commitment: Hash32,
    pub binding: Hash32,
    /// Exact 386-byte submissions with the wallet that submitted each.
    pub submissions: Vec<(Vec<u8>, [u8; 32])>,
}

/// A sealed batch ready for execution, and the version 1 promises released
/// with it.
#[derive(Debug)]
pub struct Sealed {
    pub batch: ExecutionBatch,
    pub promises: Vec<InclusionPromise>,
    pub real: usize,
    pub cover: usize,
}

/// `H(RELAY_REFUSAL,...)` over a refusal's bytes before the signature:
/// `market32 || epoch u64 || envelope_digest32 || code u8 ||
/// at_ms u64 || relay32`.
fn refusal_digest(r: &RelayRefusal) -> Hash32 {
    Hasher::new(domain::RELAY_REFUSAL)
        .chain(&r.market)
        .chain(&r.epoch.to_bytes())
        .chain(r.envelope_digest.as_bytes())
        .chain(&[r.code])
        .chain(&r.at_ms.to_le_bytes())
        .chain(&r.relay)
        .finalize()
}

/// Gossip topics.
#[cfg(feature = "simulation")]
const TOPIC_SUBMISSION: u16 = 1;

/// Where cover randomness comes from.
enum CoverRng {
    /// A fresh OS-seeded stream for every epoch.
    Os,
    /// One seeded stream for the relay's lifetime: anyone with the seed can
    /// regenerate every cover envelope.
    #[cfg(feature = "simulation")]
    Seeded(Box<ChaCha20Rng>),
}

/// One accepted envelope of the open epoch.
#[derive(Debug)]
struct Entry {
    submission: Submission,
    envelope_digest: Hash32,
    /// The wallet that submitted it, or the signing trader for version 1
    /// intake.
    submitter: [u8; 32],
    /// Issued by [`Relay::submit_verified`]. Version 1 intake issues
    /// version 1 promises instead.
    promise: Option<InclusionPromiseV2>,
}

#[derive(Debug)]
struct Open {
    /// Window, market, epoch and capacity rules, and the leaf dedup.
    auction: Auction,
    band: PriceBand,
    price_commitment: Hash32,
    /// The epoch binding. `None` when opened for header v1 only.
    binding: Option<Hash32>,
    entries: Vec<Entry>,
    /// `(commitment, submitter)` -> index into `entries`.
    by_submitter: BTreeMap<(OrderCommitment, [u8; 32]), usize>,
    /// Commitments of all entries. Version 1 intake refuses a repeat.
    commitments: BTreeSet<OrderCommitment>,
    /// Version 1 promises held back under [`AckPolicy::AtCutoff`].
    pending: Vec<InclusionPromise>,
    /// Fixed by the first close. Later calls reuse it.
    closing: Option<close::Closing>,
}

impl Open {
    fn epoch(&self) -> EpochId {
        self.auction.timing().epoch
    }

    fn accepting(&self) -> Result<(), RelayError> {
        match self.closing {
            Some(_) => Err(AuctionError::InvalidTransition { from: "Closed" }.into()),
            None => Ok(()),
        }
    }

    /// A header v2 batch needs the binding, and carries no masked encodings.
    fn closable(&self) -> Result<(), RelayError> {
        if self.binding.is_none() {
            return Err(RelayError::Unbound);
        }
        if self.entries.iter().any(|e| e.submission.masked.is_some()) {
            return Err(RelayError::MaskedNotAllowed);
        }
        Ok(())
    }

    /// Version 1 intake: one envelope per commitment.
    fn admit_v1(&mut self, now_ms: u64, v: VerifiedSubmission) -> Result<(), RelayError> {
        self.accepting()?;
        if self.commitments.contains(&v.submission.envelope.commitment) {
            return Err(AuctionError::Duplicate.into());
        }
        self.auction.submit(now_ms, v.submission.envelope.clone())?;
        let submitter = v.submission.trader.0;
        self.push(Entry {
            submission: v.submission,
            envelope_digest: v.envelope_digest,
            submitter,
            promise: None,
        });
        Ok(())
    }

    fn push(&mut self, e: Entry) {
        let c = e.submission.envelope.commitment;
        self.by_submitter
            .insert((c, e.submitter), self.entries.len());
        self.commitments.insert(c);
        self.entries.push(e);
    }
}

pub struct Relay {
    config: RelayConfig,
    key: Arc<Keypair>,
    #[cfg(feature = "simulation")]
    committer: Option<Arc<dyn BatchCommitter>>,
    cover: Box<dyn CoverSource>,
    rng: CoverRng,
    ack: AckPolicy,
    allowlist: Option<Registry<TraderId, ()>>,
    open: Option<Open>,
    #[cfg(feature = "simulation")]
    peers: Option<Endpoint>,
}

impl core::fmt::Debug for Relay {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Relay")
            .field("key", &Hash32(self.key.public()))
            .finish_non_exhaustive()
    }
}

impl Relay {
    /// A relay whose cover RNG is seeded from the OS afresh for every epoch.
    /// Batches are committed by the caller, never by the relay.
    pub fn new(config: RelayConfig, key: Arc<Keypair>, cover: Box<dyn CoverSource>) -> Self {
        Self {
            config,
            key,
            #[cfg(feature = "simulation")]
            committer: None,
            cover,
            rng: CoverRng::Os,
            ack: AckPolicy::Immediate,
            allowlist: None,
            open: None,
            #[cfg(feature = "simulation")]
            peers: None,
        }
    }

    /// A relay with a seeded cover RNG that commits roots itself through
    /// `committer`. Anyone with the seed can tell cover from real
    /// submissions, so this exists for simulations only.
    #[cfg(feature = "simulation")]
    pub fn new_seeded(
        config: RelayConfig,
        key: Arc<Keypair>,
        committer: Arc<dyn BatchCommitter>,
        cover: Box<dyn CoverSource>,
        seed: [u8; 32],
    ) -> Self {
        Self {
            committer: Some(committer),
            rng: CoverRng::Seeded(Box::new(ChaCha20Rng::from_seed(seed))),
            ..Self::new(config, key, cover)
        }
    }

    /// Rebuild an open epoch after a restart, re-verifying every persisted
    /// submission. Each one gets back the promise it had before, byte for
    /// byte (Ed25519 signing is deterministic). Any submission that no
    /// longer verifies or fits fails the whole restore.
    pub fn restore(
        config: RelayConfig,
        key: Arc<Keypair>,
        cover: Box<dyn CoverSource>,
        s: OpenSnapshot,
    ) -> Result<Self, RelayError> {
        let mut relay = Self::new(config, key, cover);
        let timing = AuctionEpoch {
            epoch: s.epoch,
            opens_at_ms: s.opens_at_ms,
            cutoff_ms: s.cutoff_ms,
        };
        // Opening validates the params before it derives the band.
        relay.open_epoch_v2(timing, s.band.reference, s.price_commitment, s.binding)?;
        if relay.open.as_ref().map(|o| o.band) != Some(s.band) {
            return Err(RelayError::Band(
                "snapshot band does not follow from its reference".into(),
            ));
        }
        for (i, (bytes, wallet)) in s.submissions.into_iter().enumerate() {
            let refuse = |e: &dyn core::fmt::Display| RelayError::Restore(format!("#{i}: {e}"));
            let sub = Submission::decode_exact(&bytes).map_err(|e| refuse(&e))?;
            let v = verify_submission(&relay.config, &sub).map_err(|e| refuse(&e))?;
            relay
                .submit_verified(s.opens_at_ms, v, wallet)
                .map_err(|e| refuse(&e))?;
        }
        Ok(relay)
    }

    /// When promises from [`Relay::submit`] are released.
    pub fn with_ack(mut self, ack: AckPolicy) -> Self {
        self.ack = ack;
        self
    }

    /// Accept submissions only from these traders, or for
    /// [`Relay::submit_verified`] these wallets (`None` accepts any).
    pub fn set_allowlist(&mut self, allowlist: Option<Registry<TraderId, ()>>) {
        self.allowlist = allowlist;
    }

    pub fn public_key(&self) -> [u8; 32] {
        self.key.public()
    }

    /// Accept a verified submission from `submitter` and promise its
    /// inclusion. Deduplicates on (commitment, submitter): the identical
    /// envelope again returns the original promise, a different envelope
    /// under the same commitment is refused. Masked encodings are refused,
    /// because a header v2 batch carries none.
    ///
    /// The signature checks of [`verify_submission`] are not repeated, but
    /// the envelope digest is: the promise signs it, and a promise for a
    /// leaf the batch will not hold is evidence against the relay.
    pub fn submit_verified(
        &mut self,
        now_ms: u64,
        v: VerifiedSubmission,
        submitter: [u8; 32],
    ) -> Result<InclusionPromiseV2, RelayError> {
        if v.submission.envelope.digest() != v.envelope_digest {
            return Err(RelayError::DigestMismatch);
        }
        if v.submission.masked.is_some() {
            return Err(RelayError::MaskedNotAllowed);
        }
        if let Some(reg) = &self.allowlist {
            reg.require_active(&TraderId(submitter))
                .map_err(|_| RelayError::Unauthorised)?;
        }
        let market = self.config.market_address;
        let open = self.open.as_mut().ok_or(RelayError::NoEpoch)?;
        let c = v.submission.envelope.commitment;
        if let Some(&i) = open.by_submitter.get(&(c, submitter)) {
            let e = &open.entries[i];
            return match e.promise {
                Some(p) if e.envelope_digest == v.envelope_digest => Ok(p),
                _ => Err(RelayError::DuplicateForSubmitter),
            };
        }
        open.accepting()?;
        open.auction.submit(now_ms, v.submission.envelope.clone())?;
        let promise =
            InclusionPromiseV2::sign(&self.key, market, open.epoch(), c, v.envelope_digest);
        open.push(Entry {
            submission: v.submission,
            envelope_digest: v.envelope_digest,
            submitter,
            promise: Some(promise),
        });
        Ok(promise)
    }

    /// Close the open epoch: pad with cover, fix the envelope set and its
    /// leaves. The batch is never empty, because CommitBatch needs at least
    /// one envelope. Idempotent: repeated calls return the same batch, and
    /// no submission is accepted after the first.
    pub fn close(&mut self, now_ms: u64) -> Result<&ClosedBatch, RelayError> {
        self.open.as_ref().ok_or(RelayError::NoEpoch)?.closable()?;
        Ok(&self.closing(now_ms)?.batch)
    }

    /// The cached closing of the open epoch, made on first use.
    fn closing(&mut self, now_ms: u64) -> Result<&mut close::Closing, RelayError> {
        let open = self.open.as_mut().ok_or(RelayError::NoEpoch)?;
        let closing = match open.closing.take() {
            Some(c) => c,
            None => close::close(
                &self.config,
                self.cover.as_ref(),
                &mut self.rng,
                open,
                now_ms,
            )?,
        };
        Ok(open.closing.insert(closing))
    }

    /// Hand the closed batch over and free the open slot, so the next epoch
    /// can open while this one is committed and executed.
    pub fn take_closed(&mut self) -> Result<ClosedBatch, RelayError> {
        let open = self.open.as_ref().ok_or(RelayError::NotClosed)?;
        if open.closing.is_none() {
            return Err(RelayError::NotClosed);
        }
        open.closable()?;
        self.open
            .take()
            .and_then(|o| o.closing)
            .map(|c| c.batch)
            .ok_or(RelayError::NotClosed)
    }

    /// A relay-signed refusal of an otherwise valid submission: portable
    /// evidence that intake turned the envelope away (`code` is the node's
    /// refusal code).
    pub fn refusal(
        &self,
        epoch: EpochId,
        envelope_digest: Hash32,
        code: u8,
        now_ms: u64,
    ) -> RelayRefusal {
        let mut r = RelayRefusal {
            market: self.config.market_address,
            epoch,
            envelope_digest,
            code,
            at_ms: now_ms,
            relay: self.key.public(),
            signature: Signature([0; 64]),
        };
        r.signature = self.key.sign_digest(&refusal_digest(&r));
        r
    }

    /// Open an epoch for header v1 batches. The band is fixed here, from
    /// the reference price known at open, so traders (and the MPC
    /// encoding) can rely on it. Refused while another epoch is open or
    /// closed but not yet taken.
    pub fn open_epoch(
        &mut self,
        timing: AuctionEpoch,
        reference: Tick,
        price_commitment: Hash32,
    ) -> Result<(), RelayError> {
        self.open_with(timing, reference, price_commitment, None)
    }

    /// Open an epoch whose closed batch becomes a header v2 batch: `binding`
    /// is the epoch binding over the price commitment, the epoch-key
    /// announcement digest and the committee digest.
    pub fn open_epoch_v2(
        &mut self,
        timing: AuctionEpoch,
        reference: Tick,
        price_commitment: Hash32,
        binding: Hash32,
    ) -> Result<(), RelayError> {
        self.open_with(timing, reference, price_commitment, Some(binding))
    }

    fn open_with(
        &mut self,
        timing: AuctionEpoch,
        reference: Tick,
        price_commitment: Hash32,
        binding: Option<Hash32>,
    ) -> Result<(), RelayError> {
        if self.open.is_some() {
            return Err(RelayError::EpochOpen);
        }
        timing.check()?;
        let params = self.config.params;
        params
            .validate()
            .map_err(|e| RelayError::Band(e.to_string()))?;
        let band = params
            .band(reference)
            .map_err(|e| RelayError::Band(e.to_string()))?;
        Bernoulli::new(self.config.carry_p)
            .map_err(|e| RelayError::Cover(format!("carry_p {}: {e}", self.config.carry_p)))?;
        let limit = match self.config.padding {
            Padding::Fixed(n) => n.min(params.max_batch_envelopes),
            _ => params.max_batch_envelopes,
        }
        .min(self.config.max_real);
        self.open = Some(Open {
            auction: Auction::new_v2(params.market, timing, limit),
            band,
            price_commitment,
            binding,
            entries: Vec::new(),
            by_submitter: BTreeMap::new(),
            commitments: BTreeSet::new(),
            pending: Vec::new(),
            closing: None,
        });
        Ok(())
    }

    /// Allowlist, then the stateless checks.
    fn check(&self, s: &Submission) -> Result<VerifiedSubmission, RelayError> {
        if let Some(reg) = &self.allowlist {
            reg.require_active(&s.trader)
                .map_err(|_| RelayError::Unauthorised)?;
        }
        verify_submission(&self.config, s)
    }

    /// Version 1 intake: accept a submission, one per commitment. Returns a
    /// version 1 promise now under [`AckPolicy::Immediate`], `None` under
    /// [`AckPolicy::AtCutoff`].
    pub fn submit(
        &mut self,
        now_ms: u64,
        s: Submission,
    ) -> Result<Option<InclusionPromise>, RelayError> {
        let v = self.check(&s)?;
        let open = self.open.as_mut().ok_or(RelayError::NoEpoch)?;
        open.admit_v1(now_ms, v)?;
        let p = InclusionPromise::sign(
            &self.key,
            self.config.params.market,
            open.epoch(),
            s.envelope.commitment,
        );
        #[cfg(feature = "simulation")]
        if let Some(peers) = &self.peers {
            // Best effort. Anti-entropy covers losses.
            let _ = peers.broadcast(TOPIC_SUBMISSION, &s.to_bytes());
        }
        match self.ack {
            AckPolicy::Immediate => Ok(Some(p)),
            AckPolicy::AtCutoff => {
                open.pending.push(p);
                Ok(None)
            }
        }
    }

    /// Replicate accepted submissions to peers on this endpoint.
    #[cfg(feature = "simulation")]
    pub fn with_peers(mut self, endpoint: Endpoint) -> Self {
        self.peers = Some(endpoint);
        self
    }

    /// Ingest replicated submissions from peers. Duplicates and late
    /// arrivals are ignored. Returns how many were added.
    #[cfg(feature = "simulation")]
    pub fn absorb_gossip(&mut self, now_ms: u64) -> usize {
        let mut inbox = Vec::new();
        if let Some(ep) = self.peers.as_mut() {
            while let Some(m) = ep.try_recv() {
                inbox.push(m);
            }
        }
        let mut added = 0;
        for m in inbox {
            if m.topic != TOPIC_SUBMISSION {
                continue;
            }
            let Ok(s) = Submission::decode_exact(&m.payload) else {
                continue;
            };
            let Ok(v) = self.check(&s) else {
                continue;
            };
            let Some(open) = self.open.as_mut() else {
                continue;
            };
            if open.admit_v1(now_ms, v).is_ok() {
                added += 1;
            }
        }
        added
    }

    /// Re-broadcast every version 1 submission held, so a peer that missed
    /// messages during a partition catches up. Peers drop what they already
    /// have.
    #[cfg(feature = "simulation")]
    pub fn anti_entropy(&self) -> usize {
        let (Some(peers), Some(open)) = (&self.peers, &self.open) else {
            return 0;
        };
        open.entries
            .iter()
            .filter(|e| e.promise.is_none())
            .filter(|e| {
                peers
                    .broadcast(TOPIC_SUBMISSION, &e.submission.to_bytes())
                    .is_ok()
            })
            .count()
    }

    /// Real envelopes accepted into the open epoch.
    pub fn len(&self) -> usize {
        self.open.as_ref().map_or(0, |o| o.entries.len())
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Header v1 path: close the epoch (padding as [`Relay::close`] does),
    /// commit the root through the committer, assemble the header.
    ///
    /// The padded set is fixed before the commit, so retrying after a failed
    /// commit commits the same root.
    #[cfg(feature = "simulation")]
    pub fn seal(
        &mut self,
        now_ms: u64,
        balances: BalanceSheet,
        prior: OrderStateTable,
        prev_receipt: Hash32,
    ) -> Result<Sealed, RelayError> {
        let params = self.config.params;
        let committer = self
            .committer
            .clone()
            .ok_or(RelayError::Commit(CommitError::Unavailable))?;
        self.closing(now_ms)?;
        let open = self.open.as_ref().ok_or(RelayError::NoEpoch)?;
        let closed = &open.closing.as_ref().ok_or(RelayError::NotClosed)?.batch;
        let commitments: Vec<OrderCommitment> =
            closed.envelopes.iter().map(|e| e.commitment).collect();
        let count = closed.real + closed.cover;
        let beacon =
            committer.commit_root(params.market, closed.epoch, batch_root(&commitments), count)?;
        let header = BatchHeader::assemble(
            params,
            closed.epoch,
            closed.band,
            closed.price_commitment,
            &commitments,
            beacon,
            prior.root(),
            balances.root(),
            prev_receipt,
        );
        // Replay the padded set through a fresh header v1 auction.
        let timing = open.auction.timing();
        let mut replay = Auction::new(params.market, timing, count);
        for e in &closed.envelopes {
            replay.submit(timing.opens_at_ms, e.clone())?;
        }
        replay.seal(now_ms, header)?;

        let open = self.open.take().ok_or(RelayError::NoEpoch)?;
        let want_masked = open.entries.iter().any(|e| e.submission.masked.is_some());
        let close::Closing { batch, masked } = open.closing.ok_or(RelayError::NotClosed)?;
        let masked = if want_masked {
            batch
                .envelopes
                .iter()
                .zip(masked)
                .map(|(e, m)| {
                    m.unwrap_or_else(|| {
                        MaskedIntent::noop(params.market, batch.epoch, e.commitment)
                    })
                })
                .collect()
        } else {
            Vec::new()
        };
        Ok(Sealed {
            real: batch.real as usize,
            cover: batch.cover as usize,
            batch: ExecutionBatch {
                header,
                envelopes: batch.envelopes,
                masked,
                balances,
                prior_state: prior,
            },
            promises: open.pending,
        })
    }
}

#[cfg(test)]
mod tests;
