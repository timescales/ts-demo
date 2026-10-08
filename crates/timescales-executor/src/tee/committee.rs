//! Threshold key-release committee.
//!
//! Each epoch has its own key pair. Before the epoch opens a dealer splits
//! the secret `t`-of-`n` across the committee with Feldman VSS and
//! publishes the public key and the commitments. Traders seal to the key. A
//! member hands its share to an executor only if all of the following hold
//! (the table, in its order):
//!
//! 1. The executor is registered on chain, and its evidence names the
//!    committee whose announcement the member acked.
//! 2. The evidence carries a fresh nonce this member issued to this
//!    executor for this epoch (consumed by the attempt, valid or not).
//! 3. The batch is committed with a revealed beacon, or, once its receipt is
//!    posted and nothing is applied yet, only for that receipt's header. The
//!    header carries the batch's root, count and beacon, its epoch binding
//!    names this member's announcement and committee, and it extends the
//!    market's settled state. The market is not halted.
//! 4. The evidence verifies and passes the attestation policy.
//! 5. No other header is pinned for the epoch, and fewer than
//!    [`MAX_RELEASES_PER_EPOCH`] releases happened.
//!
//! The decision is [`KeyReleaseMember::decide`], a function of the request,
//! one [`ReleaseContext`] read from chain state and the member's own state
//! (nonces, shares, pins). The share is sealed to the attested key, so the
//! operator of the host sees ciphertext only. Nobody can decrypt an epoch
//! before its contents are fixed on chain, and no secret is shared across
//! epochs.
//!
//! The dealer is a trusted setup step. A distributed key generation
//! would remove it. That is out of scope here.

use std::collections::BTreeMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::attestation::{AttestationError, ExecutorAttestationV2, QuoteVerifier};
use crate::policy::{AttestationPolicy, PolicyViolation};
use rand::RngCore;
#[cfg(feature = "simulation")]
use rand_core::CryptoRng;
use thiserror::Error;
use timescales_auction::{BatchHeader, CommittedStatus, epoch_binding, terms_digest};
#[cfg(feature = "simulation")]
use timescales_core::crypto::threshold::{FeldmanDealing, x25519_public};
#[cfg(feature = "simulation")]
use timescales_core::crypto::{CryptoError, ScalarSealSecret};
use timescales_core::crypto::{SealedBox, Zeroizing, seal, threshold::ScalarShare};
use timescales_core::{
    Encode, EpochId, ExecutorId, HEADER_VERSION_ENVELOPE_BOUND, Hash32, MarketId, MarketParams,
    PROTOCOL_VERSION,
};

pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// Most releases a member makes for one epoch (m).
pub const MAX_RELEASES_PER_EPOCH: u32 = 8;
/// Largest committee (`n <= 16`).
pub const MAX_COMMITTEE: u8 = 16;

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ReleaseError {
    #[error("member unavailable")]
    Unavailable,
    #[error("request not authenticated")]
    Unauthenticated,
    #[error("rate limited")]
    RateLimited,
    #[error("malformed request")]
    BadRequest,
    #[error("executor not registered for this market")]
    NotRegistered,
    #[error("attested committee is not this member's committee")]
    CommitteeMismatch,
    #[error("batch root not committed on chain")]
    NotCommitted,
    #[error("beacon not revealed yet")]
    BeaconMissing,
    #[error("chain state not final or providers disagree")]
    NotFinal,
    #[error("epoch already settled or aborted")]
    EpochClosed,
    #[error("header does not match the committed batch")]
    HeaderMismatch,
    #[error("previous epoch is not terminal")]
    PrevNotTerminal,
    #[error("a different header is pinned for this epoch")]
    HeaderPinned,
    #[error("nonce unknown, expired or already used")]
    BadNonce,
    #[error("attestation: {0}")]
    Attestation(AttestationError),
    #[error("policy: {0}")]
    Policy(PolicyViolation),
    #[error("release limit for this epoch reached")]
    TooManyReleases,
    #[error("no share for this epoch")]
    NoShare,
    #[error("market halted")]
    Halted,
    #[error("epoch binding does not match the committed terms")]
    BindingMismatch,
}

/// A committee configuration that cannot work.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum CommitteeError {
    #[error("member index {0} is outside 1..=16")]
    MemberIndex(u8),
    #[error(
        "member at position {position} has index {index}; members must be in index order 1..=n"
    )]
    IndexOrder { position: usize, index: u8 },
    #[error("threshold {threshold} of {n} members")]
    Threshold { threshold: u8, n: usize },
}

/// What an executor sends to every member.
#[derive(Clone, Debug)]
pub struct KeyReleaseRequest {
    pub header: BatchHeader,
    /// The epoch's price commitment. For a version 2 header the member
    /// recomputes the epoch binding from it.
    pub price_commitment: Hash32,
    pub attestation: ExecutorAttestationV2,
}

/// A share sealed to the requesting enclave.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SealedShare {
    pub member: u8,
    pub sealed: SealedBox,
}

/// The batch as the chain records it, read once per release request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BatchView {
    pub status: CommittedStatus,
    pub root: Hash32,
    pub count: u32,
    pub terms_digest: Hash32,
    pub beacon: Option<Hash32>,
    /// Set once a receipt is posted.
    pub header_digest: Option<Hash32>,
    pub applied_count: u32,
}

/// One consistent read of the chain state a release depends on.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReleaseContext {
    pub executors: Vec<ExecutorId>,
    pub committee_digest: Hash32,
    /// Zero when there is no previous committee.
    pub prev_committee_digest: Hash32,
    pub params: MarketParams,
    pub last_settled: EpochId,
    pub state_root: Hash32,
    pub prev_receipt: Hash32,
    pub halted: bool,
    pub batch: Option<BatchView>,
}

/// The epoch-key announcement a member acked for an epoch: its
/// digest and the committee it names. Releases check the attested
/// committee and the header's epoch binding against it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HeldAnnouncement {
    pub digest: Hash32,
    pub committee_digest: Hash32,
}

pub(crate) fn share_info(market: MarketId, epoch: EpochId) -> Vec<u8> {
    let mut i = b"key-release".to_vec();
    market.encode(&mut i);
    epoch.encode(&mut i);
    i
}

/// Interface to one committee member. Remote in a deployment.
pub trait KeyReleaseService: Send + Sync {
    /// 1-based member index, also the evaluation point of its share.
    fn index(&self) -> u8;

    fn challenge(
        &self,
        market: MarketId,
        epoch: EpochId,
    ) -> BoxFuture<'_, Result<Hash32, ReleaseError>>;

    fn release(&self, req: KeyReleaseRequest) -> BoxFuture<'_, Result<SealedShare, ReleaseError>>;
}

/// Generates and splits epoch keys with Feldman VSS. Trusted and
/// simulation only: the services deal through `timescales-krc`.
#[cfg(feature = "simulation")]
#[derive(Debug)]
pub struct EpochKeyDealer {
    pub threshold: u8,
    pub members: u8,
}

/// Output of dealing one epoch: the public key, the Feldman commitments
/// `C_0..= C_{t-1}` and one share per member, member 1 first.
#[cfg(feature = "simulation")]
#[derive(Debug)]
pub struct DealtEpoch {
    pub public: [u8; 32],
    pub commitments: Vec<[u8; 32]>,
    pub shares: Vec<ScalarShare>,
}

#[cfg(feature = "simulation")]
impl EpochKeyDealer {
    /// Deal a fresh epoch secret. The secret and the polynomial are wiped
    /// before this returns.
    pub fn deal<R: RngCore + CryptoRng>(&self, rng: &mut R) -> Result<DealtEpoch, CryptoError> {
        let (secret, commitments, shares) =
            FeldmanDealing::try_new(rng, self.threshold, self.members)?;
        Ok(DealtEpoch {
            public: x25519_public(&secret),
            commitments,
            shares,
        })
    }

    /// Deal a given secret, for batches sealed to a locally held key.
    pub fn deal_secret<R: RngCore + CryptoRng>(
        &self,
        rng: &mut R,
        secret: &ScalarSealSecret,
    ) -> Result<DealtEpoch, CryptoError> {
        let (commitments, shares) =
            FeldmanDealing::deal_secret(rng, secret.scalar(), self.threshold, self.members)?;
        Ok(DealtEpoch {
            public: secret.public(),
            commitments,
            shares,
        })
    }
}

/// Faults a member can be told to exhibit in tests.
#[cfg(feature = "fault-injection")]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum MemberFault {
    #[default]
    None,
    /// Refuses every call.
    Offline,
    /// Releases a share with flipped bits.
    CorruptShare,
    /// Delays every call.
    Slow(Duration),
}

/// Bounds on outstanding challenge nonces.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NonceLimits {
    pub ttl: Duration,
    /// Per (market, epoch, executor).
    pub per_executor: usize,
    /// Over all markets, epochs and executors.
    pub total: usize,
}

impl Default for NonceLimits {
    fn default() -> Self {
        Self {
            ttl: Duration::from_secs(60),
            per_executor: 16,
            total: 4096,
        }
    }
}

#[derive(Clone, Copy, Debug)]
struct IssuedNonce {
    market: MarketId,
    epoch: EpochId,
    executor: ExecutorId,
    expires: Instant,
}

/// Outstanding nonces. A nonce leaves the book when it is presented,
/// whatever the outcome, and that makes it single-use. Expired ones
/// are dropped whenever the book is touched.
#[derive(Debug, Default)]
struct NonceBook {
    issued: BTreeMap<Hash32, IssuedNonce>,
}

impl NonceBook {
    fn expire(&mut self, now: Instant) {
        self.issued.retain(|_, n| n.expires > now);
    }

    fn issue(
        &mut self,
        limits: &NonceLimits,
        market: MarketId,
        epoch: EpochId,
        executor: ExecutorId,
        now: Instant,
    ) -> Result<Hash32, ReleaseError> {
        self.expire(now);
        if self.issued.len() >= limits.total {
            return Err(ReleaseError::RateLimited);
        }
        let mine = self
            .issued
            .values()
            .filter(|n| n.market == market && n.epoch == epoch && n.executor == executor)
            .count();
        if mine >= limits.per_executor {
            return Err(ReleaseError::RateLimited);
        }
        let mut nonce = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut nonce);
        let nonce = Hash32(nonce);
        self.issued.insert(
            nonce,
            IssuedNonce {
                market,
                epoch,
                executor,
                expires: now + limits.ttl,
            },
        );
        Ok(nonce)
    }

    /// Remove `nonce` and return it if it was issued and is unexpired.
    fn take(&mut self, nonce: &Hash32, now: Instant) -> Option<IssuedNonce> {
        let n = self.issued.remove(nonce)?;
        self.expire(now);
        (n.expires > now).then_some(n)
    }
}

/// What a member holds for one epoch.
struct HeldEpoch {
    share: ScalarShare,
    announcement: HeldAnnouncement,
    pin: Option<Hash32>,
    releases: u32,
}

/// One key-release committee member: its share per epoch, its outstanding
/// nonces, header pins and release counts, and its verifier and policy.
///
/// Everything is held in memory. The member service (`timescales-krc`)
/// reads the chain, persists shares and pins, and calls
/// [`KeyReleaseMember::decide`] with the [`ReleaseContext`] it read.
pub struct KeyReleaseMember {
    index: u8,
    verifier: Arc<dyn QuoteVerifier>,
    policy: AttestationPolicy,
    /// Committee named for shares stored without an announcement.
    committee_digest: Hash32,
    limits: NonceLimits,
    max_releases: u32,
    nonces: Mutex<NonceBook>,
    epochs: Mutex<BTreeMap<(MarketId, EpochId), HeldEpoch>>,
    #[cfg(feature = "simulation")]
    sim: Simulated,
    #[cfg(feature = "fault-injection")]
    fault: Mutex<MemberFault>,
}

/// State of a member that builds its release context from a [`ChainView`]
/// and the request (simulation only).
#[cfg(feature = "simulation")]
#[derive(Default)]
struct Simulated {
    chain: Option<Arc<dyn ChainView>>,
    executors: Mutex<Vec<ExecutorId>>,
    header_v1: bool,
}

pub use timescales_auction::ChainView;
#[cfg(feature = "simulation")]
pub use timescales_auction::InMemoryChain;

impl core::fmt::Debug for KeyReleaseMember {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("KeyReleaseMember")
            .field("index", &self.index)
            .finish_non_exhaustive()
    }
}

impl KeyReleaseMember {
    pub fn new(
        index: u8,
        verifier: Arc<dyn QuoteVerifier>,
        policy: AttestationPolicy,
    ) -> Result<Self, CommitteeError> {
        if index == 0 || index > MAX_COMMITTEE {
            return Err(CommitteeError::MemberIndex(index));
        }
        Ok(Self {
            index,
            verifier,
            policy,
            committee_digest: Hash32::ZERO,
            limits: NonceLimits::default(),
            max_releases: MAX_RELEASES_PER_EPOCH,
            nonces: Mutex::default(),
            epochs: Mutex::default(),
            #[cfg(feature = "simulation")]
            sim: Simulated::default(),
            #[cfg(feature = "fault-injection")]
            fault: Mutex::default(),
        })
    }

    /// The committee digest this member serves, named for shares stored
    /// through [`Self::store_share`] (zero when none is anchored).
    pub fn with_committee_digest(mut self, digest: Hash32) -> Self {
        self.committee_digest = digest;
        self
    }

    pub fn with_nonce_limits(mut self, limits: NonceLimits) -> Self {
        self.limits = limits;
        self
    }

    pub fn index(&self) -> u8 {
        self.index
    }

    pub fn nonce_limits(&self) -> NonceLimits {
        self.limits
    }

    /// Hold the share for (market, epoch) under the member's own committee
    /// digest and no announcement digest. Enough for version 1 headers,
    /// which carry no epoch binding.
    pub fn store_share(
        &self,
        market: MarketId,
        epoch: EpochId,
        share: ScalarShare,
    ) -> Result<(), ReleaseError> {
        let announcement = HeldAnnouncement {
            digest: Hash32::ZERO,
            committee_digest: self.committee_digest,
        };
        self.store_dealt_share(market, epoch, share, announcement)
    }

    /// Hold the share for (market, epoch) dealt under `announcement`.
    /// Storing the same share and announcement again is a no-op. A share
    /// for another index or a different share or announcement for an epoch
    /// that already has one is refused (`BadRequest`): a dealt epoch is
    /// never dealt again.
    pub fn store_dealt_share(
        &self,
        market: MarketId,
        epoch: EpochId,
        share: ScalarShare,
        announcement: HeldAnnouncement,
    ) -> Result<(), ReleaseError> {
        if share.index != self.index {
            return Err(ReleaseError::BadRequest);
        }
        let mut epochs = self.epochs.lock().map_err(|_| ReleaseError::Unavailable)?;
        match epochs.get(&(market, epoch)) {
            Some(held) if held.announcement == announcement && held.share.value == share.value => {
                Ok(())
            }
            Some(_) => Err(ReleaseError::BadRequest),
            None => {
                epochs.insert(
                    (market, epoch),
                    HeldEpoch {
                        share,
                        announcement,
                        pin: None,
                        releases: 0,
                    },
                );
                Ok(())
            }
        }
    }

    /// The header pinned for (market, epoch) and the releases counted for
    /// it, if a release happened. A member service persists these
    /// before it sends the share it was given.
    pub fn pin(&self, market: MarketId, epoch: EpochId) -> Option<(Hash32, u32)> {
        let epochs = self.epochs.lock().ok()?;
        let held = epochs.get(&(market, epoch))?;
        held.pin.map(|p| (p, held.releases))
    }

    /// Restore a persisted pin after a restart, before serving releases for
    /// the epoch. Refused (`HeaderPinned`) if another header is pinned
    /// already, and (`NoShare`) without a share for the epoch.
    pub fn restore_pin(
        &self,
        market: MarketId,
        epoch: EpochId,
        header_digest: Hash32,
        releases: u32,
    ) -> Result<(), ReleaseError> {
        let mut epochs = self.epochs.lock().map_err(|_| ReleaseError::Unavailable)?;
        let held = epochs
            .get_mut(&(market, epoch))
            .ok_or(ReleaseError::NoShare)?;
        if held.pin.is_some_and(|p| p != header_digest) {
            return Err(ReleaseError::HeaderPinned);
        }
        held.pin = Some(header_digest);
        held.releases = held.releases.max(releases);
        Ok(())
    }

    /// Whether a share for (market, epoch) is held.
    pub fn holds(&self, market: MarketId, epoch: EpochId) -> bool {
        self.epochs
            .lock()
            .is_ok_and(|e| e.contains_key(&(market, epoch)))
    }

    /// Destroy shares, pins and outstanding nonces of `market` for every
    /// epoch up to `through` (the market's last terminal epoch), and drop
    /// expired nonces. Returns the number of shares destroyed.
    pub fn prune(&self, market: MarketId, through: EpochId) -> Result<usize, ReleaseError> {
        let mut epochs = self.epochs.lock().map_err(|_| ReleaseError::Unavailable)?;
        let before = epochs.len();
        epochs.retain(|(m, e), _| *m != market || *e > through);
        let pruned = before - epochs.len();
        drop(epochs);
        let mut nonces = self.nonces.lock().map_err(|_| ReleaseError::Unavailable)?;
        nonces
            .issued
            .retain(|_, n| n.market != market || n.epoch > through);
        nonces.expire(Instant::now());
        Ok(pruned)
    }

    /// Unexpired nonces not presented yet.
    pub fn outstanding_nonces(&self) -> usize {
        self.nonces.lock().map_or(0, |mut n| {
            n.expire(Instant::now());
            n.issued.len()
        })
    }

    #[cfg(feature = "fault-injection")]
    pub fn set_fault(&self, f: MemberFault) {
        if let Ok(mut g) = self.fault.lock() {
            *g = f;
        }
    }

    #[cfg(feature = "fault-injection")]
    fn fault(&self) -> MemberFault {
        self.fault
            .lock()
            .map(|g| *g)
            .unwrap_or(MemberFault::Offline)
    }

    /// Issue a fresh nonce to `executor` for (market, epoch). Refused
    /// (`NoShare`) without a share for the epoch, so nonces for epochs this
    /// member cannot serve never use up the overall budget. At most
    /// [`NonceLimits::per_executor`] may be outstanding per (market, epoch,
    /// executor) and [`NonceLimits::total`] overall (`RateLimited`).
    ///
    /// The registration and batch-status preconditions need a chain read
    /// and are the service's.
    pub fn issue_nonce(
        &self,
        market: MarketId,
        epoch: EpochId,
        executor: ExecutorId,
    ) -> Result<Hash32, ReleaseError> {
        self.issue_nonce_at(market, epoch, executor, Instant::now())
    }

    /// [`Self::issue_nonce`] at a given time.
    pub fn issue_nonce_at(
        &self,
        market: MarketId,
        epoch: EpochId,
        executor: ExecutorId,
        now: Instant,
    ) -> Result<Hash32, ReleaseError> {
        let held = self
            .epochs
            .lock()
            .map_err(|_| ReleaseError::Unavailable)?
            .contains_key(&(market, epoch));
        if !held {
            return Err(ReleaseError::NoShare);
        }
        self.nonces
            .lock()
            .map_err(|_| ReleaseError::Unavailable)?
            .issue(&self.limits, market, epoch, executor, now)
    }

    /// Decide one release request against one chain read, checking the
    /// table from d to o in order. The first failing check is the refusal.
    /// The nonce is consumed by every attempt that reaches it (f), valid or
    /// not, so captured requests cannot be replayed. The header is pinned
    /// only after the attestation and the policy passed, so an executor this
    /// member does not trust cannot pin a bogus header.
    ///
    /// The authentication of the request envelope (a), rate limiting (b) and
    /// decoding (c) are the service's. A finalized read that is unavailable
    /// or disputed (`NotFinal`) never yields a context.
    pub fn decide(
        &self,
        req: &KeyReleaseRequest,
        ctx: &ReleaseContext,
    ) -> Result<SealedShare, ReleaseError> {
        self.decide_at(req, ctx, Instant::now())
    }

    /// [`Self::decide`] at a given time.
    pub fn decide_at(
        &self,
        req: &KeyReleaseRequest,
        ctx: &ReleaseContext,
        now: Instant,
    ) -> Result<SealedShare, ReleaseError> {
        let h = &req.header;
        let att = &req.attestation;
        let header_digest = h.digest();

        // d. Registered in a non-zero executor slot.
        if att.executor == ExecutorId([0; 32]) || !ctx.executors.contains(&att.executor) {
            return Err(ReleaseError::NotRegistered);
        }

        // e. The attested committee is the one of the announcement this
        // member acked, and the chain still recognises it.
        let announcement = self.announcement(h.market, h.epoch)?;
        let current = announcement.committee_digest == ctx.committee_digest;
        let previous = ctx.prev_committee_digest != Hash32::ZERO
            && announcement.committee_digest == ctx.prev_committee_digest;
        if att.committee_digest != announcement.committee_digest || !(current || previous) {
            return Err(ReleaseError::CommitteeMismatch);
        }

        // f. A nonce this member issued to this executor for this epoch.
        // Consumed now whatever happens next.
        let slot = usize::from(self.index - 1);
        let nonce = att.nonces.get(slot).ok_or(ReleaseError::BadNonce)?;
        let issued = self
            .nonces
            .lock()
            .map_err(|_| ReleaseError::Unavailable)?
            .take(nonce, now);
        match issued {
            Some(n) if n.market == h.market && n.epoch == h.epoch && n.executor == att.executor => {
            }
            _ => return Err(ReleaseError::BadNonce),
        }

        // g. The batch at finalized.
        let b = ctx.batch.ok_or(ReleaseError::NotCommitted)?;
        match b.status {
            CommittedStatus::Committed => return Err(ReleaseError::BeaconMissing),
            CommittedStatus::BeaconRevealed => {}
            // Re-release for a co-signer or for recovery: the outcome of
            // the posted header is public already, so only that header.
            CommittedStatus::ReceiptPosted => {
                if b.header_digest != Some(header_digest) {
                    return Err(ReleaseError::HeaderMismatch);
                }
            }
            CommittedStatus::Verified if b.applied_count == 0 => {
                if b.header_digest != Some(header_digest) {
                    return Err(ReleaseError::HeaderMismatch);
                }
            }
            CommittedStatus::Verified | CommittedStatus::Settled | CommittedStatus::Aborted => {
                return Err(ReleaseError::EpochClosed);
            }
        }
        if b.root != h.batch_root || b.count != h.envelope_count || b.beacon != Some(h.beacon) {
            return Err(ReleaseError::HeaderMismatch);
        }

        // g2. The epoch binding names this member's announcement and
        // committee, and it is what the relay committed.
        let v2 = h.version == HEADER_VERSION_ENVELOPE_BOUND;
        if v2 {
            let binding = epoch_binding(
                &req.price_commitment,
                &announcement.digest,
                &announcement.committee_digest,
            );
            if h.price_commitment != binding
                || b.terms_digest != terms_digest(&h.band, &h.price_commitment)
            {
                return Err(ReleaseError::BindingMismatch);
            }
        }

        // h. Market state.
        if ctx.halted {
            return Err(ReleaseError::Halted);
        }
        if ctx.last_settled.0.checked_add(1) != Some(h.epoch.0) {
            return Err(ReleaseError::PrevNotTerminal);
        }
        let v1 = h.version == PROTOCOL_VERSION && self.accepts_header_v1();
        if !(v2 || v1)
            || h.params != ctx.params
            || h.market != ctx.params.market
            || h.prior_state_root != ctx.state_root
            || h.prev_receipt != ctx.prev_receipt
        {
            return Err(ReleaseError::HeaderMismatch);
        }

        // j. The attestation is for this header.
        if att.header_digest != header_digest {
            return Err(ReleaseError::HeaderMismatch);
        }

        // k, l. Evidence and policy.
        let report = self
            .verifier
            .verify(&att.evidence)
            .map_err(ReleaseError::Attestation)?;
        self.policy
            .appraise(&report, &att.expected_report_data())
            .map_err(ReleaseError::Policy)?;

        // i, m, n. Pin, count and read the share in one critical section.
        let value = {
            let mut epochs = self.epochs.lock().map_err(|_| ReleaseError::Unavailable)?;
            let held = epochs.get_mut(&(h.market, h.epoch));
            let pinned = held.as_ref().and_then(|e| e.pin);
            if pinned.is_some_and(|p| p != header_digest) {
                return Err(ReleaseError::HeaderPinned);
            }
            let Some(held) = held else {
                return Err(ReleaseError::NoShare);
            };
            if held.releases >= self.max_releases {
                return Err(ReleaseError::TooManyReleases);
            }
            held.pin = Some(header_digest);
            held.releases += 1;
            Zeroizing::new(held.share.value.to_bytes())
        };

        // o. Seal `index || scalar` to the attested key.
        let mut pt = Zeroizing::new([0u8; 33]);
        pt[0] = self.index;
        pt[1..].copy_from_slice(value.as_ref());
        #[cfg(feature = "fault-injection")]
        if self.fault() == MemberFault::CorruptShare {
            pt[1] ^= 0x5a;
        }
        let sealed = seal(
            &mut rand::rngs::OsRng,
            &att.seal_key,
            &share_info(h.market, h.epoch),
            header_digest.as_bytes(),
            pt.as_ref(),
        )
        .map_err(|_| ReleaseError::BadRequest)?;
        Ok(SealedShare {
            member: self.index,
            sealed,
        })
    }

    /// The announcement held for (market, epoch). Without one no attested
    /// committee can match (`CommitteeMismatch`).
    fn announcement(
        &self,
        market: MarketId,
        epoch: EpochId,
    ) -> Result<HeldAnnouncement, ReleaseError> {
        self.epochs
            .lock()
            .map_err(|_| ReleaseError::Unavailable)?
            .get(&(market, epoch))
            .map(|e| e.announcement)
            .ok_or(ReleaseError::CommitteeMismatch)
    }

    #[cfg(feature = "simulation")]
    fn accepts_header_v1(&self) -> bool {
        self.sim.header_v1
    }

    #[cfg(not(feature = "simulation"))]
    fn accepts_header_v1(&self) -> bool {
        false
    }
}

#[cfg(feature = "simulation")]
impl KeyReleaseMember {
    /// Read committed batches from `chain` when serving in process.
    pub fn with_chain(mut self, chain: Arc<dyn ChainView>) -> Self {
        self.sim.chain = Some(chain);
        self
    }

    /// Also release for version 1 headers, which carry no epoch binding
    /// (local simulations and the v1 vectors, the program accepts only
    /// version 2).
    pub fn accept_header_v1(mut self) -> Self {
        self.sim.header_v1 = true;
        self
    }

    /// Accept releases to `executor`, as an on-chain registration would.
    pub fn register_executor(&self, executor: ExecutorId) -> Result<(), ReleaseError> {
        let mut e = self
            .sim
            .executors
            .lock()
            .map_err(|_| ReleaseError::Unavailable)?;
        if !e.contains(&executor) {
            e.push(executor);
        }
        Ok(())
    }

    /// The release context for `header`: the batch from the chain view, the
    /// market fields from the header itself, so the market-progress checks
    /// of [`Self::decide`] pass by construction. A real member builds its
    /// context from chain state.
    pub fn context(&self, header: &BatchHeader) -> Result<ReleaseContext, ReleaseError> {
        let batch = self
            .sim
            .chain
            .as_ref()
            .and_then(|c| c.committed_batch(header.market, header.epoch))
            .map(|b| BatchView {
                status: b.status,
                root: b.root,
                count: b.count,
                terms_digest: b.terms,
                beacon: b.beacon,
                header_digest: None,
                applied_count: 0,
            });
        Ok(ReleaseContext {
            executors: self
                .sim
                .executors
                .lock()
                .map_err(|_| ReleaseError::Unavailable)?
                .clone(),
            committee_digest: self.committee_digest,
            prev_committee_digest: Hash32::ZERO,
            params: header.params,
            last_settled: EpochId(header.epoch.0.saturating_sub(1)),
            state_root: header.prior_state_root,
            prev_receipt: header.prev_receipt,
            halted: false,
            batch,
        })
    }

    /// This member as `executor` reaches it over an authenticated channel.
    pub fn serve(self: &Arc<Self>, executor: ExecutorId) -> InProcessMember {
        InProcessMember {
            member: Arc::clone(self),
            executor,
        }
    }

    #[cfg(feature = "fault-injection")]
    async fn apply_fault(&self) -> Result<(), ReleaseError> {
        match self.fault() {
            MemberFault::Offline => Err(ReleaseError::Unavailable),
            MemberFault::Slow(d) => {
                tokio::time::sleep(d).await;
                Ok(())
            }
            _ => Ok(()),
        }
    }

    #[cfg(not(feature = "fault-injection"))]
    async fn apply_fault(&self) -> Result<(), ReleaseError> {
        Ok(())
    }
}

/// A [`KeyReleaseMember`] serving one executor in process (simulation).
/// Challenges are issued to that executor, and a release whose attestation
/// names another executor is refused as unauthenticated, as a member refuses
/// an envelope whose sender is not the attested executor (a). Releases
/// are decided on the blocking pool against [`KeyReleaseMember::context`].
#[cfg(feature = "simulation")]
#[derive(Debug, Clone)]
pub struct InProcessMember {
    member: Arc<KeyReleaseMember>,
    executor: ExecutorId,
}

#[cfg(feature = "simulation")]
impl InProcessMember {
    pub fn member(&self) -> &Arc<KeyReleaseMember> {
        &self.member
    }
}

#[cfg(feature = "simulation")]
impl KeyReleaseService for InProcessMember {
    fn index(&self) -> u8 {
        self.member.index
    }

    fn challenge(
        &self,
        market: MarketId,
        epoch: EpochId,
    ) -> BoxFuture<'_, Result<Hash32, ReleaseError>> {
        Box::pin(async move {
            self.member.apply_fault().await?;
            self.member.issue_nonce(market, epoch, self.executor)
        })
    }

    fn release(&self, req: KeyReleaseRequest) -> BoxFuture<'_, Result<SealedShare, ReleaseError>> {
        Box::pin(async move {
            self.member.apply_fault().await?;
            if req.attestation.executor != self.executor {
                return Err(ReleaseError::Unauthenticated);
            }
            let member = Arc::clone(&self.member);
            tokio::task::spawn_blocking(move || {
                let ctx = member.context(&req.header)?;
                member.decide(&req, &ctx)
            })
            .await
            .map_err(|_| ReleaseError::Unavailable)?
        })
    }
}
