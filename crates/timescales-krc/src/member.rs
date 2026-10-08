//! A committee member: accepts and acks shares, answers challenges and
//! releases its share under the release rules.
//!
//! The release decision itself is `KeyReleaseMember::decide`, over one
//! [`ReleaseContext`](timescales_executor::tee::ReleaseContext) read through
//! [`KrcChain`]. Around it this service adds what needs I/O: the envelope
//! sender and the per-caller rate limit, the header pin and the
//! release count in `member.sqlite` (the database is authoritative,
//! the copy in memory only guards concurrent requests), the check that the
//! share still exists and the audit row.
//!
//! Shares live in `shares.sqlite`, sealed under the ratcheting at-rest key.
//! The release core holds a share from its delivery until the epoch
//! is pruned. After a restart a share is opened from `shares.sqlite` when
//! its epoch is first challenged or released, and its pin is restored from
//! `member.sqlite` at the same time.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::time::Duration;

use arc_swap::ArcSwap;
use curve25519_dalek::edwards::EdwardsPoint;
use parking_lot::Mutex;
use thiserror::Error;
use timescales_auction::CommittedStatus;
use timescales_chain::{Address, Level};
use timescales_core::crypto::threshold::{ScalarShare, decompress_canonical, verify_share};
use timescales_core::crypto::{Keypair, SealSecret, Zeroizing};
use timescales_core::{Decode, Encode, EpochId, ExecutorId, Hash32, MarketId};
use timescales_executor::attestation::QuoteVerifier;
use timescales_executor::policy::AttestationPolicy;
use timescales_executor::tee::{
    HeldAnnouncement, KeyReleaseMember, NonceLimits, ReleaseError, SealedShare,
};
use timescales_service::store::member::{MemberRepo, PinOutcome, ReleaseAudit};
use timescales_service::store::node::PutOutcome;
use timescales_service::store::{PruneReport, RatchetSealer, SecretSealer, StoreError};
use timescales_service::wire::{
    ChallengeRequest, ChallengeResponse, CommitteeDescription, EpochKeyAck, EpochKeyAnnouncement,
    ReleasePolicyStatement, ReleaseRefusal, ReleaseRequest, ShareDelivery,
};
use timescales_service::{ConfigError, ConfigIssue, HttpLimits};

use crate::config::load_committee;
use crate::limiter::{CallerLimiter, MAX_TRACKED_CALLERS};
use crate::metrics::MemberMetrics;
use crate::{KrcChain, KrcError, MemberConfig, b58, now_ms};

/// Epochs above the last settled one scanned when counting held shares. A
/// dealer deals at most this far ahead (`lookahead_epochs <= 1024`).
const SHARE_SCAN_EPOCHS: u64 = 1024;

/// A header digest no header has, to read a pin through
/// `pin_and_count(.., max = 0)` without changing it.
const PIN_PROBE: Hash32 = Hash32([0; 32]);

/// The member's long-term keys.
pub struct MemberKeys {
    /// In the on-chain committee digest. Signs acks and responses only.
    pub identity: Keypair,
    /// Receives shares.
    pub transport: SealSecret,
    /// Seals shares at rest. The same sealer the [`MemberRepo`] was
    /// built with, which erases generations nothing needs any more.
    pub at_rest: Arc<RatchetSealer>,
}

impl core::fmt::Debug for MemberKeys {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("MemberKeys")
            .field("identity", &Hash32(self.identity.public()))
            .finish_non_exhaustive()
    }
}

/// Why a share delivery was refused.
#[derive(Debug, Error)]
pub enum ShareRefusal {
    #[error("sender is not a configured dealer")]
    Unauthenticated,
    #[error("market not configured")]
    UnknownMarket,
    #[error("committee digest does not match chain state")]
    CommitteeMismatch,
    #[error("epoch already committed")]
    TooLate,
    #[error("share does not verify against the announcement")]
    BadShare,
    /// 409: a different announcement is stored for this epoch.
    #[error("another announcement is stored for this epoch")]
    SecondAnnouncement { stored: Hash32 },
    #[error(transparent)]
    Internal(#[from] KrcError),
}

impl From<StoreError> for ShareRefusal {
    fn from(e: StoreError) -> Self {
        ShareRefusal::Internal(KrcError::Store(e))
    }
}

/// A market this member serves: its committee and this member's signed
/// release policy for it.
struct Served {
    committee: CommitteeDescription,
    digest: Hash32,
    statement: ReleasePolicyStatement,
}

pub struct Member {
    index: u8,
    keys: MemberKeys,
    repo: MemberRepo,
    chain: Arc<dyn KrcChain>,
    verifier: Arc<dyn QuoteVerifier>,
    policy: AttestationPolicy,
    limits: NonceLimits,
    /// Nonces, held shares and the in-memory pins. Replaced as a whole by
    /// an emergency rotation, which must not leave the old share in memory.
    core: ArcSwap<KeyReleaseMember>,
    markets: BTreeMap<Address, Served>,
    first_market: Address,
    /// Market id -> address, learned from Market accounts.
    ids: Mutex<BTreeMap<u64, Address>>,
    dealer_keys: BTreeSet<[u8; 32]>,
    limiter: CallerLimiter,
    max_releases: u32,
    skew_ms: u64,
    audit_retention_ms: u64,
    kek_ratchet_epochs: u64,
    /// Settled epochs (summed over markets) / `kek_ratchet_epochs` when the
    /// at-rest key last advanced.
    ratchet_mark: Mutex<Option<u64>>,
    load: tokio::sync::Mutex<()>,
    metrics: MemberMetrics,
}

impl core::fmt::Debug for Member {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Member")
            .field("index", &self.index)
            .field("identity", &Hash32(self.keys.identity.public()))
            .field("markets", &self.markets.keys().map(b58).collect::<Vec<_>>())
            .finish_non_exhaustive()
    }
}

fn config_error(field: &str, message: impl Into<String>) -> KrcError {
    KrcError::Config(ConfigError::Invalid(vec![ConfigIssue::new(field, message)]))
}

fn share_aad(m: &Address, e: u64, index: u8) -> Vec<u8> {
    let mut aad = Vec::with_capacity(32 + 8 + 1);
    aad.extend_from_slice(m);
    aad.extend_from_slice(&e.to_le_bytes());
    aad.push(index);
    aad
}

fn refusal(e: &ReleaseError) -> ReleaseRefusal {
    ReleaseRefusal::from(e)
}

impl Member {
    /// Reads the committee description of every configured market and
    /// checks that this member is in it under its own keys. Then signs its
    /// release policy for each market (from epoch 0: the statement is a
    /// function of the configuration, so its digest, which every ack
    /// carries, stays the same across restarts).
    pub fn new(
        cfg: MemberConfig,
        keys: MemberKeys,
        repo: MemberRepo,
        chain: Arc<dyn KrcChain>,
        verifier: Arc<dyn QuoteVerifier>,
        policy: AttestationPolicy,
    ) -> Result<Self, KrcError> {
        let fields = policy.statement();
        let mut markets = BTreeMap::new();
        for (entry, address) in cfg.markets.iter().zip(cfg.market_addresses()) {
            let committee = load_committee(&entry.committee_file, &address)
                .map_err(|e| config_error("member.market.committee_file", e))?;
            let me = committee.member(cfg.index).ok_or_else(|| {
                config_error("member.index", "this index is not in the committee")
            })?;
            if me.identity != keys.identity.public() || me.transport != keys.transport.public() {
                return Err(config_error(
                    "member.identity_key",
                    format!(
                        "the keys are not those of member {} in the committee of {}",
                        cfg.index,
                        b58(&address)
                    ),
                ));
            }
            let digest = committee.digest();
            let statement = ReleasePolicyStatement {
                version: ReleasePolicyStatement::VERSION,
                market: address,
                member: cfg.index,
                committee_digest: digest,
                platforms: fields.platforms,
                measurement_set_digest: fields.measurement_set_digest,
                allow_debug: fields.allow_debug,
                min_tcb: fields.min_tcb,
                mr_config_id: fields.mr_config_id,
                from_epoch: EpochId(0),
                signature: timescales_core::crypto::Signature([0; 64]),
            }
            .sign(&keys.identity);
            markets.insert(
                address,
                Served {
                    committee,
                    digest,
                    statement,
                },
            );
        }
        let first_market = *cfg
            .market_addresses()
            .first()
            .ok_or_else(|| config_error("member.market", "no market"))?;
        let limits = NonceLimits {
            ttl: Duration::from_millis(cfg.nonce_ttl_ms),
            per_executor: usize::try_from(cfg.max_nonces_per_epoch_executor).unwrap_or(usize::MAX),
            total: usize::try_from(cfg.max_outstanding_nonces).unwrap_or(usize::MAX),
        };
        let core = Self::core(cfg.index, &verifier, &policy, limits)?;
        let metrics = MemberMetrics::default();
        metrics
            .kek_generation
            .set(i64::from(keys.at_rest.current_generation()));
        Ok(Self {
            index: cfg.index,
            limiter: CallerLimiter::new(
                cfg.per_caller_rps,
                cfg.per_caller_burst,
                MAX_TRACKED_CALLERS,
            ),
            dealer_keys: cfg.dealer_key_set(),
            max_releases: cfg.max_releases_per_epoch,
            skew_ms: cfg.skew_ms,
            audit_retention_ms: u64::from(cfg.audit_retention_days) * 86_400_000,
            kek_ratchet_epochs: cfg.kek_ratchet_epochs.max(1),
            keys,
            repo,
            chain,
            verifier,
            policy,
            limits,
            core: ArcSwap::from_pointee(core),
            markets,
            first_market,
            ids: Mutex::new(BTreeMap::new()),
            ratchet_mark: Mutex::new(None),
            load: tokio::sync::Mutex::new(()),
            metrics,
        })
    }

    fn core(
        index: u8,
        verifier: &Arc<dyn QuoteVerifier>,
        policy: &AttestationPolicy,
        limits: NonceLimits,
    ) -> Result<KeyReleaseMember, KrcError> {
        Ok(
            KeyReleaseMember::new(index, Arc::clone(verifier), policy.clone())
                .map_err(|e| config_error("member.index", e.to_string()))?
                .with_nonce_limits(limits),
        )
    }

    pub fn index(&self) -> u8 {
        self.index
    }

    /// The key this member signs acks and envelopes with.
    pub fn identity(&self) -> &Keypair {
        &self.keys.identity
    }

    pub fn transport_public(&self) -> [u8; 32] {
        self.keys.transport.public()
    }

    pub fn metrics(&self) -> &MemberMetrics {
        &self.metrics
    }

    pub fn skew_ms(&self) -> u64 {
        self.skew_ms
    }

    pub fn attestation_policy(&self) -> &AttestationPolicy {
        &self.policy
    }

    /// The markets served and the digest of each one's committee.
    pub fn committee_digests(&self) -> impl Iterator<Item = (&Address, &Hash32)> {
        self.markets.iter().map(|(m, s)| (m, &s.digest))
    }

    pub fn is_dealer(&self, key: &[u8; 32]) -> bool {
        self.dealer_keys.contains(key)
    }

    /// The release policy statement of the first configured market.
    pub fn policy(&self) -> &ReleasePolicyStatement {
        &self.markets[&self.first_market].statement
    }

    /// This member's release policy statement for market `m`.
    pub fn policy_for(&self, m: &Address) -> Option<&ReleasePolicyStatement> {
        self.markets.get(m).map(|s| &s.statement)
    }

    /// Whether both database files answer (fail-stop: a store that had a
    /// write error answers `Closed` from then on).
    pub async fn store_ok(&self) -> bool {
        self.repo
            .announcement([0; 32], 0)
            .await
            .and(self.repo.share([0; 32], 0).await)
            .is_ok()
    }

    fn ack(&self, served: &Served, announcement_digest: &Hash32) -> EpochKeyAck {
        EpochKeyAck::sign(
            self.index,
            announcement_digest,
            served.statement.digest(),
            &self.keys.identity,
        )
    }

    /// 409 on a different announcement.
    pub async fn accept_share(
        &self,
        from: [u8; 32],
        d: ShareDelivery,
    ) -> Result<EpochKeyAck, ShareRefusal> {
        if !self.dealer_keys.contains(&from) {
            return Err(ShareRefusal::Unauthenticated);
        }
        let m = d.announcement.market;
        let served = self.markets.get(&m).ok_or(ShareRefusal::UnknownMarket)?;
        let e = d.announcement.epoch.0;
        let digest = d.announcement.digest();
        if let Some((stored, stored_digest)) = self.repo.announcement(m, e).await? {
            if stored_digest != digest {
                return self
                    .rotate_or_refuse(served, &stored, stored_digest, d)
                    .await;
            }
            // The same announcement again: re-ack, unless a crash came
            // between storing the announcement and the share.
            if self.repo.share(m, e).await?.is_some() {
                return Ok(self.ack(served, &digest));
            }
        }
        let market = self.chain.market(m, Level::Confirmed).await?;
        let ann = &d.announcement;
        if ann.committee_digest != served.digest || served.digest != market.committee_digest {
            return Err(ShareRefusal::CommitteeMismatch);
        }
        if e <= market.last_committed {
            return Err(ShareRefusal::TooLate);
        }
        let share = self.verified_share(served, &d)?;
        let sealed = self
            .keys
            .at_rest
            .seal(&share_aad(&m, e, self.index), share.value.as_bytes())?;
        match self
            .repo
            .put_share(m, e, ann.to_bytes(), digest, sealed, now_ms())
            .await?
        {
            PutOutcome::Inserted | PutOutcome::Identical => {}
            PutOutcome::Conflict => {
                // Another delivery for the epoch was stored meanwhile.
                let stored = self
                    .repo
                    .announcement(m, e)
                    .await?
                    .map_or(Hash32::ZERO, |(_, d)| d);
                self.metrics.second_announcement.inc();
                return Err(ShareRefusal::SecondAnnouncement { stored });
            }
        }
        self.remember_id(market.market_id, m);
        self.hold(
            MarketId(market.market_id),
            e,
            share,
            HeldAnnouncement {
                digest,
                committee_digest: ann.committee_digest,
            },
        );
        tracing::info!(market = %b58(&m), epoch = e, announcement = %digest, "share accepted");
        Ok(self.ack(served, &digest))
    }

    /// A delivery for an epoch that holds another announcement: accepted
    /// only as an emergency rotation (the stored announcement names the
    /// previous committee, the new one the current committee, and the epoch
    /// is not committed yet), otherwise 409 and an alert.
    async fn rotate_or_refuse(
        &self,
        served: &Served,
        stored: &[u8],
        stored_digest: Hash32,
        d: ShareDelivery,
    ) -> Result<EpochKeyAck, ShareRefusal> {
        let m = d.announcement.market;
        let e = d.announcement.epoch.0;
        let stored_ann = EpochKeyAnnouncement::decode_exact(stored)
            .map_err(|e| KrcError::Wire(timescales_service::wire::WireError::Decode(e)))?;
        let market = self.chain.market(m, Level::Confirmed).await?;
        let rotation = market.prev_committee_digest != Hash32::ZERO
            && stored_ann.committee_digest == market.prev_committee_digest
            && d.announcement.committee_digest == market.committee_digest
            && market.committee_digest == served.digest
            && e > market.last_committed;
        if !rotation {
            self.metrics.second_announcement.inc();
            tracing::error!(
                market = %b58(&m),
                epoch = e,
                stored = %stored_digest,
                offered = %d.announcement.digest(),
                "second announcement for an epoch: the dealer is faulty or compromised"
            );
            return Err(ShareRefusal::SecondAnnouncement {
                stored: stored_digest,
            });
        }
        let share = self.verified_share(served, &d)?;
        let sealed = self
            .keys
            .at_rest
            .seal(&share_aad(&m, e, self.index), share.value.as_bytes())?;
        let digest = d.announcement.digest();
        self.repo
            .rotate_share(m, e, d.announcement.to_bytes(), digest, sealed, now_ms())
            .await?;
        // The old share may be held in memory: start over with a fresh core.
        // Shares and pins are loaded again from the database when needed.
        self.reset_core()?;
        self.remember_id(market.market_id, m);
        self.hold(
            MarketId(market.market_id),
            e,
            share,
            HeldAnnouncement {
                digest,
                committee_digest: d.announcement.committee_digest,
            },
        );
        tracing::warn!(
            market = %b58(&m),
            epoch = e,
            replaced = %stored_digest,
            announcement = %digest,
            "share replaced by an emergency committee rotation"
        );
        Ok(self.ack(served, &digest))
    }

    /// `check_structure`, the box opens for this member, and the share
    /// verifies against the commitments (Feldman).
    fn verified_share(
        &self,
        served: &Served,
        d: &ShareDelivery,
    ) -> Result<ScalarShare, ShareRefusal> {
        let ann = &d.announcement;
        ann.check_structure(served.committee.threshold, false)
            .map_err(|_| ShareRefusal::BadShare)?;
        if d.member != self.index {
            return Err(ShareRefusal::BadShare);
        }
        let share = d
            .open(&self.keys.transport)
            .map_err(|_| ShareRefusal::BadShare)?;
        if share.index != self.index {
            return Err(ShareRefusal::BadShare);
        }
        let points: Vec<EdwardsPoint> = ann
            .commitments
            .iter()
            .map(decompress_canonical)
            .collect::<Option<_>>()
            .ok_or(ShareRefusal::BadShare)?;
        if !verify_share(&share, &points) {
            return Err(ShareRefusal::BadShare);
        }
        Ok(share)
    }

    fn reset_core(&self) -> Result<(), KrcError> {
        let core = Self::core(self.index, &self.verifier, &self.policy, self.limits)?;
        self.core.store(Arc::new(core));
        Ok(())
    }

    fn hold(&self, market: MarketId, e: u64, share: ScalarShare, ann: HeldAnnouncement) {
        if let Err(err) = self
            .core
            .load()
            .store_dealt_share(market, EpochId(e), share, ann)
        {
            // Already held under the same announcement, or replaced by a
            // rotation that reset the core meanwhile. The database is
            // authoritative either way.
            tracing::debug!(epoch = e, error = %err, "share not added to the release core");
        }
    }

    fn remember_id(&self, id: u64, m: Address) {
        self.ids.lock().insert(id, m);
    }

    /// The configured market with this id, reading Market accounts of
    /// markets whose id is not known yet.
    async fn address_of(&self, id: MarketId) -> Option<Address> {
        if let Some(m) = self.ids.lock().get(&id.0) {
            return Some(*m);
        }
        let unknown: Vec<Address> = {
            let ids = self.ids.lock();
            self.markets
                .keys()
                .filter(|m| !ids.values().any(|k| k == *m))
                .copied()
                .collect()
        };
        for m in unknown {
            if let Ok(market) = self.chain.market(m, Level::Confirmed).await {
                self.remember_id(market.market_id, m);
            }
        }
        self.ids.lock().get(&id.0).copied()
    }

    /// Opens the share of (m, e) into the release core if it is not held
    /// there yet, and restores its pin. False without a stored share.
    async fn ensure_loaded(&self, m: Address, id: MarketId, e: EpochId) -> Result<bool, KrcError> {
        if self.core.load().holds(id, e) {
            return Ok(true);
        }
        let _one_loader = self.load.lock().await;
        let core = self.core.load_full();
        if core.holds(id, e) {
            return Ok(true);
        }
        let Some(sealed) = self.repo.share(m, e.0).await? else {
            return Ok(false);
        };
        let Some((ann, digest)) = self.repo.announcement(m, e.0).await? else {
            return Ok(false);
        };
        let ann = EpochKeyAnnouncement::decode_exact(&ann)
            .map_err(|e| KrcError::Wire(timescales_service::wire::WireError::Decode(e)))?;
        let plain = self
            .keys
            .at_rest
            .open(&share_aad(&m, e.0, self.index), &sealed)?;
        let bytes: Zeroizing<[u8; 32]> = Zeroizing::new(
            plain
                .as_slice()
                .try_into()
                .map_err(|_| StoreError::Corrupt("stored share has the wrong length"))?,
        );
        let share = ScalarShare::from_bytes(self.index, &bytes).ok_or(StoreError::Corrupt(
            "stored share is not a canonical scalar",
        ))?;
        core.store_dealt_share(
            id,
            e,
            share,
            HeldAnnouncement {
                digest,
                committee_digest: ann.committee_digest,
            },
        )
        .map_err(|_| StoreError::Corrupt("stored share does not belong to this member"))?;
        if let PinOutcome::Other(pinned) = self.repo.pin_and_count(m, e.0, PIN_PROBE, 0).await? {
            core.restore_pin(id, e, pinned, 0)
                .map_err(|_| StoreError::Corrupt("pin could not be restored"))?;
        }
        Ok(true)
    }

    pub async fn announcement(
        &self,
        m: Address,
        e: EpochId,
    ) -> Result<Option<(EpochKeyAnnouncement, EpochKeyAck)>, KrcError> {
        let served = self.markets.get(&m).ok_or(KrcError::UnknownMarket(m))?;
        let Some((bytes, digest)) = self.repo.announcement(m, e.0).await? else {
            return Ok(None);
        };
        let ann = EpochKeyAnnouncement::decode_exact(&bytes)
            .map_err(|e| KrcError::Wire(timescales_service::wire::WireError::Decode(e)))?;
        Ok(Some((ann, self.ack(served, &digest))))
    }

    pub async fn challenge(
        &self,
        from: ExecutorId,
        r: ChallengeRequest,
    ) -> Result<ChallengeResponse, ReleaseRefusal> {
        self.metrics.challenges.inc();
        if from != r.executor {
            return Err(ReleaseRefusal::Unauthenticated);
        }
        if !self.limiter.check(&from.0) {
            return Err(ReleaseRefusal::RateLimited);
        }
        let m = r.market;
        if !self.markets.contains_key(&m) {
            return Err(ReleaseRefusal::BadRequest);
        }
        let market = self
            .chain
            .market(m, Level::Confirmed)
            .await
            .map_err(|e| match e {
                KrcError::NotFinal => ReleaseRefusal::NotFinal,
                _ => ReleaseRefusal::Unavailable,
            })?;
        self.remember_id(market.market_id, m);
        if r.executor.0 == [0; 32] || !market.executors.contains(&r.executor.0) {
            return Err(ReleaseRefusal::NotRegistered);
        }
        let ctx = self
            .chain
            .release_context(m, r.epoch)
            .await
            .map_err(|_| ReleaseRefusal::NotFinal)?;
        match ctx.batch {
            None => return Err(ReleaseRefusal::NotCommitted),
            Some(b)
                if matches!(
                    b.status,
                    CommittedStatus::Settled | CommittedStatus::Aborted
                ) || (b.status == CommittedStatus::Verified && b.applied_count > 0) =>
            {
                return Err(ReleaseRefusal::EpochClosed);
            }
            Some(_) => {}
        }
        let id = MarketId(market.market_id);
        if !self
            .ensure_loaded(m, id, r.epoch)
            .await
            .map_err(|_| ReleaseRefusal::Unavailable)?
        {
            return Err(ReleaseRefusal::NoShare);
        }
        let core = self.core.load();
        let nonce = core
            .issue_nonce(id, r.epoch, r.executor)
            .map_err(|e| refusal(&e))?;
        self.metrics
            .nonces_outstanding
            .set(i64::try_from(core.outstanding_nonces()).unwrap_or(i64::MAX));
        let ttl = u64::try_from(self.limits.ttl.as_millis()).unwrap_or(u64::MAX);
        Ok(ChallengeResponse {
            member: self.index,
            market: m,
            epoch: r.epoch,
            nonce,
            expires_at_ms: now_ms().saturating_add(ttl),
        })
    }

    /// The release rules, in the order the decision checks them.
    pub async fn release(
        &self,
        from: ExecutorId,
        r: ReleaseRequest,
    ) -> Result<SealedShare, ReleaseRefusal> {
        let result = self.decide(from, &r).await;
        let (code, name) = match &result {
            Ok(_) => (0, "released".to_owned()),
            Err(c) => (*c as u8, format!("{c:?}")),
        };
        self.metrics.release(&name);
        // Neither an unauthenticated nor a rate-limited request is
        // recorded: their senders are not limited by anything else.
        if !matches!(
            result,
            Err(ReleaseRefusal::Unauthenticated | ReleaseRefusal::RateLimited)
        ) {
            let audit = ReleaseAudit {
                market: self
                    .ids
                    .lock()
                    .get(&r.header.market.0)
                    .copied()
                    .unwrap_or([0; 32]),
                epoch: r.header.epoch.0,
                executor: r.attestation.executor.0,
                seal_key: r.attestation.seal_key,
                header_digest: r.header.digest(),
                quote_hash: r.attestation.digest(),
                result: code,
                at_ms: now_ms(),
            };
            if let Err(e) = self.repo.audit(audit).await {
                tracing::error!(error = %e, "release audit row not written");
                if result.is_ok() {
                    return Err(ReleaseRefusal::Unavailable);
                }
            }
        }
        match &result {
            Ok(_) => tracing::info!(
                market = r.header.market.0,
                epoch = r.header.epoch.0,
                executor = %r.attestation.executor,
                "share released"
            ),
            Err(code) => tracing::info!(
                market = r.header.market.0,
                epoch = r.header.epoch.0,
                executor = %r.attestation.executor,
                ?code,
                "release refused"
            ),
        }
        result
    }

    async fn decide(
        &self,
        from: ExecutorId,
        r: &ReleaseRequest,
    ) -> Result<SealedShare, ReleaseRefusal> {
        // a. The envelope was checked by the HTTP layer. Its sender must be
        // the attested executor.
        if from != r.attestation.executor {
            return Err(ReleaseRefusal::Unauthenticated);
        }
        // b.
        if !self.limiter.check(&from.0) {
            return Err(ReleaseRefusal::RateLimited);
        }
        let h = &r.header;
        let m = self
            .address_of(h.market)
            .await
            .ok_or(ReleaseRefusal::BadRequest)?;
        // One chain read for every check from d on.
        let ctx = self
            .chain
            .release_context(m, h.epoch)
            .await
            .map_err(|_| ReleaseRefusal::NotFinal)?;
        self.ensure_loaded(m, h.market, h.epoch)
            .await
            .map_err(|_| ReleaseRefusal::Unavailable)?;
        // d to l, and i and m in memory. The evidence is verified on the
        // blocking pool.
        let core = self.core.load_full();
        let req = r.clone();
        let sealed = tokio::task::spawn_blocking(move || core.decide(&req, &ctx))
            .await
            .map_err(|_| ReleaseRefusal::Unavailable)?
            .map_err(|e| refusal(&e))?;
        // i and m, durably and only now that the attestation and the policy
        // passed.
        match self
            .repo
            .pin_and_count(m, h.epoch.0, h.digest(), self.max_releases)
            .await
        {
            Ok(PinOutcome::Pinned | PinOutcome::Matches) => {}
            Ok(PinOutcome::Other(_)) => return Err(ReleaseRefusal::HeaderPinned),
            Ok(PinOutcome::TooMany) => return Err(ReleaseRefusal::TooManyReleases),
            Err(_) => return Err(ReleaseRefusal::Unavailable),
        }
        // n. A prune may have destroyed the share since it was loaded.
        match self.repo.share(m, h.epoch.0).await {
            Ok(Some(_)) => Ok(sealed),
            Ok(None) => Err(ReleaseRefusal::NoShare),
            Err(_) => Err(ReleaseRefusal::Unavailable),
        }
    }

    /// Destroys shares and pins of terminal epochs (<= `Market.last_settled`
    /// at finalized) and truncates the WAL, drops expired audit rows,
    /// nonces and rate-limit buckets, and ratchets the at-rest key.
    pub async fn prune(&self) -> Result<PruneReport, KrcError> {
        let mut report = PruneReport::default();
        let mut settled = 0u64;
        let mut held = 0u64;
        let mut first_error = None;
        for &m in self.markets.keys() {
            let market = match self.chain.market(m, Level::Finalized).await {
                Ok(market) => market,
                Err(e) => {
                    tracing::warn!(market = %b58(&m), error = %e, "prune: market not read");
                    first_error.get_or_insert(e);
                    continue;
                }
            };
            self.remember_id(market.market_id, m);
            let through = market.last_settled;
            report.rows_deleted += self.repo.destroy_through(m, through).await?;
            let core = self.core.load();
            if let Err(e) = core.prune(MarketId(market.market_id), EpochId(through)) {
                tracing::error!(error = %e, "release core not pruned");
            }
            settled = settled.saturating_add(through);
            for e in through + 1..=through.saturating_add(SHARE_SCAN_EPOCHS) {
                if self.repo.share(m, e).await?.is_some() {
                    held += 1;
                }
            }
        }
        let cutoff = now_ms().saturating_sub(self.audit_retention_ms);
        report.rows_deleted += self.repo.prune_audit(cutoff).await?.rows_deleted;
        self.limiter.prune();
        if first_error.is_none() {
            self.ratchet(settled).await?;
        }
        self.metrics
            .shares_held
            .set(i64::try_from(held).unwrap_or(i64::MAX));
        self.metrics
            .nonces_outstanding
            .set(i64::try_from(self.core.load().outstanding_nonces()).unwrap_or(i64::MAX));
        match first_error {
            Some(e) => Err(e),
            None => Ok(report),
        }
    }

    /// Advances the at-rest key once per `kek_ratchet_epochs` settled
    /// epochs, then erases every older generation no stored share needs.
    async fn ratchet(&self, settled: u64) -> Result<(), KrcError> {
        let bucket = settled / self.kek_ratchet_epochs;
        let advance = {
            let mut mark = self.ratchet_mark.lock();
            let advance = mark.is_some_and(|b| bucket > b);
            if mark.is_none_or(|b| bucket > b) {
                *mark = Some(bucket);
            }
            advance
        };
        if advance {
            let generation = self.keys.at_rest.advance()?;
            tracing::info!(generation, "at-rest key advanced");
        }
        let current = self.keys.at_rest.current_generation();
        self.repo.ratchet(current).await?;
        self.metrics.kek_generation.set(i64::from(current));
        Ok(())
    }

    /// Rate-limit buckets tracked now.
    pub fn tracked_callers(&self) -> usize {
        self.limiter.tracked()
    }

    /// Nonces issued and not yet presented or expired.
    pub fn outstanding_nonces(&self) -> usize {
        self.core.load().outstanding_nonces()
    }
}

/// `/krc/v1/*`.
pub fn router(m: Arc<Member>, limits: HttpLimits) -> axum::Router {
    crate::http::router(m, limits)
}
