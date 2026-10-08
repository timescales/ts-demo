//! The trusted dealer: deals each epoch once, persists before sending,
//! collects acks and pushes bundles to the node.
//!
//! **Trusted**: the dealer draws every epoch secret it deals. The secret,
//! the polynomial and the plaintext shares exist only inside [`Dealer`]'s
//! dealing step and are wiped before the sealed deliveries are written to
//! `dealer.sqlite`, which happens before anything is sent. A recorded
//! dealing is never replaced: after a crash the same stored ciphertexts are
//! sent again, and after the database is lost the dealer adopts what the
//! members hold ([`Dealer::recover`]) instead of dealing again.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use futures::future::join_all;
use parking_lot::Mutex;
use rand_core::OsRng;
use thiserror::Error;
use timescales_chain::program::MarketAccount;
use timescales_chain::{Address, ChainError, Level, SolanaRpc};
use timescales_core::crypto::Keypair;
use timescales_core::crypto::threshold::{FeldmanDealing, x25519_public};
use timescales_core::{Decode, DecodeError, Encode, EpochId, Hash32};
use timescales_service::store::StoreError;
use timescales_service::store::dealer::{DealerRepo, Dealing};
use timescales_service::wire::{
    AnnouncementQuery, AnnouncementReply, CommitteeDescription, EpochKeyAck, EpochKeyAnnouncement,
    EpochKeyBundle, KeyScheme, MessageKind, ShareDelivery, WireError,
};
use timescales_service::{ClientError, SignedClient};
use tokio_util::sync::CancellationToken;

use crate::config::load_committee;
use crate::metrics::DealerMetrics;
use crate::{BoxFuture, DealerConfig, KrcError, b58, now_ms};

#[derive(Debug, Error)]
pub enum DealError {
    #[error(transparent)]
    Krc(#[from] KrcError),
    #[error("committee description does not match Market.committee_digest")]
    CommitteeMismatch,
    #[error("{got} of {need} acks")]
    NotEnoughAcks { got: u8, need: u8 },
    /// The dealing was lost and fewer than t members still hold it. The
    /// epoch waits for a committee rotation.
    #[error("epoch {0} cannot be dealt again")]
    Undealable(u64),
    /// After a database loss too few members answered to rule out that
    /// they hold an announcement for the epoch, so it is not dealt yet.
    #[error("epoch {0}: too few members answered the recovery query")]
    Unconfirmed(u64),
    /// Past `lookahead_epochs` after the last committed epoch.
    #[error("epoch {epoch} is beyond the lookahead (at most {max})")]
    TooFarAhead { epoch: u64, max: u64 },
    #[error("node: {0}")]
    Node(String),
}

impl From<StoreError> for DealError {
    fn from(e: StoreError) -> Self {
        DealError::Krc(KrcError::Store(e))
    }
}

impl From<WireError> for DealError {
    fn from(e: WireError) -> Self {
        DealError::Krc(KrcError::Wire(e))
    }
}

impl From<DecodeError> for DealError {
    fn from(e: DecodeError) -> Self {
        DealError::Krc(KrcError::Wire(WireError::Decode(e)))
    }
}

/// What [`Dealer::recover`] adopted.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RecoveryReport {
    pub adopted: Vec<u64>,
    pub rebuilt_bundles: Vec<u64>,
    pub undealable: Vec<u64>,
}

/// A member's answer to a share delivery.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Delivered {
    Ack(EpochKeyAck),
    /// 409: the member holds another announcement for the epoch (the one
    /// it sent, when its answer carried it).
    Conflict(Option<EpochKeyAnnouncement>),
}

#[derive(Debug, Error)]
pub enum LinkError {
    #[error(transparent)]
    Client(#[from] ClientError),
    #[error("unexpected answer: {0}")]
    Answer(&'static str),
}

/// How the dealer reaches members and the node. [`HttpLinks`] is the
/// service's. Tests put members in process.
pub trait DealerLinks: Send + Sync {
    /// `POST /krc/v1/shares` with an encoded `ShareDelivery`.
    fn deliver(
        &self,
        market: Address,
        member: u8,
        delivery: Vec<u8>,
    ) -> BoxFuture<'_, Result<Delivered, LinkError>>;
    /// `POST /krc/v1/announcements` (recovery).
    fn query(
        &self,
        market: Address,
        member: u8,
        epoch: EpochId,
    ) -> BoxFuture<'_, Result<AnnouncementReply, LinkError>>;
    /// The node's `/internal/v1/markets/{market}/epochs/{epoch}/key` with an
    /// encoded `EpochKeyBundle`.
    fn put_bundle(
        &self,
        market: Address,
        epoch: EpochId,
        bundle: Vec<u8>,
    ) -> BoxFuture<'_, Result<(), LinkError>>;
}

/// [`DealerLinks`] over [`SignedClient`]s: one per member of each market's
/// committee (the envelope audience is the member's identity) and one for
/// the node. Mutual TLS when `[dealer.tls]` is configured.
///
/// The node is called with `POST`: [`SignedClient`] has no other method.
pub struct HttpLinks {
    members: BTreeMap<(Address, u8), (SignedClient, String)>,
    node: SignedClient,
    node_url: String,
}

impl core::fmt::Debug for HttpLinks {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("HttpLinks")
            .field("members", &self.members.len())
            .field("node_url", &self.node_url)
            .finish_non_exhaustive()
    }
}

impl HttpLinks {
    pub fn new(
        cfg: &DealerConfig,
        identity: Arc<Keypair>,
        committees: &BTreeMap<Address, CommitteeDescription>,
    ) -> Result<Self, ClientError> {
        let tls = cfg.tls.clone().filter(|t| t.is_configured());
        let timeout = Duration::from_millis(cfg.ack_timeout_ms);
        let mut members = BTreeMap::new();
        for (market, committee) in committees {
            for (m, url) in committee.members.iter().zip(&cfg.member_urls) {
                let client = SignedClient::new(identity.clone(), m.identity, tls.clone(), timeout)?;
                members.insert(
                    (*market, m.index),
                    (client, url.trim_end_matches('/').to_owned()),
                );
            }
        }
        let node_key = cfg
            .node_key()
            .ok_or_else(|| ClientError::Transport("node_identity is not 64 hex digits".into()))?;
        Ok(Self {
            members,
            node: SignedClient::new(identity, node_key, tls, timeout)?,
            node_url: cfg.node_url.trim_end_matches('/').to_owned(),
        })
    }

    fn member(&self, market: &Address, member: u8) -> Result<&(SignedClient, String), LinkError> {
        self.members
            .get(&(*market, member))
            .ok_or(LinkError::Answer("no such member"))
    }
}

impl DealerLinks for HttpLinks {
    fn deliver(
        &self,
        market: Address,
        member: u8,
        delivery: Vec<u8>,
    ) -> BoxFuture<'_, Result<Delivered, LinkError>> {
        Box::pin(async move {
            let (client, url) = self.member(&market, member)?;
            match client
                .call(
                    &format!("{url}/krc/v1/shares"),
                    MessageKind::ShareDelivery,
                    delivery,
                )
                .await
            {
                Ok(env) if env.kind == MessageKind::EpochKeyAck => {
                    EpochKeyAck::decode_exact(&env.body)
                        .map(Delivered::Ack)
                        .map_err(|_| LinkError::Answer("malformed ack"))
                }
                Ok(_) => Err(LinkError::Answer("expected an ack")),
                Err(ClientError::Refused {
                    status: 409,
                    envelope,
                }) if envelope.kind == MessageKind::AnnouncementReply => {
                    let reply = AnnouncementReply::decode_exact(&envelope.body)
                        .map_err(|_| LinkError::Answer("malformed conflict"))?;
                    Ok(Delivered::Conflict(reply.0.map(|(ann, _)| ann)))
                }
                Err(ClientError::Status(409)) => Ok(Delivered::Conflict(None)),
                Err(e) => Err(e.into()),
            }
        })
    }

    fn query(
        &self,
        market: Address,
        member: u8,
        epoch: EpochId,
    ) -> BoxFuture<'_, Result<AnnouncementReply, LinkError>> {
        Box::pin(async move {
            let (client, url) = self.member(&market, member)?;
            let env = client
                .call(
                    &format!("{url}/krc/v1/announcements"),
                    MessageKind::AnnouncementQuery,
                    AnnouncementQuery { market, epoch }.to_bytes(),
                )
                .await?;
            if env.kind != MessageKind::AnnouncementReply {
                return Err(LinkError::Answer("expected an announcement reply"));
            }
            AnnouncementReply::decode_exact(&env.body)
                .map_err(|_| LinkError::Answer("malformed announcement reply"))
        })
    }

    fn put_bundle(
        &self,
        market: Address,
        epoch: EpochId,
        bundle: Vec<u8>,
    ) -> BoxFuture<'_, Result<(), LinkError>> {
        Box::pin(async move {
            let url = format!(
                "{}/internal/v1/markets/{}/epochs/{}/key",
                self.node_url,
                b58(&market),
                epoch.0
            );
            let env = self
                .node
                .call(&url, MessageKind::KeyBundlePut, bundle)
                .await?;
            if env.kind != MessageKind::Empty {
                return Err(LinkError::Answer("expected an empty answer"));
            }
            Ok(())
        })
    }
}

/// A market's committee as configured.
struct Committee {
    committee: CommitteeDescription,
    digest: Hash32,
}

pub struct Dealer {
    lookahead: u64,
    ack_timeout: Duration,
    interval: Duration,
    identity: Arc<Keypair>,
    repo: DealerRepo,
    rpc: Arc<dyn SolanaRpc>,
    program: Address,
    markets: BTreeMap<Address, Committee>,
    links: Arc<dyn DealerLinks>,
    /// Markets whose recovery query found nothing left to rule out.
    recovered: Mutex<BTreeSet<Address>>,
    metrics: DealerMetrics,
    /// When the last round over every market ended (ms since the Unix
    /// epoch), for readiness.
    last_round_ms: Arc<AtomicU64>,
}

impl core::fmt::Debug for Dealer {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Dealer")
            .field("identity", &Hash32(self.identity.public()))
            .field("markets", &self.markets.keys().map(b58).collect::<Vec<_>>())
            .finish_non_exhaustive()
    }
}

fn config_error(field: &str, message: impl Into<String>) -> DealError {
    DealError::Krc(KrcError::Config(timescales_service::ConfigError::Invalid(
        vec![timescales_service::ConfigIssue::new(field, message)],
    )))
}

fn committees(cfg: &DealerConfig) -> Result<BTreeMap<Address, CommitteeDescription>, DealError> {
    let mut out = BTreeMap::new();
    for (entry, address) in cfg.markets.iter().zip(cfg.market_addresses()) {
        let committee = load_committee(&entry.committee_file, &address)
            .map_err(|e| config_error("dealer.market.committee_file", e))?;
        if committee.members.len() != cfg.member_urls.len() {
            return Err(config_error(
                "dealer.member_urls",
                format!(
                    "{} URLs for a committee of {} in {}",
                    cfg.member_urls.len(),
                    committee.members.len(),
                    b58(&address)
                ),
            ));
        }
        out.insert(address, committee);
    }
    if out.is_empty() {
        return Err(config_error("dealer.market", "no market"));
    }
    Ok(out)
}

impl Dealer {
    /// Reads each market's committee description and reaches members and
    /// the node over HTTP ([`HttpLinks`]).
    pub fn new(
        cfg: DealerConfig,
        identity: Keypair,
        repo: DealerRepo,
        rpc: Arc<dyn SolanaRpc>,
    ) -> Result<Self, DealError> {
        let identity = Arc::new(identity);
        let links = HttpLinks::new(&cfg, Arc::clone(&identity), &committees(&cfg)?)
            .map_err(|e| config_error("dealer.tls", e.to_string()))?;
        Self::with_links(cfg, identity, repo, rpc, Arc::new(links))
    }

    /// [`Dealer::new`] with other [`DealerLinks`].
    pub fn with_links(
        cfg: DealerConfig,
        identity: Arc<Keypair>,
        repo: DealerRepo,
        rpc: Arc<dyn SolanaRpc>,
        links: Arc<dyn DealerLinks>,
    ) -> Result<Self, DealError> {
        let program = cfg
            .chain
            .program()
            .ok_or_else(|| config_error("dealer.chain.program_id", "not a base58 address"))?;
        let markets = committees(&cfg)?
            .into_iter()
            .map(|(m, committee)| {
                let digest = committee.digest();
                (m, Committee { committee, digest })
            })
            .collect();
        Ok(Self {
            lookahead: cfg.lookahead_epochs,
            ack_timeout: Duration::from_millis(cfg.ack_timeout_ms),
            interval: Duration::from_millis(cfg.interval_ms),
            identity,
            repo,
            rpc,
            program,
            markets,
            links,
            recovered: Mutex::new(BTreeSet::new()),
            metrics: DealerMetrics::default(),
            last_round_ms: Arc::new(AtomicU64::new(0)),
        })
    }

    pub fn metrics(&self) -> &DealerMetrics {
        &self.metrics
    }

    /// When [`Dealer::run`] last finished a round (ms since the Unix epoch).
    pub fn last_round(&self) -> Arc<AtomicU64> {
        Arc::clone(&self.last_round_ms)
    }

    /// Whether `dealer.sqlite` answers (fail-stop, as the member's).
    pub async fn store_ok(&self) -> bool {
        self.repo.dealing([0; 32], 0).await.is_ok()
    }

    /// Deals every market's window every `interval_ms` until `shutdown`.
    pub async fn run(self, shutdown: CancellationToken) -> Result<(), DealError> {
        let mut tick = tokio::time::interval(self.interval);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tokio::select! {
                () = shutdown.cancelled() => return Ok(()),
                _ = tick.tick() => {}
            }
            for &m in self.markets.keys() {
                if let Err(e) = self.tick(m).await {
                    tracing::warn!(market = %b58(&m), error = %e, "dealing round failed");
                }
            }
            if !self.store_ok().await {
                return Err(StoreError::Closed.into());
            }
            self.last_round_ms.store(now_ms(), Ordering::Relaxed);
        }
    }

    /// One round for market `m`: every epoch of the
    /// window is dealt or completed, then the deliveries of terminal epochs
    /// are dropped.
    async fn tick(&self, m: Address) -> Result<(), DealError> {
        let c = self.committee(&m)?;
        let acct = self.read_market(m, Level::Confirmed).await?;
        self.check_committee(&m, c, &acct)?;
        if !self.is_recovered(&m) {
            self.recover(m).await?;
        }
        let mut ready = 0u64;
        let mut ahead = true;
        let mut pending = 0u64;
        for e in acct.last_committed + 1..=acct.last_committed + self.lookahead {
            match self.deal_epoch(m, c, &acct, e).await {
                Ok(_) => {
                    if ahead {
                        ready += 1;
                    }
                }
                Err(err) => {
                    ahead = false;
                    pending += 1;
                    tracing::debug!(market = %b58(&m), epoch = e, error = %err, "epoch not ready");
                }
            }
        }
        self.metrics
            .lookahead_epochs
            .set(i64::try_from(ready).unwrap_or(i64::MAX));
        self.metrics
            .pending_deliveries
            .set(i64::try_from(pending).unwrap_or(i64::MAX));
        let settled = self.read_market(m, Level::Finalized).await?.last_settled;
        self.repo.prune_through(m, settled).await?;
        Ok(())
    }

    /// Idempotent.
    pub async fn deal_one(
        &self,
        market: Address,
        epoch: EpochId,
    ) -> Result<EpochKeyBundle, DealError> {
        let c = self.committee(&market)?;
        let acct = self.read_market(market, Level::Confirmed).await?;
        self.check_committee(&market, c, &acct)?;
        if !self.is_recovered(&market) {
            self.recover(market).await?;
        }
        self.deal_epoch(market, c, &acct, epoch.0).await
    }

    async fn deal_epoch(
        &self,
        m: Address,
        c: &Committee,
        acct: &MarketAccount,
        e: u64,
    ) -> Result<EpochKeyBundle, DealError> {
        let dealing = match self.repo.dealing(m, e).await? {
            Some(d) => d,
            None => {
                if e <= acct.last_committed {
                    return Err(DealError::Undealable(e));
                }
                let max = acct.last_committed.saturating_add(self.lookahead);
                if e > max {
                    return Err(DealError::TooFarAhead { epoch: e, max });
                }
                if !self.is_recovered(&m) {
                    return Err(DealError::Unconfirmed(e));
                }
                self.deal(m, c, EpochId(e)).await?;
                self.repo
                    .dealing(m, e)
                    .await?
                    .ok_or(StoreError::Corrupt("recorded dealing not found"))?
            }
        };
        let result = self.complete(m, c, e, dealing).await;
        match &result {
            Ok(_) => {}
            Err(DealError::NotEnoughAcks { .. }) => self.metrics.dealt("not_enough_acks"),
            Err(DealError::Undealable(_)) => self.metrics.dealt("undealable"),
            Err(_) => self.metrics.dealt("error"),
        }
        result
    }

    /// draws the polynomial, seals one share to each member,
    /// wipes the secret, the coefficients and the shares, and records the
    /// announcement with the sealed deliveries before anything is sent.
    async fn deal(&self, m: Address, c: &Committee, epoch: EpochId) -> Result<(), DealError> {
        let committee = &c.committee;
        let n = u8::try_from(committee.members.len()).unwrap_or(u8::MAX);
        let (announcement, deliveries) = {
            let (secret, commitments, shares) =
                FeldmanDealing::try_new(&mut OsRng, committee.threshold, n)
                    .map_err(|_| WireError::Committee("threshold does not fit the committee"))?;
            let epoch_pk = x25519_public(&secret);
            drop(secret);
            let ann = EpochKeyAnnouncement {
                version: EpochKeyAnnouncement::VERSION,
                market: m,
                epoch,
                committee_digest: c.digest,
                scheme: KeyScheme::FeldmanEd25519,
                epoch_pk,
                commitments,
            };
            let mut deliveries = Vec::with_capacity(shares.len());
            for share in &shares {
                let to = committee
                    .member(share.index)
                    .ok_or(WireError::UnknownMember(share.index))?;
                let d = ShareDelivery::seal(&mut OsRng, ann.clone(), to, share)?;
                deliveries.push((share.index, d.to_bytes()));
            }
            // The shares wipe themselves on drop. Only ciphertexts leave
            // this block.
            drop(shares);
            (ann, deliveries)
        };
        let outcome = self
            .repo
            .record_dealing(m, epoch.0, announcement.to_bytes(), deliveries)
            .await?;
        self.metrics.dealt("dealt");
        tracing::info!(
            market = %b58(&m),
            epoch = epoch.0,
            announcement = %announcement.digest(),
            ?outcome,
            "epoch dealt"
        );
        Ok(())
    }

    /// for a recorded dealing: the bundle if one is
    /// recorded, otherwise the stored deliveries to every member without a
    /// valid ack, then with >= t acks the write-ahead bundle and the node.
    async fn complete(
        &self,
        m: Address,
        c: &Committee,
        e: u64,
        d: Dealing,
    ) -> Result<EpochKeyBundle, DealError> {
        let ann = EpochKeyAnnouncement::decode_exact(&d.announcement)?;
        if let Some(bytes) = d.bundle {
            let bundle = EpochKeyBundle::decode_exact(&bytes)?;
            if !d.bundle_delivered {
                self.deliver_bundle(m, e, bytes).await?;
            }
            return Ok(bundle);
        }
        if ann.committee_digest != c.digest {
            // Dealt under another committee (adopted after a rotation):
            // this configuration can neither verify nor complete it.
            return Err(DealError::Undealable(e));
        }
        let digest = ann.digest();
        let need = c.committee.threshold;
        let mut acks: BTreeMap<u8, EpochKeyAck> = d
            .acks
            .iter()
            .filter_map(|bytes| EpochKeyAck::decode_exact(bytes).ok())
            .filter(|ack| self.valid_ack(c, &digest, ack))
            .map(|ack| (ack.member, ack))
            .collect();
        let missing: Vec<(u8, Vec<u8>)> = d
            .deliveries
            .into_iter()
            .filter(|(i, _)| !acks.contains_key(i))
            .collect();
        if acks.len() < usize::from(need) && missing.is_empty() {
            return Err(DealError::Undealable(e));
        }
        if acks.len() < usize::from(need) {
            let answers = join_all(missing.iter().map(|(i, bytes)| {
                tokio::time::timeout(self.ack_timeout, self.links.deliver(m, *i, bytes.clone()))
            }))
            .await;
            for ((i, _), answer) in missing.iter().zip(answers) {
                match answer {
                    Ok(Ok(Delivered::Ack(ack)))
                        if ack.member == *i && self.valid_ack(c, &digest, &ack) =>
                    {
                        self.repo.record_ack(m, e, ack.to_bytes()).await?;
                        acks.insert(ack.member, ack);
                    }
                    Ok(Ok(Delivered::Ack(_))) => {
                        tracing::warn!(market = %b58(&m), epoch = e, member = i, "invalid ack");
                    }
                    Ok(Ok(Delivered::Conflict(held))) => tracing::error!(
                        market = %b58(&m),
                        epoch = e,
                        member = i,
                        held = ?held.map(|a| a.digest()),
                        "member holds another announcement for this epoch"
                    ),
                    Ok(Err(err)) => {
                        tracing::warn!(market = %b58(&m), epoch = e, member = i, error = %err, "delivery failed");
                    }
                    Err(_) => {
                        tracing::warn!(market = %b58(&m), epoch = e, member = i, "delivery timed out");
                    }
                }
            }
        }
        let got = u8::try_from(acks.len()).unwrap_or(u8::MAX);
        if got < need {
            return Err(DealError::NotEnoughAcks { got, need });
        }
        let bundle = EpochKeyBundle {
            announcement: ann,
            acks: acks.into_values().collect(),
        };
        let bytes = bundle.to_bytes();
        self.repo.bundle_intent(m, e, bytes.clone()).await?;
        self.deliver_bundle(m, e, bytes).await?;
        Ok(bundle)
    }

    async fn deliver_bundle(&self, m: Address, e: u64, bytes: Vec<u8>) -> Result<(), DealError> {
        self.links
            .put_bundle(m, EpochId(e), bytes)
            .await
            .map_err(|err| DealError::Node(err.to_string()))?;
        self.repo.bundle_delivered(m, e).await?;
        self.metrics.dealt("bundled");
        tracing::info!(market = %b58(&m), epoch = e, "bundle delivered to the node");
        Ok(())
    }

    fn valid_ack(&self, c: &Committee, digest: &Hash32, ack: &EpochKeyAck) -> bool {
        c.committee
            .member(ack.member)
            .is_some_and(|member| ack.verify(digest, &member.identity).is_ok())
    }

    /// After loss of `dealer.sqlite`: asks every member for its
    /// announcement of each epoch in the window that has no recorded
    /// dealing and adopts what they hold. With >= t valid acks the bundle is
    /// rebuilt and sent to the node. With fewer the epoch stays undealt.
    /// An epoch nobody reported is cleared for dealing once at least
    /// `n - t + 1` members answered: with `n <= 2t - 1`, any announcement
    /// that ever reached t acks is held by one of them.
    pub async fn recover(&self, market: Address) -> Result<RecoveryReport, DealError> {
        let c = self.committee(&market)?;
        let acct = self.read_market(market, Level::Confirmed).await?;
        self.check_committee(&market, c, &acct)?;
        let n = c.committee.members.len();
        let t = usize::from(c.committee.threshold);
        let need_answers = n + 1 - t;
        let mut report = RecoveryReport::default();
        let mut complete = true;
        for e in acct.last_committed + 1..=acct.last_committed + self.lookahead {
            if self.repo.dealing(market, e).await?.is_some() {
                continue;
            }
            let replies = join_all(c.committee.members.iter().map(|member| {
                tokio::time::timeout(
                    self.ack_timeout,
                    self.links.query(market, member.index, EpochId(e)),
                )
            }))
            .await;
            let mut answered = 0usize;
            let mut found: BTreeMap<Hash32, (EpochKeyAnnouncement, Vec<EpochKeyAck>)> =
                BTreeMap::new();
            for (member, reply) in c.committee.members.iter().zip(replies) {
                let Ok(Ok(AnnouncementReply(held))) = reply else {
                    continue;
                };
                answered += 1;
                let Some((ann, ack)) = held else { continue };
                if ann.market != market || ann.epoch.0 != e {
                    continue;
                }
                let entry = found
                    .entry(ann.digest())
                    .or_insert_with(|| (ann, Vec::new()));
                if ack.member == member.index {
                    entry.1.push(ack);
                }
            }
            if found.is_empty() {
                if answered < need_answers {
                    complete = false;
                }
                continue;
            }
            if found.len() > 1 {
                tracing::error!(
                    market = %b58(&market),
                    epoch = e,
                    announcements = found.len(),
                    "members hold different announcements for one epoch"
                );
            }
            let candidates = found.into_iter().map(|(digest, (ann, acks))| {
                let valid: Vec<EpochKeyAck> = if ann.committee_digest == c.digest {
                    acks.into_iter()
                        .filter(|a| self.valid_ack(c, &digest, a))
                        .collect()
                } else {
                    Vec::new()
                };
                (ann, valid)
            });
            let Some((ann, acks)) = candidates.max_by_key(|(_, acks)| acks.len()) else {
                continue;
            };
            let adopted = self
                .repo
                .adopt(
                    market,
                    e,
                    ann.to_bytes(),
                    acks.iter().map(Encode::to_bytes).collect(),
                )
                .await;
            match adopted {
                Ok(()) => report.adopted.push(e),
                Err(StoreError::Conflict(why)) => {
                    // A committee an emergency rotation superseded for this
                    // epoch: what the members hold is void.
                    tracing::warn!(market = %b58(&market), epoch = e, why, "announcement not adopted");
                    if answered < need_answers {
                        complete = false;
                    }
                    continue;
                }
                Err(err) => return Err(err.into()),
            }
            if ann.committee_digest != c.digest {
                continue;
            }
            if acks.len() >= t {
                let mut sorted = acks;
                sorted.sort_by_key(|a| a.member);
                let bundle = EpochKeyBundle {
                    announcement: ann,
                    acks: sorted,
                };
                let bytes = bundle.to_bytes();
                self.repo.bundle_intent(market, e, bytes.clone()).await?;
                match self.deliver_bundle(market, e, bytes).await {
                    Ok(()) => report.rebuilt_bundles.push(e),
                    // Recorded as intent: the next round sends it again.
                    Err(err) => {
                        tracing::warn!(market = %b58(&market), epoch = e, error = %err, "rebuilt bundle not delivered")
                    }
                }
            } else {
                report.undealable.push(e);
            }
        }
        if !report.adopted.is_empty() {
            self.metrics.recoveries.inc();
            tracing::warn!(
                market = %b58(&market),
                adopted = ?report.adopted,
                rebuilt = ?report.rebuilt_bundles,
                undealable = ?report.undealable,
                "recovered announcements from members"
            );
        }
        if complete {
            self.recovered.lock().insert(market);
        }
        Ok(report)
    }

    /// Emergency rotation: drops this dealer's dealings of the
    /// previous committee from `from_epoch` on, once the configured
    /// committee is the one on chain, so those epochs are dealt again under
    /// it. Returns how many dealings were dropped.
    pub async fn supersede(&self, market: Address, from_epoch: EpochId) -> Result<u64, DealError> {
        let c = self.committee(&market)?;
        let acct = self.read_market(market, Level::Confirmed).await?;
        self.check_committee(&market, c, &acct)?;
        if acct.prev_committee_digest == Hash32::ZERO {
            return Err(KrcError::Chain(ChainError::Inconsistent(
                "the market has no previous committee",
            ))
            .into());
        }
        let dropped = self
            .repo
            .supersede(market, from_epoch.0, acct.prev_committee_digest)
            .await?;
        tracing::warn!(
            market = %b58(&market),
            from_epoch = from_epoch.0,
            dropped,
            "dealings of the previous committee superseded"
        );
        Ok(dropped)
    }

    fn committee(&self, m: &Address) -> Result<&Committee, DealError> {
        self.markets
            .get(m)
            .ok_or(DealError::Krc(KrcError::UnknownMarket(*m)))
    }

    fn is_recovered(&self, m: &Address) -> bool {
        self.recovered.lock().contains(m)
    }

    fn check_committee(
        &self,
        m: &Address,
        c: &Committee,
        acct: &MarketAccount,
    ) -> Result<(), DealError> {
        if acct.committee_digest != c.digest {
            self.metrics.committee_mismatch.set(1);
            tracing::error!(
                market = %b58(m),
                configured = %c.digest,
                onchain = %acct.committee_digest,
                "configured committee differs from Market.committee_digest"
            );
            return Err(DealError::CommitteeMismatch);
        }
        self.metrics.committee_mismatch.set(0);
        Ok(())
    }

    async fn read_market(&self, m: Address, level: Level) -> Result<MarketAccount, DealError> {
        let account = self
            .rpc
            .get_account(m, level, None)
            .await
            .map_err(KrcError::Rpc)?
            .ok_or(KrcError::UnknownMarket(m))?;
        if account.owner != self.program {
            return Err(KrcError::Chain(ChainError::Inconsistent(
                "market account not owned by the settlement program",
            ))
            .into());
        }
        Ok(timescales_chain::program::decode_market(&account.data)
            .map_err(|e| KrcError::Chain(ChainError::Decode(e)))?)
    }
}
