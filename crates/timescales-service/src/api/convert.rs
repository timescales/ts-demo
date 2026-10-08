//! Conversions from protocol types (accounts, receipts, bundles,
//! announcements, promises and refusals) into DTOs.
//!
//! Each conversion takes the protocol values the node holds (accounts as
//! the chain crate decodes them, wire messages, receipts, promises) and
//! the node's own facts that the chain does not record, and checks that the
//! parts agree before it builds the DTO. A node must never serve a key
//! bundle for another epoch than the announcement that names it, or a
//! committee description whose digest is not the one on chain: clients
//! reject such data and stop trading on the market. Nothing here
//! verifies signatures. That is the clients' job.

use crate::relay::{InclusionPromiseV2, Padding};
use crate::wire::{
    CommitteeDescription, EpochAnnouncement, EpochKeyBundle, RelayRefusal, ReleasePolicyStatement,
};
use timescales_auction::BatchHeader;
use timescales_auction::receipts::{BackendKind, ExecutionReceipt};
use timescales_chain::program::loader::ProgramData;
use timescales_chain::program::spl::Mint;
use timescales_chain::program::{
    BatchAccount, BatchStatus, GovernanceChange, MarketAccount, PendingChange,
};
use timescales_core::oracle::PriceCommitment;
use timescales_core::{
    BookId, ClearingPrice, CommitmentScheme, Encode, FlowMode, HEADER_VERSION_ENVELOPE_BOUND,
    Hash32, MarketParams, PROTOCOL_VERSION, PriceBand, Rationing,
};

use crate::api::schema::NUM_MAX;
use crate::api::{
    AbortReason, AbortView, B58, B58Sig, B64, Band, BatchFullDetails, BatchView, Book, BookLabel,
    ChangeKind, Clearing, CommitmentSchemeJson, CommitteeMemberView, CommitteeView, CurrentEpoch,
    DuplicateCommitmentDetails, EnclavePlatform, EpochClosedDetails, EpochDetail, EpochKey,
    EpochPhaseRef, EpochSummary, ErrorCode, FlowJson, Hex32, Intake, IntakePausedDetails,
    MarketChainState, MarketDetail, MarketParamsJson, MarketState, MarketSummary, MintAuthorities,
    MintAuthority, Observation, OpenEpoch, OutcomeView, PaddingView, PauseReason,
    PendingChangeView, PriceCommitmentView, ProblemDetails, ProgramView, PublicPhase, Quorum,
    QuotaExceededDetails, RationingJson, RealSlotsLeft, ReceiptBackend, ReceiptView,
    ReferencePrice, RelayPolicyView, SettlementStatus, SettlementView, SubmitResult, SubmitStatus,
    TimingView, TxView, U64,
};

/// Why protocol values do not make a DTO.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum ConvertError {
    /// Two inputs that must agree do not, for example a key bundle and the
    /// announcement that names it.
    #[error("{0} does not match")]
    Mismatch(&'static str),
    /// A value v1 of the API cannot express, for example a Poseidon market
    /// or a receipt of a backend other than the TEE.
    #[error("{0} is not supported by the v1 API")]
    Unsupported(&'static str),
    /// A count above the largest `Num` (2^31 - 1).
    #[error("{0} does not fit a Num")]
    OutOfRange(&'static str),
}

fn num(v: u32, what: &'static str) -> Result<u32, ConvertError> {
    if u64::from(v) <= NUM_MAX {
        Ok(v)
    } else {
        Err(ConvertError::OutOfRange(what))
    }
}

fn require(ok: bool, what: &'static str) -> Result<(), ConvertError> {
    if ok {
        Ok(())
    } else {
        Err(ConvertError::Mismatch(what))
    }
}

// ---- Market ----

pub fn book(b: BookId) -> Book {
    match b {
        BookId::Single => Book::Single,
        BookId::MakerAskTakerBid => Book::MakerAskTakerBid,
        BookId::MakerBidTakerAsk => Book::MakerBidTakerAsk,
    }
}

/// The books a market of this flow clears, in book order.
pub fn books(flow: FlowMode) -> &'static [Book] {
    match flow {
        FlowMode::SingleBook => &[Book::Single],
        FlowMode::DualFlow => &[Book::MakerAskTakerBid, Book::MakerBidTakerAsk],
    }
}

pub fn band(b: &PriceBand) -> Band {
    Band {
        lo: U64(b.lo.0),
        hi: U64(b.hi.0),
        reference: U64(b.reference.0),
    }
}

pub fn clearing(prices: &[ClearingPrice]) -> Vec<Clearing> {
    prices
        .iter()
        .map(|c| Clearing {
            book: book(c.book),
            tick: U64(c.tick.0),
            volume: U64(c.volume.0),
        })
        .collect()
}

/// `params` as JSON. Only SHA-256 markets exist in v1.
pub fn market_params(p: &MarketParams) -> Result<MarketParamsJson, ConvertError> {
    let commitment_scheme = match p.commitment_scheme {
        CommitmentScheme::Sha256 => CommitmentSchemeJson::Sha256,
        CommitmentScheme::PoseidonBn254 => {
            return Err(ConvertError::Unsupported("Poseidon commitment scheme"));
        }
    };
    Ok(MarketParamsJson {
        market: U64(p.market.0),
        base_lot_size: U64(p.base_lot_size),
        tick_size: U64(p.tick_size),
        band_half_width: num(p.band_half_width, "band_half_width")?,
        max_order_lots_log2: u32::from(p.max_order_lots_log2),
        max_orders_per_trader: u32::from(p.max_orders_per_trader),
        max_batch_envelopes: num(p.max_batch_envelopes, "max_batch_envelopes")?,
        max_order_lifetime: num(p.max_order_lifetime, "max_order_lifetime")?,
        maker_fee_bps: u32::from(p.maker_fee.0),
        taker_fee_bps: u32::from(p.taker_fee.0),
        flow: match p.flow {
            FlowMode::SingleBook => FlowJson::SingleBook,
            FlowMode::DualFlow => FlowJson::DualFlow,
        },
        rationing: match p.rationing {
            Rationing::Lottery => RationingJson::Lottery,
            Rationing::ProRata => RationingJson::ProRata,
        },
        commitment_scheme,
    })
}

pub fn change_kind(c: &GovernanceChange) -> ChangeKind {
    match c {
        GovernanceChange::SetRelay(_) => ChangeKind::SetRelay,
        GovernanceChange::SetExecutors { .. } => ChangeKind::SetExecutors,
        GovernanceChange::SetCommitteeDigest(_) => ChangeKind::SetCommitteeDigest,
        GovernanceChange::SetAdmin(_) => ChangeKind::SetAdmin,
        GovernanceChange::SetTimings { .. } => ChangeKind::SetTimings,
        GovernanceChange::SetTimelock(_) => ChangeKind::SetTimelock,
    }
}

/// The market's pending change as seen at `slot`: it is due once `slot`
/// reaches its eta.
pub fn pending_change(p: &PendingChange, slot: u64) -> Result<PendingChangeView, ConvertError> {
    let payload = p
        .change
        .payload()
        .map_err(|_| ConvertError::OutOfRange("pending executor set"))?;
    Ok(PendingChangeView {
        kind: change_kind(&p.change),
        eta_slot: U64(p.eta_slot),
        payload_b64: B64(payload),
        due: slot >= p.eta_slot,
    })
}

/// The relay's padding. A relay that publishes the real count has no v1
/// representation, and the node never runs one.
pub fn padding(p: Padding) -> Result<PaddingView, ConvertError> {
    match p {
        Padding::None => Err(ConvertError::Unsupported("unpadded batches")),
        Padding::PowerOfTwo { min } => Ok(PaddingView::PowerOfTwo {
            min: num(min, "padding minimum")?,
        }),
        Padding::Fixed(n) => Ok(PaddingView::Fixed {
            n: num(n, "fixed padding")?,
        }),
    }
}

fn mint_authority(m: &Mint) -> MintAuthority {
    MintAuthority {
        mint: m.mint_authority.map(B58),
        freeze: m.freeze_authority.map(B58),
    }
}

/// The committee view of a market. `description` must be the one whose
/// digest is on chain, `prev` the one of `prev_committee_digest` when a
/// rotation set it, and every policy statement must be a current member's.
pub fn committee(
    market_address: &[u8; 32],
    account: &MarketAccount,
    description: &CommitteeDescription,
    prev: Option<&CommitteeDescription>,
    policies: &[ReleasePolicyStatement],
) -> Result<CommitteeView, ConvertError> {
    require(
        description.digest() == account.committee_digest,
        "committee digest",
    )?;
    require(description.market == *market_address, "committee market")?;
    let prev_digest =
        (account.prev_committee_digest != Hash32::ZERO).then_some(account.prev_committee_digest);
    match (prev_digest, prev) {
        (None, None) => {}
        (Some(d), Some(p)) => {
            require(p.digest() == d, "previous committee digest")?;
            require(p.market == *market_address, "previous committee market")?;
        }
        _ => return Err(ConvertError::Mismatch("previous committee")),
    }
    for p in policies {
        require(
            p.market == *market_address
                && p.committee_digest == account.committee_digest
                && description.member(p.member).is_some(),
            "release policy statement",
        )?;
    }
    Ok(CommitteeView {
        digest: account.committee_digest.into(),
        description_b64: B64(description.to_bytes()),
        threshold: u32::from(description.threshold),
        members: description
            .members
            .iter()
            .map(|m| CommitteeMemberView {
                index: u32::from(m.index),
                identity: Hex32(m.identity),
                transport: Hex32(m.transport),
            })
            .collect(),
        prev_digest: prev_digest.map(Hex32::from),
        prev_description_b64: prev.map(|p| B64(p.to_bytes())),
        policies_b64: policies.iter().map(|p| B64(p.to_bytes())).collect(),
    })
}

/// What the node knows about a market besides its account: display names,
/// its state, the mints and the program data it read, the committee
/// documents, and its relay configuration.
#[derive(Clone, Debug)]
pub struct MarketFacts {
    pub name: String,
    pub base_symbol: String,
    pub quote_symbol: String,
    pub state: MarketState,
    pub last_clearing: Option<Vec<Clearing>>,
    pub base_mint: Mint,
    pub quote_mint: Mint,
    pub committee: CommitteeDescription,
    /// The description whose digest is `prev_committee_digest`, if the
    /// account has one.
    pub prev_committee: Option<CommitteeDescription>,
    /// The current members' signed release policies (V-14).
    pub policies: Vec<ReleasePolicyStatement>,
    pub epoch_interval_ms: u32,
    pub max_park_ahead_epochs: u32,
    pub relay_policy: RelayPolicyView,
    pub session_domains: Vec<String>,
    /// One label per book of the market's flow, in book order.
    pub books: Vec<BookLabel>,
    pub program: ProgramData,
    /// The slot the account and the mints were read at.
    pub context_slot: u64,
}

/// `GET /v1/markets/{market}` from the Market account at `address`.
pub fn market_detail(
    address: [u8; 32],
    account: &MarketAccount,
    facts: MarketFacts,
) -> Result<MarketDetail, ConvertError> {
    require(
        account.params.market.0 == account.market_id,
        "params market id",
    )?;
    let flow_books = books(account.params.flow);
    require(
        facts
            .books
            .iter()
            .map(|b| b.book)
            .eq(flow_books.iter().copied()),
        "books of the market's flow",
    )?;
    let committee = committee(
        &address,
        account,
        &facts.committee,
        facts.prev_committee.as_ref(),
        &facts.policies,
    )?;
    Ok(MarketDetail {
        summary: MarketSummary {
            market: B58(address),
            name: facts.name,
            base_symbol: facts.base_symbol,
            quote_symbol: facts.quote_symbol,
            state: facts.state,
            halted: account.halted,
            last_clearing: facts.last_clearing,
        },
        market_id: U64(account.market_id),
        creator: B58(account.creator),
        admin: B58(account.admin),
        params: market_params(&account.params)?,
        params_b64: B64(account.params.to_bytes()),
        params_digest: account.params_digest.into(),
        base_mint: B58(account.base_mint),
        quote_mint: B58(account.quote_mint),
        base_vault: B58(account.base_vault),
        quote_vault: B58(account.quote_vault),
        base_decimals: u32::from(facts.base_mint.decimals),
        quote_decimals: u32::from(facts.quote_mint.decimals),
        relay: B58(account.relay),
        executors: account
            .executors
            .iter()
            .filter(|k| **k != [0; 32])
            .copied()
            .map(B58)
            .collect(),
        receipt_quorum: u32::from(account.receipt_quorum),
        committee,
        timing: TimingView {
            epoch_interval_ms: num(facts.epoch_interval_ms, "epoch_interval_ms")?,
            beacon_delay_slots: u32::from(account.beacon_delay_slots),
            exec_timeout_slots: U64(account.exec_timeout_slots),
            settle_timeout_slots: U64(account.settle_timeout_slots),
            timelock_slots: U64(account.timelock_slots),
            max_park_ahead_epochs: num(facts.max_park_ahead_epochs, "max_park_ahead_epochs")?,
        },
        relay_policy: facts.relay_policy,
        market_id_salt: Hex32(account.salt),
        session_domains: facts.session_domains,
        mint_authorities: MintAuthorities {
            base: mint_authority(&facts.base_mint),
            quote: mint_authority(&facts.quote_mint),
        },
        books: facts.books,
        pending_change: account
            .pending
            .as_ref()
            .map(|p| pending_change(p, facts.context_slot))
            .transpose()?,
        program: ProgramView {
            upgrade_authority: facts.program.upgrade_authority.map(B58),
            last_deploy_slot: U64(facts.program.last_deploy_slot),
        },
        chain: MarketChainState {
            last_committed: U64(account.last_committed),
            last_settled: U64(account.last_settled),
            state_root: account.state_root.into(),
            prev_receipt: account.prev_receipt.into(),
            context_slot: U64(facts.context_slot),
        },
    })
}

// ---- Epoch keys and the open epoch ----

/// `GET /v1/markets/{market}/epochs/{epoch}/key`.
pub fn epoch_key(bundle: &EpochKeyBundle) -> EpochKey {
    let a = &bundle.announcement;
    EpochKey {
        epoch: U64(a.epoch.0),
        epoch_pk: Hex32(a.epoch_pk),
        committee_digest: a.committee_digest.into(),
        bundle_b64: B64(bundle.to_bytes()),
    }
}

/// `CurrentEpoch.open.price_commitment` from the commitment itself:
/// its digest, reference and observations, and its canonical bytes. The
/// source is the node's configured price source, which the commitment does
/// not record.
pub fn price_commitment(
    c: &PriceCommitment,
    source: ReferencePrice,
) -> Result<PriceCommitmentView, ConvertError> {
    Ok(PriceCommitmentView {
        digest: c.digest().into(),
        reference: U64(c.reference.0),
        source,
        observations: c
            .observations
            .iter()
            .map(|o| {
                Ok(Observation {
                    source: num(o.source, "observation source")?,
                    tick: U64(o.tick.0),
                    time: U64(o.time),
                })
            })
            .collect::<Result<_, ConvertError>>()?,
        commitment_b64: B64(c.to_bytes()),
    })
}

/// The relay's announcement names this bundle's key and committee (V-4).
fn check_key(a: &EpochAnnouncement, bundle: &EpochKeyBundle) -> Result<(), ConvertError> {
    let k = &bundle.announcement;
    require(k.market == a.market, "key bundle market")?;
    require(k.epoch == a.epoch, "key bundle epoch")?;
    require(k.digest() == a.key_digest, "announced key digest")?;
    require(
        k.committee_digest == a.committee_digest,
        "announced committee digest",
    )
}

/// The open epoch of `CurrentEpoch`: its announcement, its key and the
/// price commitment the announcement binds.
pub fn open_epoch(
    announcement: &EpochAnnouncement,
    bundle: &EpochKeyBundle,
    price_commitment: PriceCommitmentView,
    real_slots_left: RealSlotsLeft,
) -> Result<OpenEpoch, ConvertError> {
    check_key(announcement, bundle)?;
    require(
        price_commitment.digest == Hex32::from(announcement.price_commitment),
        "price commitment digest",
    )?;
    require(
        price_commitment.reference.0 == announcement.band.reference.0,
        "price commitment reference",
    )?;
    Ok(OpenEpoch {
        epoch: U64(announcement.epoch.0),
        opens_at_ms: announcement.opens_at_ms,
        cutoff_ms: announcement.cutoff_ms,
        band: band(&announcement.band),
        binding: announcement.binding().into(),
        terms_digest: announcement.terms_digest().into(),
        price_commitment,
        announcement_b64: B64(announcement.to_bytes()),
        key: epoch_key(bundle),
        real_slots_left,
    })
}

/// The epoch open for intake.
#[derive(Clone, Debug)]
pub struct OpenFacts {
    pub announcement: EpochAnnouncement,
    pub bundle: EpochKeyBundle,
    pub price_commitment: PriceCommitmentView,
    pub real_slots_left: RealSlotsLeft,
}

/// The node's view of a market's epochs, as `CurrentEpoch` reports it.
#[derive(Clone, Debug)]
pub struct CurrentFacts {
    pub server_time_ms: u64,
    pub intake: Intake,
    /// Set only while intake is paused.
    pub pause_reason: Option<PauseReason>,
    pub open: Option<OpenFacts>,
    /// Verified bundles of the epochs after the open one that accept
    /// parked envelopes, in epoch order.
    pub park_window: Vec<EpochKeyBundle>,
    pub previous: Option<EpochPhaseRef>,
    pub inflight: Option<EpochPhaseRef>,
    pub context_slot: u64,
}

/// `GET /v1/markets/{market}/epochs/current` for the market at `market`.
pub fn current_epoch(market: [u8; 32], facts: CurrentFacts) -> Result<CurrentEpoch, ConvertError> {
    require(
        facts.pause_reason.is_none() || facts.intake == Intake::Paused,
        "pause reason of open intake",
    )?;
    let mut after = None;
    let open = match facts.open {
        Some(o) => {
            require(o.announcement.market == market, "announcement market")?;
            after = Some(o.announcement.epoch);
            Some(open_epoch(
                &o.announcement,
                &o.bundle,
                o.price_commitment,
                o.real_slots_left,
            )?)
        }
        None => None,
    };
    for b in &facts.park_window {
        let a = &b.announcement;
        require(a.market == market, "park window market")?;
        require(after.is_none_or(|e| a.epoch > e), "park window epochs")?;
        after = Some(a.epoch);
    }
    Ok(CurrentEpoch {
        market: B58(market),
        server_time_ms: facts.server_time_ms,
        intake: facts.intake,
        pause_reason: facts.pause_reason,
        open,
        park_window: facts.park_window.iter().map(epoch_key).collect(),
        previous: facts.previous,
        inflight: facts.inflight,
        context_slot: U64(facts.context_slot),
    })
}

// ---- Committed epochs ----

pub fn abort_reason(r: timescales_chain::program::AbortReason) -> AbortReason {
    use timescales_chain::program::AbortReason as Chain;
    match r {
        Chain::Admin => AbortReason::Admin,
        Chain::Relay => AbortReason::Relay,
        Chain::BeaconExpired => AbortReason::BeaconExpired,
        Chain::ExecTimeout => AbortReason::ExecTimeout,
        Chain::SettleTimeout => AbortReason::SettleTimeout,
        Chain::QuorumTimeout => AbortReason::QuorumTimeout,
    }
}

/// The `status` string of `EpochDetail.batch`: the program's status name.
pub fn batch_status(s: BatchStatus) -> &'static str {
    match s {
        BatchStatus::Committed => "committed",
        BatchStatus::BeaconRevealed => "beacon_revealed",
        BatchStatus::ReceiptPosted => "receipt_posted",
        BatchStatus::Verified => "verified",
        BatchStatus::Settled => "settled",
        BatchStatus::Aborted => "aborted",
    }
}

/// `RevealBeacon` ran: it is the only writer of `reveal_slot`, which is
/// past `commit_slot + d` and so never zero.
fn revealed(b: &BatchAccount) -> bool {
    b.reveal_slot != 0
}

/// `PostReceipt` ran. Likewise the only writer of `receipt_slot`. Both stay
/// set when the batch is aborted later.
fn posted(b: &BatchAccount) -> bool {
    b.receipt_slot != 0
}

/// A committed batch as the chain holds it.
#[derive(Clone, Debug)]
pub struct ChainBatch {
    pub address: [u8; 32],
    pub account: BatchAccount,
    /// Signature of the `CommitBatch` transaction.
    pub commit_signature: [u8; 64],
}

/// `EpochDetail.batch`. Co-signers are the market's live executors whose
/// bit is set, the poster included. A removed executor's signature no
/// longer counts towards the quorum, so it is not listed either.
pub fn batch_view(
    batch: &ChainBatch,
    market: &MarketAccount,
    context_slot: u64,
) -> Result<BatchView, ConvertError> {
    let b = &batch.account;
    let posted = posted(b);
    let live = b.cosign_bitmap & market.live_slots();
    let cosigners: Vec<B58> = market
        .executors
        .iter()
        .enumerate()
        .filter(|(i, _)| live & (1 << i) != 0)
        .map(|(_, k)| B58(*k))
        .collect();
    Ok(BatchView {
        address: B58(batch.address),
        status: batch_status(b.status).to_owned(),
        root: b.root.into(),
        count: num(b.count, "envelope count")?,
        terms_digest: b.terms_digest.into(),
        commit_slot: U64(b.commit_slot),
        commit_signature: B58Sig(batch.commit_signature),
        beacon: revealed(b).then(|| b.beacon.into()),
        beacon_slots: revealed(b).then_some([U64(b.beacon_slot_a), U64(b.beacon_slot_b)]),
        reveal_slot: revealed(b).then_some(U64(b.reveal_slot)),
        header_digest: posted.then(|| b.header_digest.into()),
        receipt_digest: posted.then(|| b.receipt.into()),
        outcome_digest: posted.then(|| b.outcome_digest.into()),
        cosigners,
        quorum: Quorum {
            have: live.count_ones(),
            need: u32::from(market.receipt_quorum),
        },
        settlement_count: posted
            .then(|| num(b.settlement_count, "settlement count"))
            .transpose()?,
        fees: posted.then_some(U64(b.fees)),
        context_slot: U64(context_slot),
    })
}

/// Settlement progress once a receipt is posted.
pub fn settlement_view(b: &BatchAccount) -> Result<Option<SettlementView>, ConvertError> {
    if !posted(b) {
        return Ok(None);
    }
    let status = match b.status {
        BatchStatus::Committed | BatchStatus::BeaconRevealed => {
            return Err(ConvertError::Mismatch("receipt slot of an unposted batch"));
        }
        BatchStatus::ReceiptPosted if b.verified_count == 0 => SettlementStatus::Posted,
        BatchStatus::ReceiptPosted => SettlementStatus::Verifying,
        BatchStatus::Verified if b.applied_count == 0 => SettlementStatus::Verified,
        BatchStatus::Verified => SettlementStatus::Applying,
        BatchStatus::Settled => SettlementStatus::Settled,
        BatchStatus::Aborted => SettlementStatus::Aborted,
    };
    Ok(Some(SettlementView {
        status,
        verified: num(b.verified_count, "verified count")?,
        applied: num(b.applied_count, "applied count")?,
        total: num(b.settlement_count, "settlement count")?,
    }))
}

/// `EpochDetail.receipt`: a version 1 receipt of the TEE backend, the only
/// kind the program accepts.
pub fn receipt_view(r: &ExecutionReceipt) -> Result<ReceiptView, ConvertError> {
    if r.version != PROTOCOL_VERSION {
        return Err(ConvertError::Unsupported("receipt version"));
    }
    if r.backend != BackendKind::Tee {
        return Err(ConvertError::Unsupported("receipt backend"));
    }
    let o = &r.outcome;
    Ok(ReceiptView {
        version: u32::from(r.version),
        digest: r.digest().into(),
        backend: ReceiptBackend::Tee,
        executor: B58::from(r.executor),
        attestation: r.attestation.into(),
        proof: r.proof.into(),
        trace: r.trace.into(),
        outcome: OutcomeView {
            header_digest: o.header_digest.into(),
            clearing: clearing(&o.clearing),
            fill_count: num(o.fill_count, "fill count")?,
            fills_root: o.fills_root.into(),
            cancelled_root: o.cancelled_root.into(),
            next_state_root: o.next_state_root.into(),
            settlement_count: num(o.settlement_count, "settlement count")?,
            settlement_root: o.settlement_root.into(),
            fees: U64(o.fees.0),
        },
    })
}

/// What the node holds about one epoch besides the market account.
#[derive(Clone, Debug)]
pub struct EpochFacts {
    pub phase: PublicPhase,
    pub terminal_at_ms: Option<u64>,
    /// Platform of the posting enclave's attestation.
    pub tee_platform: Option<EnclavePlatform>,
    pub announcement: EpochAnnouncement,
    pub bundle: EpochKeyBundle,
    /// The committed batch, once `CommitBatch` landed.
    pub batch: Option<ChainBatch>,
    /// The header v2 the batch executes under, once assembled.
    pub header: Option<BatchHeader>,
    /// The posted receipt.
    pub receipt: Option<ExecutionReceipt>,
    /// The store's flag, set once the receipt quorum is on chain.
    pub artifacts_public: bool,
    pub txs: Vec<TxView>,
    /// Why the batch was aborted, in words. Used only for an aborted batch.
    pub abort_detail: String,
    /// The slot the batch account was read at.
    pub context_slot: u64,
}

/// The header executes the announced terms and the committed batch, and
/// is the one the posted receipt names.
fn check_header(
    h: &BatchHeader,
    market: &MarketAccount,
    a: &EpochAnnouncement,
    batch: Option<&BatchAccount>,
) -> Result<(), ConvertError> {
    if h.version != HEADER_VERSION_ENVELOPE_BOUND {
        return Err(ConvertError::Unsupported("header version"));
    }
    require(h.market.0 == market.market_id, "header market")?;
    require(h.epoch == a.epoch, "header epoch")?;
    require(
        h.band == a.band && h.price_commitment == a.binding(),
        "header terms",
    )?;
    let b = batch.ok_or(ConvertError::Mismatch("header of an uncommitted epoch"))?;
    require(
        h.batch_root == b.root && h.envelope_count == b.count,
        "header batch",
    )?;
    if posted(b) {
        require(h.digest() == b.header_digest, "header digest")?;
    }
    Ok(())
}

fn check_receipt(
    r: &ExecutionReceipt,
    market: &MarketAccount,
    a: &EpochAnnouncement,
    batch: Option<&BatchAccount>,
    header: Option<&BatchHeader>,
) -> Result<(), ConvertError> {
    let b = batch
        .filter(|b| posted(b))
        .ok_or(ConvertError::Mismatch("receipt of an unposted batch"))?;
    require(
        r.outcome.market.0 == market.market_id && r.outcome.epoch == a.epoch,
        "receipt epoch",
    )?;
    require(r.digest() == b.receipt, "receipt digest")?;
    if let Some(h) = header {
        require(r.outcome.header_digest == h.digest(), "receipt header")?;
    }
    Ok(())
}

/// `GET /v1/markets/{market}/epochs/{epoch}`. The summary's clearing and
/// fill count come from the posted receipt and are left out once the
/// batch is aborted: nothing traded.
pub fn epoch_detail(
    market: &MarketAccount,
    facts: EpochFacts,
) -> Result<EpochDetail, ConvertError> {
    let a = &facts.announcement;
    check_key(a, &facts.bundle)?;
    let account = facts.batch.as_ref().map(|b| &b.account);
    if let Some(b) = account {
        require(b.market == a.market, "batch market")?;
        require(b.epoch == a.epoch.0, "batch epoch")?;
        require(b.terms_digest == a.terms_digest(), "batch terms digest")?;
    }
    if let Some(h) = &facts.header {
        check_header(h, market, a, account)?;
    }
    if let Some(r) = &facts.receipt {
        check_receipt(r, market, a, account, facts.header.as_ref())?;
    }
    require(
        !facts.artifacts_public || account.is_some_and(posted),
        "artifacts_public of an unposted batch",
    )?;
    let aborted = account.and_then(|b| b.abort_reason).map(abort_reason);
    let receipt = facts.receipt.as_ref().map(receipt_view).transpose()?;
    let traded = receipt.as_ref().filter(|_| aborted.is_none());
    Ok(EpochDetail {
        summary: EpochSummary {
            market: B58(a.market),
            epoch: U64(a.epoch.0),
            phase: facts.phase,
            opens_at_ms: a.opens_at_ms,
            cutoff_ms: a.cutoff_ms,
            envelope_count: account
                .map(|b| num(b.count, "envelope count"))
                .transpose()?,
            clearing: traded.map(|r| r.outcome.clearing.clone()),
            fill_count: traded.map(|r| r.outcome.fill_count),
            terminal_at_ms: facts.terminal_at_ms,
            abort_reason: aborted,
            tee_platform: facts.tee_platform,
        },
        band: band(&a.band),
        terms_digest: a.terms_digest().into(),
        announcement_b64: B64(a.to_bytes()),
        key: epoch_key(&facts.bundle),
        batch: facts
            .batch
            .as_ref()
            .map(|b| batch_view(b, market, facts.context_slot))
            .transpose()?,
        artifacts_public: facts.artifacts_public,
        header_b64: facts.header.as_ref().map(|h| B64(h.to_bytes())),
        receipt_b64: facts.receipt.as_ref().map(|r| B64(r.to_bytes())),
        receipt,
        settlement: account.map(settlement_view).transpose()?.flatten(),
        txs: facts.txs,
        abort: aborted.map(|reason| AbortView {
            reason,
            detail: facts.abort_detail,
        }),
    })
}

// ---- Submissions ----

/// The `202` of a submission (and the `ok` of a batch item): the relay's
/// promise, and whether these exact bytes were submitted before.
pub fn submit_result(
    promise: &InclusionPromiseV2,
    status: SubmitStatus,
    received_at_ms: u64,
    duplicate: bool,
) -> SubmitResult {
    SubmitResult {
        status,
        market: B58(promise.market),
        epoch: U64(promise.epoch.0),
        commitment: promise.commitment.into(),
        envelope_digest: promise.envelope_digest.into(),
        received_at_ms,
        promise_b64: B64(promise.to_bytes()),
        duplicate,
    }
}

/// `DUPLICATE_COMMITMENT`: the wallet submitted other bytes under this
/// commitment before, and `original` is the promise it got for them.
pub fn duplicate_commitment(original: &InclusionPromiseV2) -> ProblemDetails {
    ProblemDetails::DuplicateCommitment(DuplicateCommitmentDetails {
        promise_b64: B64(original.to_bytes()),
    })
}

/// Why intake refused an otherwise valid submission, with what the
/// problem's details carry besides the refusal.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refused {
    /// `fair_share` when the per-wallet fair share applied.
    BatchFull {
        fair_share: Option<u32>,
    },
    IntakePaused {
        reason: PauseReason,
    },
    QuotaExceeded,
    EpochClosed {
        next_epoch: u64,
        next_opens_at_ms: u64,
    },
}

impl Refused {
    pub fn code(&self) -> ErrorCode {
        match self {
            Refused::BatchFull { .. } => ErrorCode::BatchFull,
            Refused::IntakePaused { .. } => ErrorCode::IntakePaused,
            Refused::QuotaExceeded => ErrorCode::QuotaExceeded,
            Refused::EpochClosed { .. } => ErrorCode::EpochClosed,
        }
    }
}

/// The details of a refused submission, carrying the relay-signed
/// `refusal`, whose code must be the one of `refused`.
pub fn refusal_details(
    refusal: &RelayRefusal,
    refused: Refused,
) -> Result<ProblemDetails, ConvertError> {
    require(
        refused.code().refusal_code() == Some(refusal.code),
        "refusal code",
    )?;
    let refusal_b64 = B64(refusal.to_bytes());
    Ok(match refused {
        Refused::BatchFull { fair_share } => ProblemDetails::BatchFull(BatchFullDetails {
            fair_share: fair_share.map(|f| num(f, "fair share")).transpose()?,
            refusal_b64,
        }),
        Refused::IntakePaused { reason } => ProblemDetails::IntakePaused(IntakePausedDetails {
            reason,
            refusal_b64,
        }),
        Refused::QuotaExceeded => {
            ProblemDetails::QuotaExceeded(QuotaExceededDetails { refusal_b64 })
        }
        Refused::EpochClosed {
            next_epoch,
            next_opens_at_ms,
        } => {
            require(next_epoch > refusal.epoch.0, "next epoch")?;
            ProblemDetails::EpochClosed(EpochClosedDetails {
                next_epoch: U64(next_epoch),
                next_opens_at_ms,
                refusal_b64,
            })
        }
    })
}
