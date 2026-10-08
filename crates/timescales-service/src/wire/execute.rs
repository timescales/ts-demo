//! Execution requests from the node to enclaves and their responses.
//!
//! ```text
//! ExecuteRequest  = ver u8 (1) || market32 || commit_slot u64 || ExecutionBatch || EpochKeyBundle
//!                   || CommitteeDescription || price_commitment32 || Provenance
//! Provenance      = seq<GrantRecord> (<= 1024) || seq<ProvenanceEntry> (= envelope count)
//! GrantRecord     = bytes text (UTF-8, <= 1024) || sig64 || method u8
//! ProvenanceEntry = grant u32 || session_sig64
//! ExecuteReady    = executor32 || header_digest32 || outcome_digest32 || cosign_sig64
//!                   || seq<u32> unauthenticated (<= 1024)
//! PublishRequest  = market32 || epoch u64 || header_digest32 || seq<(executor32 || sig64)> (<= 7)
//! ExecutePosted   = ExecutionReceipt || ExecutionArtifacts || bytes attestation (<= 64 KiB)
//!                   || PostedTx || seq<PostedTx> (<= 7)
//! PostedTx        = sig64 || slot u64
//! ErrorResponse   = code u8 (1..= 10) || bytes detail (UTF-8, <= 64) || u8 has_receipt
//!                   || [ExecutionReceipt]
//! ```
//!
//! An `ErrorResponse` carries a receipt exactly when its code is
//! `OutcomeMismatch`. With at most two clearing prices it stays within the
//! 512-byte body of its envelope kind.
//!
//! The batch inside an `ExecuteRequest` has the `ExecutionBatch` layout,
//! decoded here with the bounds of header version 2: at most
//! `MAX_SETTLEMENT_DELTAS` envelopes, checked before any is read, and no
//! masked intents.

use timescales_auction::BatchHeader;
use timescales_auction::receipts::{ExecutionArtifacts, ExecutionReceipt};
use timescales_core::crypto::Signature;
use timescales_core::intent::{ENVELOPE_LEN, SealedEnvelope};
use timescales_core::{
    Decode, DecodeError, Encode, EpochId, ExecutorId, Hash32, MAX_SETTLEMENT_DELTAS, Reader,
    encoding::{put_bool, put_bytes, put_seq, put_u8, put_u32, put_u64},
};
use timescales_executor::ExecutionBatch;
use timescales_executor::attestation::{Evidence, Platform};
use timescales_executor::tee::codec::HEADER_LEN;

use crate::wire::text::{read_utf8, truncate_utf8};
use crate::wire::{CommitteeDescription, EpochKeyBundle};

/// Most envelopes an executed batch holds.
pub const MAX_EXECUTE_ENVELOPES: usize = MAX_SETTLEMENT_DELTAS as usize;
/// Most distinct session grants one batch refers to.
pub const MAX_GRANTS: usize = 1024;
/// Longest grant text.
pub const MAX_GRANT_TEXT: usize = 1024;
/// Most envelope indices an enclave reports as unauthenticated.
pub const MAX_UNAUTHENTICATED: usize = MAX_SETTLEMENT_DELTAS as usize;
/// Most co-signatures beside the poster's own receipt: one per other
/// executor slot (`MAX_EXECUTORS` = 8).
pub const MAX_COSIGS: usize = 7;
/// Largest attestation an enclave returns with a posted receipt.
pub const MAX_POSTED_ATTESTATION_LEN: usize = 64 * 1024;
/// Longest detail of an enclave's [`ErrorResponse`].
pub const MAX_ERROR_DETAIL: usize = 64;

/// Who submitted each envelope (provenance). `grants` are
/// deduplicated. `entries.len == batch.envelopes.len`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Provenance {
    pub grants: Vec<GrantRecord>,
    pub entries: Vec<ProvenanceEntry>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GrantRecord {
    /// Exact signed UTF-8, at most 1024 bytes.
    pub text: String,
    pub signature: Signature,
    pub method: GrantMethod,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProvenanceEntry {
    /// Index into `grants`. `u32::MAX` = none (relay cover).
    pub grant: u32,
    /// The submission's signature by the session key.
    pub session_signature: Signature,
}

#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GrantMethod {
    SignIn = 0,
    SignMessage = 1,
}

#[derive(Clone, Debug)]
pub struct ExecuteRequest {
    pub version: u8,
    pub market: [u8; 32],
    pub commit_slot: u64,
    pub batch: ExecutionBatch,
    pub bundle: EpochKeyBundle,
    pub committee: CommitteeDescription,
    pub price_commitment: Hash32,
    pub provenance: Provenance,
}

/// Returned by every executing enclave. Reveals nothing about fills:
/// digests and a co-signature only.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExecuteReady {
    pub executor: ExecutorId,
    pub header_digest: Hash32,
    pub outcome_digest: Hash32,
    pub cosign: Signature,
    /// Indices that failed decryption, intent signature or provenance. Never
    /// collateral or matching reasons.
    pub unauthenticated: Vec<u32>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublishRequest {
    pub market: [u8; 32],
    pub epoch: EpochId,
    pub header_digest: Hash32,
    pub cosigs: Vec<(ExecutorId, Signature)>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExecutePosted {
    pub receipt: ExecutionReceipt,
    pub artifacts: ExecutionArtifacts,
    pub attestation: Vec<u8>,
    pub posted: PostedTx,
    pub cosigned: Vec<PostedTx>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PostedTx {
    pub signature: [u8; 64],
    pub slot: u64,
}

/// An enclave's registration identity: its keys and evidence binding
/// `registration_report_data(seal_key, executor, program, market, nonce)`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EnclaveIdentity {
    pub executor: ExecutorId,
    pub seal_key: [u8; 32],
    pub platform: Platform,
    pub measurement: Hash32,
    pub evidence: Evidence,
    pub fee_payer: [u8; 32],
}

impl Encode for GrantMethod {
    fn encode(&self, out: &mut Vec<u8>) {
        put_u8(out, *self as u8);
    }
}

impl Decode for GrantMethod {
    fn decode(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        match r.u8()? {
            0 => Ok(GrantMethod::SignIn),
            1 => Ok(GrantMethod::SignMessage),
            tag => Err(DecodeError::InvalidTag {
                ty: "GrantMethod",
                tag,
            }),
        }
    }
}

impl GrantRecord {
    /// An empty text.
    pub const MIN_ENCODED_LEN: usize = 4 + 64 + 1;
}

impl Encode for GrantRecord {
    fn encode(&self, out: &mut Vec<u8>) {
        put_bytes(out, self.text.as_bytes());
        self.signature.encode(out);
        self.method.encode(out);
    }
}

impl Decode for GrantRecord {
    fn decode(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        Ok(GrantRecord {
            text: read_utf8(r, MAX_GRANT_TEXT, "GrantRecord.text")?,
            signature: Signature::decode(r)?,
            method: GrantMethod::decode(r)?,
        })
    }
}

impl ProvenanceEntry {
    /// `grant` of an envelope no session submitted (relay cover).
    pub const NO_GRANT: u32 = u32::MAX;
    pub const ENCODED_LEN: usize = 4 + 64;
    pub const MIN_ENCODED_LEN: usize = Self::ENCODED_LEN;
}

impl Encode for ProvenanceEntry {
    fn encode(&self, out: &mut Vec<u8>) {
        put_u32(out, self.grant);
        self.session_signature.encode(out);
    }
}

impl Decode for ProvenanceEntry {
    fn decode(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        Ok(ProvenanceEntry {
            grant: r.u32()?,
            session_signature: Signature::decode(r)?,
        })
    }
}

impl Provenance {
    /// No grants and no entries.
    pub const MIN_ENCODED_LEN: usize = 4 + 4;
}

impl Encode for Provenance {
    fn encode(&self, out: &mut Vec<u8>) {
        put_seq(out, &self.grants);
        put_seq(out, &self.entries);
    }
}

/// Every entry names a grant of the list or [`ProvenanceEntry::NO_GRANT`].
impl Decode for Provenance {
    fn decode(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        let grants: Vec<GrantRecord> = r.seq(MAX_GRANTS)?;
        let entries: Vec<ProvenanceEntry> = r.seq(MAX_EXECUTE_ENVELOPES)?;
        let known = |g: u32| {
            g == ProvenanceEntry::NO_GRANT || usize::try_from(g).is_ok_and(|g| g < grants.len())
        };
        if !entries.iter().all(|e| known(e.grant)) {
            return Err(DecodeError::InvalidValue("Provenance.entries"));
        }
        Ok(Provenance { grants, entries })
    }
}

impl ExecuteRequest {
    pub const VERSION: u8 = 1;
    /// An empty batch (header and four empty lists: envelopes, masked
    /// intents, balances, prior state), a dev-scheme bundle without acks, a
    /// one-member committee and no provenance.
    pub const MIN_ENCODED_LEN: usize = 1
        + 32
        + 8
        + (HEADER_LEN + 4 + 4 + 4 + 4)
        + EpochKeyBundle::MIN_ENCODED_LEN
        + CommitteeDescription::MIN_ENCODED_LEN
        + 32
        + Provenance::MIN_ENCODED_LEN;
}

impl Encode for ExecuteRequest {
    fn encode(&self, out: &mut Vec<u8>) {
        put_u8(out, self.version);
        out.extend_from_slice(&self.market);
        put_u64(out, self.commit_slot);
        self.batch.encode(out);
        self.bundle.encode(out);
        self.committee.encode(out);
        self.price_commitment.encode(out);
        self.provenance.encode(out);
    }
}

impl Decode for ExecuteRequest {
    fn decode(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        if r.u8()? != Self::VERSION {
            return Err(DecodeError::InvalidValue("ExecuteRequest.version"));
        }
        let market = r.array()?;
        let commit_slot = r.u64()?;
        let batch = decode_batch_v2(r)?;
        let bundle = EpochKeyBundle::decode(r)?;
        let committee = CommitteeDescription::decode(r)?;
        let price_commitment = Hash32::decode(r)?;
        let provenance = Provenance::decode(r)?;
        if provenance.entries.len() != batch.envelopes.len() {
            return Err(DecodeError::InvalidValue("ExecuteRequest.provenance"));
        }
        Ok(ExecuteRequest {
            version: Self::VERSION,
            market,
            commit_slot,
            batch,
            bundle,
            committee,
            price_commitment,
            provenance,
        })
    }
}

/// `ExecutionBatch` with the header version 2 bounds: the envelope count is
/// bounded (and checked against the input left) before anything is
/// allocated, and the masked-intent list must be empty.
fn decode_batch_v2(r: &mut Reader<'_>) -> Result<ExecutionBatch, DecodeError> {
    let header = BatchHeader::decode(r)?;
    let count = r.len_prefix(MAX_EXECUTE_ENVELOPES)?;
    if count > r.remaining() / ENVELOPE_LEN {
        return Err(DecodeError::UnexpectedEof {
            needed: count.saturating_mul(ENVELOPE_LEN),
            remaining: r.remaining(),
        });
    }
    let mut envelopes = Vec::with_capacity(count);
    for _ in 0..count {
        envelopes.push(SealedEnvelope::decode(r)?);
    }
    r.len_prefix(0)?;
    // The balance sheet and the prior order state decode with their own
    // canonical-order checks. Their types are inferred from the batch.
    let balances = Decode::decode(r)?;
    let prior_state = Decode::decode(r)?;
    Ok(ExecutionBatch {
        header,
        envelopes,
        masked: Vec::new(),
        balances,
        prior_state,
    })
}

impl ExecuteReady {
    /// No unauthenticated indices.
    pub const MIN_ENCODED_LEN: usize = 32 + 32 + 32 + 64 + 4;
}

impl Encode for ExecuteReady {
    fn encode(&self, out: &mut Vec<u8>) {
        self.executor.encode(out);
        self.header_digest.encode(out);
        self.outcome_digest.encode(out);
        self.cosign.encode(out);
        put_u32(
            out,
            u32::try_from(self.unauthenticated.len()).unwrap_or(u32::MAX),
        );
        for i in &self.unauthenticated {
            put_u32(out, *i);
        }
    }
}

impl Decode for ExecuteReady {
    fn decode(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        let executor = ExecutorId::decode(r)?;
        let header_digest = Hash32::decode(r)?;
        let outcome_digest = Hash32::decode(r)?;
        let cosign = Signature::decode(r)?;
        let count = r.len_prefix(MAX_UNAUTHENTICATED)?;
        let mut unauthenticated = Vec::with_capacity(count.min(r.remaining() / 4));
        for _ in 0..count {
            unauthenticated.push(r.u32()?);
        }
        Ok(ExecuteReady {
            executor,
            header_digest,
            outcome_digest,
            cosign,
            unauthenticated,
        })
    }
}

impl PublishRequest {
    /// No co-signatures.
    pub const MIN_ENCODED_LEN: usize = 32 + 8 + 32 + 4;
}

impl Encode for PublishRequest {
    fn encode(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.market);
        self.epoch.encode(out);
        self.header_digest.encode(out);
        put_u32(out, u32::try_from(self.cosigs.len()).unwrap_or(u32::MAX));
        for (executor, sig) in &self.cosigs {
            executor.encode(out);
            sig.encode(out);
        }
    }
}

impl Decode for PublishRequest {
    fn decode(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        let market = r.array()?;
        let epoch = EpochId::decode(r)?;
        let header_digest = Hash32::decode(r)?;
        let count = r.len_prefix(MAX_COSIGS)?;
        let mut cosigs = Vec::with_capacity(count);
        for _ in 0..count {
            cosigs.push((ExecutorId::decode(r)?, Signature::decode(r)?));
        }
        Ok(PublishRequest {
            market,
            epoch,
            header_digest,
            cosigs,
        })
    }
}

impl PostedTx {
    pub const ENCODED_LEN: usize = 64 + 8;
    pub const MIN_ENCODED_LEN: usize = Self::ENCODED_LEN;
}

impl Encode for PostedTx {
    fn encode(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.signature);
        put_u64(out, self.slot);
    }
}

impl Decode for PostedTx {
    fn decode(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        Ok(PostedTx {
            signature: r.array()?,
            slot: r.u64()?,
        })
    }
}

impl ExecutePosted {
    /// A receipt without clearing prices (390 bytes), empty artifacts (36),
    /// an empty attestation, the posting transaction and no co-signatures.
    pub const MIN_ENCODED_LEN: usize = 390 + 36 + 4 + PostedTx::ENCODED_LEN + 4;
}

impl Encode for ExecutePosted {
    fn encode(&self, out: &mut Vec<u8>) {
        self.receipt.encode(out);
        self.artifacts.encode(out);
        put_bytes(out, &self.attestation);
        self.posted.encode(out);
        put_seq(out, &self.cosigned);
    }
}

impl Decode for ExecutePosted {
    fn decode(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        Ok(ExecutePosted {
            receipt: ExecutionReceipt::decode(r)?,
            artifacts: ExecutionArtifacts::decode(r)?,
            attestation: r.bytes(MAX_POSTED_ATTESTATION_LEN)?,
            posted: PostedTx::decode(r)?,
            cosigned: r.seq(MAX_COSIGS)?,
        })
    }
}

/// Why an enclave refused an execute or publish call.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EnclaveRefusal {
    /// The header's epoch binding names another key or committee.
    BindingMismatch = 1,
    /// The batch's balance sheet disagrees with the chain. No key was
    /// requested.
    BalanceMismatch = 2,
    /// The committee did not release enough valid shares.
    KeyUnavailable = 3,
    BadRequest = 4,
    /// The enclave runs as many executions as it allows.
    Busy = 5,
    /// The receipt was not seen on chain by the post deadline. The result
    /// stays cached.
    PostFailed = 6,
    /// Another outcome was posted for the batch. The response carries this
    /// enclave's signed receipt as evidence.
    OutcomeMismatch = 7,
    /// The co-signatures are not enough distinct registered executors'
    /// signatures over this outcome.
    QuorumInvalid = 8,
    /// The same outcome is posted, but its quorum is not on chain yet.
    QuorumPending = 9,
    /// No completed execution for the header.
    NotExecuted = 10,
}

impl EnclaveRefusal {
    pub const ALL: [EnclaveRefusal; 10] = [
        EnclaveRefusal::BindingMismatch,
        EnclaveRefusal::BalanceMismatch,
        EnclaveRefusal::KeyUnavailable,
        EnclaveRefusal::BadRequest,
        EnclaveRefusal::Busy,
        EnclaveRefusal::PostFailed,
        EnclaveRefusal::OutcomeMismatch,
        EnclaveRefusal::QuorumInvalid,
        EnclaveRefusal::QuorumPending,
        EnclaveRefusal::NotExecuted,
    ];

    pub fn from_u8(code: u8) -> Option<Self> {
        Self::ALL.get(usize::from(code).checked_sub(1)?).copied()
    }
}

/// The body of an enclave's `ErrorResponse` envelope.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ErrorResponse {
    pub code: EnclaveRefusal,
    /// A short UTF-8 detail, at most 64 bytes, for example the number of
    /// traders whose balance disagrees. Never order data.
    pub detail: String,
    /// This enclave's signed receipt. Present exactly with
    /// [`EnclaveRefusal::OutcomeMismatch`].
    pub receipt: Option<ExecutionReceipt>,
}

impl ErrorResponse {
    /// An empty detail and no receipt.
    pub const MIN_ENCODED_LEN: usize = 1 + 4 + 1;

    /// A refusal without a receipt, for every code but
    /// [`EnclaveRefusal::OutcomeMismatch`] (see [`Self::outcome_mismatch`]).
    /// `detail` is cut to 64 bytes at a character boundary.
    pub fn refused(code: EnclaveRefusal, detail: &str) -> Self {
        ErrorResponse {
            code,
            detail: truncate_utf8(detail, MAX_ERROR_DETAIL).to_owned(),
            receipt: None,
        }
    }

    /// The refusal of a publish call for a batch whose posted outcome is
    /// not this enclave's, with this enclave's receipt.
    pub fn outcome_mismatch(receipt: ExecutionReceipt, detail: &str) -> Self {
        ErrorResponse {
            code: EnclaveRefusal::OutcomeMismatch,
            detail: truncate_utf8(detail, MAX_ERROR_DETAIL).to_owned(),
            receipt: Some(receipt),
        }
    }
}

impl Encode for EnclaveRefusal {
    fn encode(&self, out: &mut Vec<u8>) {
        put_u8(out, *self as u8);
    }
}

impl Decode for EnclaveRefusal {
    fn decode(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        let tag = r.u8()?;
        Self::from_u8(tag).ok_or(DecodeError::InvalidTag {
            ty: "EnclaveRefusal",
            tag,
        })
    }
}

impl Encode for ErrorResponse {
    fn encode(&self, out: &mut Vec<u8>) {
        self.code.encode(out);
        put_bytes(
            out,
            truncate_utf8(&self.detail, MAX_ERROR_DETAIL).as_bytes(),
        );
        put_bool(out, self.receipt.is_some());
        if let Some(receipt) = &self.receipt {
            receipt.encode(out);
        }
    }
}

impl Decode for ErrorResponse {
    fn decode(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        let code = EnclaveRefusal::decode(r)?;
        let detail = read_utf8(r, MAX_ERROR_DETAIL, "ErrorResponse.detail")?;
        let receipt = if r.bool()? {
            Some(ExecutionReceipt::decode(r)?)
        } else {
            None
        };
        if receipt.is_some() != (code == EnclaveRefusal::OutcomeMismatch) {
            return Err(DecodeError::InvalidValue("ErrorResponse.receipt"));
        }
        Ok(ErrorResponse {
            code,
            detail,
            receipt,
        })
    }
}
