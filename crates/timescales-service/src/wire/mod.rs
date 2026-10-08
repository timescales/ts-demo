//! Every cross-process message of the Timescales services.
//!
//! Internal requests and responses travel in a [`SignedEnvelope`] whose
//! fixed 94-byte prefix is checked before the body is read. The messages
//! themselves cover epoch-key dealing (announcements, bundles, acks, share
//! deliveries), key release (challenge and release), execution (execute,
//! ready, publish, posted), relay-signed public statements (epoch
//! announcements and refusals) and SIWS session grants.
//!
//! Every codec uses `timescales_core::encoding`: little-endian integers,
//! strict tags and bools, length prefixes checked against a bound before
//! allocating, and `decode_exact`. Versioned messages accept only the
//! version they define. Each message type has a `MIN_ENCODED_LEN`, and
//! fixed-size ones an `ENCODED_LEN`.

#![cfg_attr(test, allow(clippy::unwrap_used, clippy::cast_possible_truncation))]

mod announcement;
mod committee;
mod envelope;
mod execute;
mod keys;
mod points;
mod release;
mod session;
mod text;

pub use announcement::{AnnouncementFields, EpochAnnouncement, RelayRefusal};
pub use committee::{CommitteeDescription, CommitteeMember, MAX_COMMITTEE, ReleasePolicyStatement};
pub use envelope::{
    EnvelopePrefix, EnvelopeSigner, MessageKind, PREFIX_LEN, ReplayGuard, SignedEnvelope,
    WIRE_VERSION, WireError,
};
pub use execute::{
    EnclaveIdentity, EnclaveRefusal, ErrorResponse, ExecutePosted, ExecuteReady, ExecuteRequest,
    GrantMethod, GrantRecord, MAX_COSIGS, MAX_ERROR_DETAIL, MAX_EXECUTE_ENVELOPES, MAX_GRANT_TEXT,
    MAX_GRANTS, MAX_POSTED_ATTESTATION_LEN, MAX_UNAUTHENTICATED, PostedTx, Provenance,
    ProvenanceEntry, PublishRequest,
};
pub use keys::{
    AnnouncementQuery, AnnouncementReply, EpochKeyAck, EpochKeyAnnouncement, EpochKeyBundle,
    KeyScheme, ShareDelivery, ack_digest,
};
pub use release::{
    ChallengeRequest, ChallengeResponse, MAX_REFUSAL_DETAIL, ReleaseRefusal, ReleaseRequest,
    ReleaseResponse,
};
pub use session::{
    ChainId, GrantExpectations, MAX_SESSION_TEXT_BYTES, SESSION_STATEMENT, SessionAuthorization,
    SessionGrant, check_session_nonce, issue_session_nonce, parse_session_message,
    render_session_message, session_request_digest,
};
