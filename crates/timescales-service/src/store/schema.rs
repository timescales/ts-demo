//! Forward-only migrations of every database file.
//!
//! Migration `n` of a schema moves `PRAGMA user_version` from `n - 1` to
//! `n`. All pending migrations of a file run in one transaction. The first
//! migration also stamps `PRAGMA application_id`, so a file is never opened
//! as another schema (`node.sqlite` as `shares.sqlite`, say).

use crate::store::Schema;

impl Schema {
    /// The migrations of this schema, oldest first.
    pub(crate) fn migrations(self) -> &'static [&'static str] {
        match self {
            Schema::Node => &[NODE_V1],
            Schema::Member => &[MEMBER_V1],
            Schema::MemberShares => &[SHARES_V1],
            Schema::Dealer => &[DEALER_V1],
        }
    }

    /// `PRAGMA application_id` stamped by the first migration.
    pub(crate) fn application_id(self) -> i32 {
        let tag: &[u8; 4] = match self {
            Schema::Node => b"TSND",
            Schema::Member => b"TSMB",
            Schema::MemberShares => b"TSSH",
            Schema::Dealer => b"TSDL",
        };
        i32::from_be_bytes(*tag)
    }

    pub(crate) fn name(self) -> &'static str {
        match self {
            Schema::Node => "node",
            Schema::Member => "member",
            Schema::MemberShares => "member shares",
            Schema::Dealer => "dealer",
        }
    }
}

/// Node store schema. Three details matter: `parked.envelope_digest` (a parked row
/// becomes a submission row when its epoch opens), indexes on `session_pk`
/// (a session is kept while any row still links to it) and `AUTOINCREMENT`
/// on `events.seq` (the stream sequence never repeats, even after the log
/// is pruned empty).
const NODE_V1: &str = "
CREATE TABLE meta(k TEXT PRIMARY KEY, v BLOB NOT NULL);
CREATE TABLE epochs(market BLOB NOT NULL, epoch INTEGER NOT NULL, phase INTEGER NOT NULL, opens_at_ms INTEGER,
  cutoff_ms INTEGER, reference INTEGER, band BLOB, price_commitment BLOB, committee_digest BLOB, binding BLOB,
  terms_digest BLOB, announcement BLOB, root BLOB, envelope_count INTEGER, real_count INTEGER, cover_count INTEGER,
  commit_sig BLOB, commit_slot INTEGER, snapshot_slot INTEGER, snapshot_late INTEGER NOT NULL DEFAULT 0, beacon BLOB,
  reveal_slot INTEGER, header BLOB, receipt BLOB, receipt_slot INTEGER, artifacts_public INTEGER NOT NULL DEFAULT 0,
  abort_reason INTEGER, abort_detail TEXT, terminal_slot INTEGER, updated_at_ms INTEGER NOT NULL,
  PRIMARY KEY(market, epoch));
CREATE TABLE submissions(market BLOB NOT NULL, epoch INTEGER NOT NULL, commitment BLOB NOT NULL,
  envelope_digest BLOB NOT NULL, wallet BLOB, session_pk BLOB, submission BLOB NOT NULL, promise BLOB NOT NULL,
  received_at_ms INTEGER NOT NULL, PRIMARY KEY(market, epoch, commitment, wallet));
CREATE INDEX submissions_wallet ON submissions(market, epoch, wallet);
CREATE INDEX submissions_session ON submissions(session_pk);
CREATE TABLE parked(market BLOB NOT NULL, epoch INTEGER NOT NULL, commitment BLOB NOT NULL,
  envelope_digest BLOB NOT NULL, wallet BLOB NOT NULL, session_pk BLOB NOT NULL, submission BLOB NOT NULL,
  promise BLOB NOT NULL, received_at_ms INTEGER NOT NULL, PRIMARY KEY(market, epoch, commitment, wallet));
CREATE INDEX parked_wallet ON parked(market, wallet);
CREATE INDEX parked_session ON parked(session_pk);
CREATE TABLE sessions(session_pk BLOB PRIMARY KEY, wallet BLOB NOT NULL, market BLOB, grant_text TEXT NOT NULL,
  signature BLOB NOT NULL, method INTEGER NOT NULL, nonce BLOB NOT NULL, issued_at_ms INTEGER, expires_at_ms INTEGER,
  revoked INTEGER NOT NULL DEFAULT 0, keep_until_epoch INTEGER);
CREATE UNIQUE INDEX sessions_grant ON sessions(wallet, nonce);
CREATE TABLE used_nonces(nonce BLOB PRIMARY KEY, expires_at_ms INTEGER NOT NULL);
CREATE TABLE bans(market BLOB NOT NULL, wallet BLOB NOT NULL, until_epoch INTEGER NOT NULL, reason TEXT NOT NULL,
  PRIMARY KEY(market, wallet));
CREATE TABLE closed(market BLOB NOT NULL, epoch INTEGER NOT NULL, closed BLOB NOT NULL, leaves BLOB NOT NULL,
  PRIMARY KEY(market, epoch));
CREATE TABLE cover_carry(market BLOB NOT NULL, commitment BLOB NOT NULL, sealed_intent BLOB NOT NULL,
  last_epoch INTEGER NOT NULL, PRIMARY KEY(market, commitment));
CREATE TABLE snapshots(market BLOB NOT NULL, epoch INTEGER NOT NULL, sheet BLOB NOT NULL, slot INTEGER NOT NULL,
  PRIMARY KEY(market, epoch));
CREATE TABLE sealed(market BLOB NOT NULL, epoch INTEGER NOT NULL, header BLOB NOT NULL, batch BLOB NOT NULL,
  PRIMARY KEY(market, epoch));
CREATE TABLE attempts(market BLOB NOT NULL, epoch INTEGER NOT NULL, n INTEGER NOT NULL, enclave TEXT NOT NULL,
  started_at_ms INTEGER NOT NULL, result TEXT, detail TEXT, PRIMARY KEY(market, epoch, n));
CREATE TABLE results(market BLOB NOT NULL, epoch INTEGER NOT NULL, receipt BLOB NOT NULL, artifacts BLOB NOT NULL,
  attestation BLOB, cosigs BLOB, PRIMARY KEY(market, epoch));
CREATE TABLE fills(market BLOB NOT NULL, epoch INTEGER NOT NULL, idx INTEGER NOT NULL, commitment BLOB NOT NULL,
  trader BLOB NOT NULL, book INTEGER NOT NULL, side INTEGER NOT NULL, role INTEGER NOT NULL, qty INTEGER NOT NULL,
  tick INTEGER NOT NULL, PRIMARY KEY(market, epoch, idx));
CREATE TABLE deltas(market BLOB NOT NULL, epoch INTEGER NOT NULL, idx INTEGER NOT NULL, trader BLOB NOT NULL,
  base INTEGER NOT NULL, quote INTEGER NOT NULL, PRIMARY KEY(market, epoch, idx));
CREATE TABLE cancelled(market BLOB NOT NULL, epoch INTEGER NOT NULL, idx INTEGER NOT NULL, commitment BLOB NOT NULL,
  PRIMARY KEY(market, epoch, idx));
CREATE TABLE order_state(market BLOB NOT NULL, epoch INTEGER NOT NULL, tbl BLOB NOT NULL, root BLOB NOT NULL,
  confirmed INTEGER NOT NULL, PRIMARY KEY(market, epoch));
CREATE TABLE key_bundles(market BLOB NOT NULL, epoch INTEGER NOT NULL, bundle BLOB NOT NULL, received_at_ms INTEGER,
  served INTEGER NOT NULL DEFAULT 0, PRIMARY KEY(market, epoch));
CREATE TABLE txs(id INTEGER PRIMARY KEY, market BLOB NOT NULL, epoch INTEGER, op TEXT NOT NULL, signature BLOB NOT NULL,
  last_valid_block_height INTEGER NOT NULL, status TEXT NOT NULL, error TEXT, sent_at_ms INTEGER NOT NULL, slot INTEGER);
CREATE INDEX txs_epoch ON txs(market, epoch);
CREATE INDEX txs_status ON txs(status);
CREATE TABLE events(seq INTEGER PRIMARY KEY AUTOINCREMENT, market BLOB, topic TEXT NOT NULL,
  topic_seq INTEGER NOT NULL, at_ms INTEGER NOT NULL, event TEXT NOT NULL);
";

/// Member store schema. Announcements keep their digest instead of the ack: the repository
/// is never handed an ack, and the member re-derives it (Ed25519 signatures
/// are deterministic).
const MEMBER_V1: &str = "
CREATE TABLE meta(k TEXT PRIMARY KEY, v BLOB NOT NULL);
CREATE TABLE announcements(market BLOB NOT NULL, epoch INTEGER NOT NULL, announcement BLOB NOT NULL,
  ann_digest BLOB NOT NULL, received_at_ms INTEGER NOT NULL, PRIMARY KEY(market, epoch));
CREATE TABLE pins(market BLOB NOT NULL, epoch INTEGER NOT NULL, header_digest BLOB NOT NULL, releases INTEGER NOT NULL,
  pinned_at_ms INTEGER NOT NULL, PRIMARY KEY(market, epoch));
CREATE TABLE releases(id INTEGER PRIMARY KEY, market BLOB NOT NULL, epoch INTEGER NOT NULL, executor BLOB NOT NULL,
  seal_key BLOB NOT NULL, header_digest BLOB NOT NULL, quote_hash BLOB NOT NULL, result INTEGER NOT NULL,
  at_ms INTEGER NOT NULL);
CREATE INDEX releases_at ON releases(at_ms);
";

/// The only table of `shares.sqlite`.
const SHARES_V1: &str = "
CREATE TABLE shares(market BLOB NOT NULL, epoch INTEGER NOT NULL, ann_digest BLOB NOT NULL,
  kek_generation INTEGER NOT NULL, share_sealed BLOB NOT NULL, received_at_ms INTEGER NOT NULL,
  PRIMARY KEY(market, epoch));
";

/// Dealer store schema, with the committee digest of each dealing (what `supersede`
/// selects on) and the audit rows `supersede` keeps.
const DEALER_V1: &str = "
CREATE TABLE dealings(market BLOB NOT NULL, epoch INTEGER NOT NULL, announcement BLOB NOT NULL,
  ann_digest BLOB NOT NULL, committee_digest BLOB NOT NULL, created_at_ms INTEGER NOT NULL, PRIMARY KEY(market, epoch));
CREATE TABLE deliveries(market BLOB NOT NULL, epoch INTEGER NOT NULL, member INTEGER NOT NULL, sealed BLOB NOT NULL,
  PRIMARY KEY(market, epoch, member));
CREATE TABLE acks(market BLOB NOT NULL, epoch INTEGER NOT NULL, member INTEGER NOT NULL, ack BLOB NOT NULL,
  received_at_ms INTEGER NOT NULL, PRIMARY KEY(market, epoch, member));
CREATE TABLE bundles(market BLOB NOT NULL, epoch INTEGER NOT NULL, bundle BLOB NOT NULL,
  state TEXT NOT NULL CHECK(state IN ('intent', 'delivered')), updated_at_ms INTEGER NOT NULL,
  PRIMARY KEY(market, epoch));
CREATE TABLE superseded(id INTEGER PRIMARY KEY, market BLOB NOT NULL, epoch INTEGER NOT NULL,
  committee_digest BLOB NOT NULL, ann_digest BLOB NOT NULL, at_ms INTEGER NOT NULL);
CREATE INDEX superseded_epoch ON superseded(market, epoch);
";
