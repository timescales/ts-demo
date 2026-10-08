//! Builders and file helpers shared by the store tests.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use rusqlite::Connection;
use tempfile::TempDir;
use timescales_core::crypto::Signature;
use timescales_core::{Encode, EpochId, Hash32, OrderCommitment, PriceBand, Tick};
use timescales_service::store::dealer::DealerRepo;
use timescales_service::store::member::MemberRepo;
use timescales_service::store::node::{EpochRow, NodeRepo, Phase, SessionRow, SubmissionRow};
use timescales_service::store::{RatchetSealer, Schema, SecretSealer, Store, StoreOptions};
use timescales_service::wire::{EpochKeyAck, EpochKeyAnnouncement, GrantMethod, KeyScheme};
use zeroize::Zeroizing;

pub(crate) const MARKET: [u8; 32] = [0x4d; 32];
pub(crate) const OTHER_MARKET: [u8; 32] = [0x6f; 32];
/// This member's index in the committee (part of the share AAD).
pub(crate) const MEMBER_INDEX: u8 = 2;

pub(crate) fn opts() -> StoreOptions {
    StoreOptions {
        group_commit_ms: 1,
        readers: 2,
        ..StoreOptions::default()
    }
}

pub(crate) fn open(dir: &Path, name: &str, schema: Schema) -> Store {
    Store::open(&dir.join(name), schema, opts()).unwrap()
}

pub(crate) struct NodeFixture {
    pub(crate) dir: TempDir,
    pub(crate) repo: NodeRepo,
}

impl NodeFixture {
    pub(crate) fn db(&self) -> PathBuf {
        self.dir.path().join("node.sqlite")
    }
}

pub(crate) fn node() -> NodeFixture {
    let dir = tempfile::tempdir().unwrap();
    let repo = NodeRepo::new(open(dir.path(), "node.sqlite", Schema::Node));
    NodeFixture { dir, repo }
}

pub(crate) struct MemberFixture {
    pub(crate) dir: TempDir,
    pub(crate) repo: MemberRepo,
    pub(crate) sealer: Arc<RatchetSealer>,
}

impl MemberFixture {
    pub(crate) fn member_db(&self) -> PathBuf {
        self.dir.path().join("member.sqlite")
    }

    pub(crate) fn shares_db(&self) -> PathBuf {
        self.dir.path().join("shares").join("shares.sqlite")
    }

    pub(crate) fn key_file(&self) -> PathBuf {
        self.dir.path().join("kek.keys")
    }

    /// A share for epoch `e`, sealed at rest the way a member seals it.
    pub(crate) fn seal_share(&self, e: u64, marker: u8) -> Vec<u8> {
        self.sealer.seal(&share_aad(e), &[marker; 33]).unwrap()
    }
}

/// `market || epoch || index`.
pub(crate) fn share_aad(e: u64) -> Vec<u8> {
    let mut aad = MARKET.to_vec();
    aad.extend_from_slice(&e.to_le_bytes());
    aad.push(MEMBER_INDEX);
    aad
}

pub(crate) const KEK_0: [u8; 32] = [0x17; 32];

pub(crate) fn member() -> MemberFixture {
    let dir = tempfile::tempdir().unwrap();
    let shares_dir = dir.path().join("shares");
    std::fs::create_dir(&shares_dir).unwrap();
    let sealer = Arc::new(
        RatchetSealer::create(&dir.path().join("kek.keys"), 0, Zeroizing::new(KEK_0)).unwrap(),
    );
    let repo = MemberRepo::new(
        open(dir.path(), "member.sqlite", Schema::Member),
        open(&shares_dir, "shares.sqlite", Schema::MemberShares),
        Arc::clone(&sealer),
    );
    MemberFixture { dir, repo, sealer }
}

pub(crate) struct DealerFixture {
    pub(crate) dir: TempDir,
    pub(crate) repo: DealerRepo,
}

impl DealerFixture {
    pub(crate) fn db(&self) -> PathBuf {
        self.dir.path().join("dealer.sqlite")
    }
}

pub(crate) fn dealer() -> DealerFixture {
    let dir = tempfile::tempdir().unwrap();
    let repo = DealerRepo::new(open(dir.path(), "dealer.sqlite", Schema::Dealer));
    DealerFixture { dir, repo }
}

/// A row with only the required columns set.
pub(crate) fn bare_row(e: u64, phase: Phase) -> EpochRow {
    EpochRow {
        market: MARKET,
        epoch: e,
        phase,
        opens_at_ms: None,
        cutoff_ms: None,
        reference: None,
        band: None,
        price_commitment: None,
        committee_digest: None,
        binding: None,
        terms_digest: None,
        announcement: None,
        root: None,
        envelope_count: None,
        real_count: None,
        cover_count: None,
        commit_sig: None,
        commit_slot: None,
        snapshot_slot: None,
        snapshot_late: false,
        beacon: None,
        reveal_slot: None,
        header: None,
        receipt: None,
        receipt_slot: None,
        artifacts_public: false,
        abort_reason: None,
        abort_detail: None,
        terminal_slot: None,
        updated_at_ms: 1_000,
    }
}

/// The row of an epoch that opens now (phase 2).
pub(crate) fn open_row(e: u64) -> EpochRow {
    EpochRow {
        opens_at_ms: Some(e * 10_000),
        cutoff_ms: Some(e * 10_000 + 10_000),
        reference: Some(10_000),
        band: Some(PriceBand {
            lo: Tick(9_990),
            hi: Tick(10_010),
            reference: Tick(10_000),
        }),
        price_commitment: Some(Hash32([1; 32])),
        committee_digest: Some(Hash32([2; 32])),
        binding: Some(Hash32([3; 32])),
        terms_digest: Some(Hash32([4; 32])),
        announcement: Some(vec![5; 273]),
        updated_at_ms: e * 10_000,
        ..bare_row(e, Phase::Open)
    }
}

pub(crate) fn session_pk(wallet: u8) -> [u8; 32] {
    [wallet ^ 0x5a; 32]
}

/// Wallet `wallet`'s submission of commitment `c` to epoch `e`.
pub(crate) fn submission(e: u64, c: u8, wallet: u8) -> SubmissionRow {
    SubmissionRow {
        market: MARKET,
        epoch: e,
        commitment: OrderCommitment([c; 32]),
        envelope_digest: Hash32([c ^ 0xff; 32]),
        wallet: Some([wallet; 32]),
        session_pk: Some(session_pk(wallet)),
        submission: vec![c; 386],
        promise: vec![c.wrapping_add(wallet); 201],
        received_at_ms: 1_000 + e,
    }
}

pub(crate) fn session(wallet: u8, key: u8, issued_at_ms: u64) -> SessionRow {
    SessionRow {
        session_pk: [key; 32],
        wallet: [wallet; 32],
        market: Some(MARKET),
        grant_text: format!("grant {key} for wallet {wallet}"),
        signature: [key; 64],
        method: GrantMethod::SignIn,
        nonce: [key; 16],
        issued_at_ms: Some(issued_at_ms),
        expires_at_ms: Some(issued_at_ms + 86_400_000),
        revoked: false,
        keep_until_epoch: None,
    }
}

/// An encoded epoch-key announcement for (market, e) under committee
/// `[committee; 32]`, and its digest. `key` varies the epoch key.
pub(crate) fn announcement(market: [u8; 32], e: u64, committee: u8, key: u8) -> (Vec<u8>, Hash32) {
    let ann = EpochKeyAnnouncement {
        version: EpochKeyAnnouncement::VERSION,
        market,
        epoch: EpochId(e),
        committee_digest: Hash32([committee; 32]),
        scheme: KeyScheme::DevX25519,
        epoch_pk: [key; 32],
        commitments: Vec::new(),
    };
    (ann.to_bytes(), ann.digest())
}

pub(crate) fn ack(member: u8, policy: u8) -> Vec<u8> {
    EpochKeyAck {
        member,
        policy_digest: Hash32([policy; 32]),
        signature: Signature([member ^ policy; 64]),
    }
    .to_bytes()
}

/// Whether `needle` occurs anywhere in the file (a missing file holds
/// nothing).
pub(crate) fn file_contains(path: &Path, needle: &[u8]) -> bool {
    match std::fs::read(path) {
        Ok(bytes) => bytes.windows(needle.len()).any(|w| w == needle),
        Err(_) => false,
    }
}

/// The database file and its WAL.
pub(crate) fn db_files(path: &Path) -> [PathBuf; 2] {
    let mut wal = path.as_os_str().to_owned();
    wal.push("-wal");
    [path.to_path_buf(), PathBuf::from(wal)]
}

pub(crate) fn wal_len(path: &Path) -> u64 {
    std::fs::metadata(&db_files(path)[1])
        .map(|m| m.len())
        .unwrap_or(0)
}

pub(crate) fn tables(path: &Path) -> Vec<String> {
    let conn = Connection::open(path).unwrap();
    let mut st = conn
        .prepare("SELECT name FROM sqlite_master WHERE type = 'table' ORDER BY name")
        .unwrap();
    st.query_map([], |r| r.get(0))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap()
}

/// A connection of its own, as another process would open the file.
pub(crate) fn outside(path: &Path) -> Connection {
    let conn = Connection::open(path).unwrap();
    conn.busy_timeout(std::time::Duration::from_secs(5))
        .unwrap();
    conn
}
