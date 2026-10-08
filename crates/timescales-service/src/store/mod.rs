//! SQLite persistence for the Timescales services.
//!
//! One writer thread per database file applies each write as one
//! transaction, with group commit. Reads use a pool of read-only
//! connections. Migrations are forward only and a copy is taken before each.
//! Any write error moves the store to [`StoreError::Closed`]: the owning
//! service logs, sets `/readyz` false and exits 70 (fail-stop).
//!
//! Typed repositories: [`node::NodeRepo`] (`node.sqlite`),
//! [`member::MemberRepo`] (`member.sqlite` plus `shares.sqlite`, which is
//! never backed up) and [`dealer::DealerRepo`] (`dealer.sqlite`).
//!
//! # Writes, group commit and fail-stop
//!
//! [`Store::write`] queues a closure for the writer thread. The writer opens
//! one `BEGIN IMMEDIATE` transaction for a group of writes (everything that
//! arrives within `group_commit_ms` of the first, at most
//! `group_commit_max`), runs each closure inside its own savepoint and
//! commits once, so one fsync covers the group. A write is acknowledged only
//! after that commit, so an acknowledged write is durable.
//!
//! A closure that returns [`StoreError::Conflict`], [`StoreError::Corrupt`]
//! or another logical refusal has its savepoint rolled back and the group
//! carries on. A closure that fails with [`StoreError::Sqlite`] (or panics),
//! and any failure to commit, is a write error: the writes before it in the
//! group are still committed if SQLite allows, the failing caller gets its
//! error, and every later call gets [`StoreError::Closed`].

#![cfg_attr(test, allow(clippy::unwrap_used, clippy::cast_possible_truncation))]

pub mod dealer;
pub mod member;
pub mod node;
mod schema;
mod sealer;
mod sql;
#[allow(clippy::module_inception)]
mod store;

use std::path::PathBuf;

use thiserror::Error;

pub use sealer::{KekSealer, RatchetSealer, SecretSealer};
pub use store::Store;

pub type Address = [u8; 32];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StoreOptions {
    pub synchronous_full: bool,
    pub group_commit_ms: u64,
    pub group_commit_max: usize,
    pub readers: usize,
    pub busy_timeout_ms: u64,
    pub queue: usize,
    pub secure_delete: bool,
}

impl Default for StoreOptions {
    /// The `[store]` defaults.
    fn default() -> Self {
        StoreOptions {
            synchronous_full: true,
            group_commit_ms: 2,
            group_commit_max: 256,
            readers: 4,
            busy_timeout_ms: 5000,
            queue: 8192,
            secure_delete: false,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Schema {
    Node,
    Member,
    /// `shares.sqlite`: always `secure_delete`, never copied (no backup and
    /// no pre-migration copy).
    MemberShares,
    Dealer,
}

#[derive(Clone, Debug, PartialEq, Eq, Error)]
pub enum StoreError {
    /// SQLite, or a file the store manages, failed. Returned by a write
    /// closure it closes the store.
    #[error("sqlite: {0}")]
    Sqlite(String),
    #[error("corrupt data: {0}")]
    Corrupt(&'static str),
    #[error("database schema {have} is newer than this binary ({max})")]
    FutureSchema { have: u32, max: u32 },
    #[error("store closed after a write error")]
    Closed,
    #[error("conflict: {0}")]
    Conflict(&'static str),
    #[error("write queue full")]
    Full,
}

/// Result of [`Store::backup_to`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BackupReport {
    pub path: PathBuf,
    pub bytes: u64,
    pub stripped: Vec<&'static str>,
    pub integrity_ok: bool,
}

/// Rows removed or rewritten by a prune.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PruneReport {
    pub rows_deleted: u64,
    pub wallets_nulled: u64,
}
