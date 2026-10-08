//! The node engine against the real settlement program in LiteSVM, three
//! in-process simulated enclaves (quorum 2) and a test dealer. Tokio time is
//! paused. The node's `ManualClock` follows it.

#![cfg(all(feature = "litesvm", feature = "test-util"))]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::cast_possible_truncation
)]

use super::support;

#[path = "engine/epoch.rs"]
mod epoch;

#[path = "engine/intake.rs"]
mod intake;

#[path = "engine/sessions.rs"]
mod sessions;

#[path = "engine/recovery.rs"]
mod recovery;

#[path = "engine/faults.rs"]
mod faults;

#[path = "engine/model.rs"]
mod model;

#[path = "engine/logs.rs"]
mod logs;
