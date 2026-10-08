#![allow(
    dead_code,
    unused_imports,
    unreachable_pub,
    clippy::unwrap_used,
    clippy::cast_possible_truncation
)]

#[cfg(all(feature = "sim-platform", feature = "litesvm", feature = "test-util"))]
mod common;
mod config;
mod enclave;
