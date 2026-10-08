#![allow(
    dead_code,
    unused_imports,
    unreachable_pub,
    clippy::unwrap_used,
    clippy::cast_possible_truncation
)]

mod engine;
#[cfg(all(feature = "litesvm", feature = "test-util"))]
mod support;
mod trait_shapes;
