#![allow(
    dead_code,
    unused_imports,
    unreachable_pub,
    clippy::unwrap_used,
    clippy::cast_possible_truncation
)]

//! Behaviour of every wire message: codecs (round trip, bounds
//! checked before allocating, trailing bytes, tags and bools), signatures,
//! verification rules and the size limits.

mod announcement;
mod committee;
mod common;
mod decoders;
mod envelope;
mod errors;
mod execute;
mod keys;
mod limits;
mod release;
mod session;
