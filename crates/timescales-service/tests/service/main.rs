#![allow(
    dead_code,
    unused_imports,
    unreachable_pub,
    clippy::unwrap_used,
    clippy::cast_possible_truncation
)]

//! Behaviour of timescales-service: configuration and profiles, key files,
//! the ops router, the signed-envelope extractor, and `SignedClient` over
//! plain HTTP and mutual TLS against real local listeners.

mod client;
mod common;
mod config;
mod envelope;
mod keys;
mod ops;

mod otlp;
mod trait_shapes;
