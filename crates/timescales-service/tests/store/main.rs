#![allow(
    dead_code,
    unused_imports,
    unreachable_pub,
    clippy::unwrap_used,
    clippy::cast_possible_truncation
)]

//! Behaviour of the store against real SQLite files in temporary
//! directories: the writer and its fail-stop, migrations, backups, the
//! sealers and every repository method, plus crash tests that SIGKILL a
//! child process.

mod common;
mod core;
mod crash;
mod dealer;
mod errors;
mod member;
mod node;
mod sealer;
