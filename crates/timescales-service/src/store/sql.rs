//! Conversions between Rust values and SQLite columns, and small query
//! helpers.
//!
//! SQLite integers are `i64`. Protocol `u64`s (epochs, slots, milliseconds)
//! are stored as is. A value that does not fit is refused before the
//! database is touched, and a stored negative value reads back as corrupt.

use std::time::{SystemTime, UNIX_EPOCH};

use rusqlite::{Connection, Params, Row};
use timescales_core::Hash32;

use crate::store::StoreError;

impl From<rusqlite::Error> for StoreError {
    fn from(e: rusqlite::Error) -> Self {
        StoreError::Sqlite(e.to_string())
    }
}

/// A `u64` as a column value.
pub(crate) fn int(v: u64) -> Result<i64, StoreError> {
    i64::try_from(v).map_err(|_| StoreError::Conflict("integer exceeds the store's range"))
}

pub(crate) fn opt_int(v: Option<u64>) -> Result<Option<i64>, StoreError> {
    v.map(int).transpose()
}

/// A `u64` used only as a query bound: values beyond the store's range act
/// like the largest one, which no stored value exceeds.
pub(crate) fn bound(v: u64) -> i64 {
    i64::try_from(v).unwrap_or(i64::MAX)
}

/// A row count as `u64`.
pub(crate) fn count(n: usize) -> u64 {
    u64::try_from(n).unwrap_or(u64::MAX)
}

/// A column value that must be a `u64`.
pub(crate) fn uint(v: i64) -> Result<u64, StoreError> {
    u64::try_from(v).map_err(|_| StoreError::Corrupt("negative integer column"))
}

pub(crate) fn opt_uint(v: Option<i64>) -> Result<Option<u64>, StoreError> {
    v.map(uint).transpose()
}

pub(crate) fn uint32(v: i64) -> Result<u32, StoreError> {
    u32::try_from(v).map_err(|_| StoreError::Corrupt("integer column out of range"))
}

pub(crate) fn opt_uint32(v: Option<i64>) -> Result<Option<u32>, StoreError> {
    v.map(uint32).transpose()
}

pub(crate) fn uint8(v: i64) -> Result<u8, StoreError> {
    u8::try_from(v).map_err(|_| StoreError::Corrupt("integer column out of range"))
}

pub(crate) fn opt_uint8(v: Option<i64>) -> Result<Option<u8>, StoreError> {
    v.map(uint8).transpose()
}

pub(crate) fn arr<const N: usize>(v: Vec<u8>) -> Result<[u8; N], StoreError> {
    <[u8; N]>::try_from(v).map_err(|_| StoreError::Corrupt("blob column has the wrong length"))
}

pub(crate) fn opt_arr<const N: usize>(v: Option<Vec<u8>>) -> Result<Option<[u8; N]>, StoreError> {
    v.map(arr).transpose()
}

pub(crate) fn hash(v: Vec<u8>) -> Result<Hash32, StoreError> {
    arr(v).map(Hash32)
}

pub(crate) fn opt_hash(v: Option<Vec<u8>>) -> Result<Option<Hash32>, StoreError> {
    v.map(hash).transpose()
}

/// A boolean column, stored as 0 or 1.
pub(crate) fn flag(v: i64) -> Result<bool, StoreError> {
    match v {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err(StoreError::Corrupt("boolean column is neither 0 nor 1")),
    }
}

/// Runs `sql` through the connection's statement cache. The writer repeats
/// the same few dozen statements for the life of the process, so preparing
/// each one once is the difference that matters on its single thread.
pub(crate) fn exec<P: Params>(
    conn: &Connection,
    sql: &str,
    params: P,
) -> Result<usize, StoreError> {
    Ok(conn.prepare_cached(sql)?.execute(params)?)
}

/// Every row `sql` returns, converted by `f`.
pub(crate) fn rows<T, P: Params>(
    conn: &Connection,
    sql: &str,
    params: P,
    f: impl Fn(&Row<'_>) -> Result<T, StoreError>,
) -> Result<Vec<T>, StoreError> {
    let mut stmt = conn.prepare_cached(sql)?;
    let mut rows = stmt.query(params)?;
    let mut out = Vec::new();
    while let Some(row) = rows.next()? {
        out.push(f(row)?);
    }
    Ok(out)
}

/// The first row `sql` returns, if any, converted by `f`.
pub(crate) fn row<T, P: Params>(
    conn: &Connection,
    sql: &str,
    params: P,
    f: impl FnOnce(&Row<'_>) -> Result<T, StoreError>,
) -> Result<Option<T>, StoreError> {
    let mut stmt = conn.prepare_cached(sql)?;
    let mut rows = stmt.query(params)?;
    match rows.next()? {
        Some(row) => f(row).map(Some),
        None => Ok(None),
    }
}

/// Milliseconds since the Unix epoch, for the few rows whose methods take
/// no timestamp from the caller.
pub(crate) fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
        .unwrap_or(0)
}

/// Numbered placeholders `?first, ?first+1,...` for an `IN (...)` list of `n`
/// values. Numbered, because a bare `?` after `?1` would reuse a number
/// that appears later in the statement.
pub(crate) fn placeholders(first: usize, n: usize) -> String {
    (first..first + n)
        .map(|i| format!("?{i}"))
        .collect::<Vec<_>>()
        .join(", ")
}
