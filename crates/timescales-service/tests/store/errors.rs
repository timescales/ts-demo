//! Values the store cannot hold are refused before SQLite sees them, and
//! rows that do not decode read back as `Corrupt`, never as wrong values.

use timescales_service::store::StoreError;
use timescales_service::store::node::{EpochPatch, Phase};

use crate::common::{MARKET, node, outside, submission};

#[tokio::test]
async fn integers_beyond_the_store_range_are_refused() {
    let f = node();
    let out_of_range = Err(StoreError::Conflict("integer exceeds the store's range"));
    assert_eq!(
        f.repo
            .put_key_bundle(MARKET, u64::MAX, vec![1], 1)
            .await
            .map(|_| ()),
        out_of_range
    );
    assert_eq!(
        f.repo.use_nonce([1; 16], u64::MAX).await.map(|_| ()),
        out_of_range
    );
    let mut s = submission(1, 1, 1);
    s.received_at_ms = u64::MAX;
    assert_eq!(f.repo.insert_submission(s).await.map(|_| ()), out_of_range);
    // A refusal, not a write error.
    assert!(f.repo.meta("k").await.is_ok());
    // Reads take any u64 as a bound.
    assert_eq!(f.repo.epoch(MARKET, u64::MAX).await.unwrap(), None);
    assert!(
        f.repo
            .submissions(MARKET, u64::MAX)
            .await
            .unwrap()
            .is_empty()
    );
}

#[tokio::test]
async fn corrupt_rows_read_as_corrupt() {
    let f = node();
    f.repo.put_key_bundle(MARKET, 1, vec![1], 1).await.unwrap();
    f.repo.put_key_bundle(MARKET, 2, vec![2], 1).await.unwrap();
    f.repo.put_key_bundle(MARKET, 3, vec![3], 1).await.unwrap();
    let conn = outside(&f.db());
    conn.execute("UPDATE epochs SET phase = 99 WHERE epoch = 1", [])
        .unwrap();
    conn.execute("UPDATE epochs SET root = x'0102' WHERE epoch = 2", [])
        .unwrap();
    conn.execute("UPDATE epochs SET updated_at_ms = -5 WHERE epoch = 3", [])
        .unwrap();
    drop(conn);

    assert_eq!(
        f.repo.epoch(MARKET, 1).await,
        Err(StoreError::Corrupt("unknown epoch phase"))
    );
    assert_eq!(
        f.repo.epoch(MARKET, 2).await,
        Err(StoreError::Corrupt("blob column has the wrong length"))
    );
    assert_eq!(
        f.repo.epoch(MARKET, 3).await,
        Err(StoreError::Corrupt("negative integer column"))
    );
    // A write that meets a corrupt row is refused. The store stays open.
    assert_eq!(
        f.repo
            .advance(MARKET, 1, Phase::Open, EpochPatch::default())
            .await,
        Err(StoreError::Corrupt("unknown epoch phase"))
    );
    assert!(f.repo.meta("k").await.is_ok());
}
