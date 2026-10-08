//! Implements every async trait of the crate with bodies that hold each
//! argument across an await point, so an unimplementable signature fails to
//! compile here.

#![allow(clippy::unwrap_used)]

use std::sync::Arc;

use timescales_chain::program::MarketAccount;
use timescales_chain::{Address, Level};
use timescales_core::EpochId;
use timescales_executor::tee::ReleaseContext;
use timescales_krc::{BoxFuture, KrcChain, KrcError};
use tokio::task::yield_now;

struct NoMarkets;

impl KrcChain for NoMarkets {
    fn release_context(
        &self,
        m: Address,
        e: EpochId,
    ) -> BoxFuture<'_, Result<ReleaseContext, KrcError>> {
        Box::pin(async move {
            yield_now().await;
            if e.0 == 0 {
                return Err(KrcError::NotFinal);
            }
            Err(KrcError::UnknownMarket(m))
        })
    }

    fn market(&self, m: Address, level: Level) -> BoxFuture<'_, Result<MarketAccount, KrcError>> {
        Box::pin(async move {
            yield_now().await;
            if level == Level::Processed {
                return Err(KrcError::NotFinal);
            }
            Err(KrcError::UnknownMarket(m))
        })
    }
}

#[tokio::test]
async fn krc_chain_is_implementable_and_object_safe() {
    let chain: Arc<dyn KrcChain> = Arc::new(NoMarkets);
    assert!(matches!(
        chain.release_context([1; 32], EpochId(0)).await,
        Err(KrcError::NotFinal)
    ));
    assert!(matches!(
        chain.market([1; 32], Level::Finalized).await,
        Err(KrcError::UnknownMarket(m)) if m == [1; 32]
    ));
}
