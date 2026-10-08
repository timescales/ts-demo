//! Implements the crate's async trait with bodies that hold each argument
//! across an await point, so an unimplementable signature fails to compile
//! here.

#![allow(clippy::unwrap_used)]

use std::sync::Arc;

use parking_lot::Mutex;
use timescales_auction::BatchHeader;
use timescales_core::{
    CommitmentScheme, EpochId, ExecutorId, FlowMode, Hash32, MarketId, PriceBand, Tick,
};
use timescales_executor::attestation::{Evidence, ExecutorAttestationV2, Platform};
use timescales_executor::tee::{
    BoxFuture, KeyReleaseRequest, KeyReleaseService, ReleaseError, SealedShare,
};
use timescales_executor::workload::default_params;
use tokio::task::yield_now;

/// A member that issues counter nonces and refuses every release.
struct Refusing {
    index: u8,
    issued: Mutex<Vec<(MarketId, EpochId)>>,
}

impl KeyReleaseService for Refusing {
    fn index(&self) -> u8 {
        self.index
    }

    fn challenge(
        &self,
        market: MarketId,
        epoch: EpochId,
    ) -> BoxFuture<'_, Result<Hash32, ReleaseError>> {
        Box::pin(async move {
            yield_now().await;
            let mut issued = self.issued.lock();
            issued.push((market, epoch));
            Ok(Hash32([u8::try_from(issued.len()).unwrap(); 32]))
        })
    }

    fn release(&self, req: KeyReleaseRequest) -> BoxFuture<'_, Result<SealedShare, ReleaseError>> {
        Box::pin(async move {
            yield_now().await;
            let issued = self
                .issued
                .lock()
                .contains(&(req.header.market, req.header.epoch));
            if !issued || req.attestation.nonces.is_empty() {
                return Err(ReleaseError::BadNonce);
            }
            Err(ReleaseError::NoShare)
        })
    }
}

fn header() -> BatchHeader {
    let params = default_params(FlowMode::DualFlow, CommitmentScheme::Sha256);
    BatchHeader::assemble(
        params,
        EpochId(1),
        PriceBand {
            lo: Tick(90),
            hi: Tick(110),
            reference: Tick(100),
        },
        Hash32::ZERO,
        &[],
        Hash32::ZERO,
        Hash32::ZERO,
        Hash32::ZERO,
        Hash32::ZERO,
    )
}

#[tokio::test]
async fn key_release_service_is_implementable_and_object_safe() {
    let m: Arc<dyn KeyReleaseService> = Arc::new(Refusing {
        index: 1,
        issued: Mutex::default(),
    });
    let h = header();
    let nonce = m.challenge(h.market, h.epoch).await.unwrap();
    let req = KeyReleaseRequest {
        header: h,
        price_commitment: Hash32::ZERO,
        attestation: ExecutorAttestationV2 {
            executor: ExecutorId([1; 32]),
            seal_key: [2; 32],
            header_digest: h.digest(),
            nonces: vec![nonce],
            committee_digest: Hash32::ZERO,
            evidence: Evidence {
                platform: Platform::Simulated,
                quote: vec![],
            },
        },
    };
    assert_eq!(m.index(), 1);
    assert_eq!(m.release(req).await, Err(ReleaseError::NoShare));
}
