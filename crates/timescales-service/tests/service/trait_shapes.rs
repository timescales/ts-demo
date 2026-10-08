//! Implements every async trait of the crate with a body that awaits, so an
//! unimplementable signature fails to compile here.

#![allow(clippy::unwrap_used)]

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use timescales_service::{BoxFuture, Readiness, ReadinessProbe};
use tokio::task::yield_now;

struct Flag(AtomicBool);

impl ReadinessProbe for Flag {
    fn ready(&self) -> BoxFuture<'_, Readiness> {
        Box::pin(async move {
            yield_now().await;
            let ok = self.0.load(Ordering::SeqCst);
            Readiness {
                ready: ok,
                checks: vec![("store".into(), ok)],
            }
        })
    }
}

#[tokio::test]
async fn readiness_probe_is_object_safe() {
    let probe: Arc<dyn ReadinessProbe> = Arc::new(Flag(AtomicBool::new(true)));
    let r = probe.ready().await;
    assert!(r.ready);
    assert_eq!(r.checks, vec![("store".to_string(), true)]);
}
