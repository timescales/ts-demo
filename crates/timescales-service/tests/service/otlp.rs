//! OTLP span export (feature `otlp`): spans reach a collector through the
//! batch processor, whose export runs on the tokio runtime.
//!
//! A test binary of its own, because it installs the global subscriber.

#![cfg(feature = "otlp")]
#![allow(clippy::unwrap_used)]

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use axum::Router;
use axum::body::Bytes;
use axum::extract::State;
use axum::routing::post;
use timescales_service::{LogFormat, TelemetryConfig, init_telemetry};

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn spans_are_exported_to_the_collector() {
    let received = Arc::new(AtomicUsize::new(0));
    let collector = Router::new()
        .route(
            "/v1/traces",
            post(
                |State(n): State<Arc<AtomicUsize>>, body: Bytes| async move {
                    if !body.is_empty() {
                        n.fetch_add(1, Ordering::SeqCst);
                    }
                },
            ),
        )
        .with_state(Arc::clone(&received));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, collector).await.unwrap() });

    let guard = init_telemetry(
        &TelemetryConfig {
            log_format: LogFormat::Json,
            log_filter: "info".into(),
            otlp_endpoint: format!("http://{addr}/v1/traces"),
            service_name: Some("timescales-test".into()),
        },
        "timescales-test",
    )
    .unwrap();
    {
        let span = tracing::info_span!("epoch", market = "4dbe", epoch = 1u64);
        let _e = span.enter();
        tracing::info!("exported");
    }
    // Dropping the guard flushes the batch.
    tokio::task::spawn_blocking(move || drop(guard))
        .await
        .unwrap();
    assert!(received.load(Ordering::SeqCst) >= 1);
}
