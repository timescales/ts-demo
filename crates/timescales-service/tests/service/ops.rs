//! `/livez`, `/readyz` and `/metrics`.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use prometheus_client::metrics::counter::Counter;
use timescales_service::{
    BoxFuture, BuildInfo, Metrics, OPENMETRICS_CONTENT_TYPE, Readiness, ReadinessProbe, ops_router,
};
use tower::ServiceExt;

struct Probe(AtomicBool);

impl ReadinessProbe for Probe {
    fn ready(&self) -> BoxFuture<'_, Readiness> {
        Box::pin(async move {
            let store = self.0.load(Ordering::SeqCst);
            Readiness {
                ready: store,
                checks: vec![("store".into(), store), ("chain".into(), true)],
            }
        })
    }
}

const BUILD: BuildInfo = BuildInfo {
    version: "0.1.0",
    git_sha: "0123abc",
    simulation: true,
    sim_platform: false,
};

async fn get(router: &axum::Router, path: &str) -> (StatusCode, Option<String>, String) {
    let response = router
        .clone()
        .oneshot(Request::get(path).body(Body::empty()).unwrap())
        .await
        .unwrap();
    let status = response.status();
    let content_type = response
        .headers()
        .get(header::CONTENT_TYPE)
        .map(|v| v.to_str().unwrap().to_owned());
    let body = axum::body::to_bytes(response.into_body(), 1 << 20)
        .await
        .unwrap();
    (
        status,
        content_type,
        String::from_utf8(body.to_vec()).unwrap(),
    )
}

#[tokio::test]
async fn livez_readyz_and_metrics() {
    let mut metrics = Metrics::new(&BUILD, "simulated");
    let served = Counter::<u64>::default();
    metrics.registry.register(
        "timescales_test_requests",
        "Requests served by the test",
        served.clone(),
    );
    served.inc_by(3);
    let probe = Arc::new(Probe(AtomicBool::new(true)));
    let router = ops_router(Arc::new(metrics), probe.clone());

    let (status, _, body) = get(&router, "/livez").await;
    assert_eq!(
        (status, body.as_str()),
        (StatusCode::OK, r#"{"status":"ok"}"#)
    );

    let (status, _, body) = get(&router, "/readyz").await;
    assert_eq!(status, StatusCode::OK);
    let json: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(
        json,
        serde_json::json!({"status": "ready", "checks": {"store": true, "chain": true}})
    );

    // A store that failed (fail-stop) makes the service unready.
    probe.0.store(false, Ordering::SeqCst);
    let (status, _, body) = get(&router, "/readyz").await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    let json: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(json["status"], "not_ready");
    assert_eq!(json["checks"]["store"], false);

    let (status, content_type, body) = get(&router, "/metrics").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(content_type.as_deref(), Some(OPENMETRICS_CONTENT_TYPE));
    assert!(
        body.contains("# TYPE timescales_build_info gauge"),
        "{body}"
    );
    assert!(
        body.contains(
            r#"timescales_build_info{version="0.1.0",git_sha="0123abc",simulation="true",sim_platform="false",tee_platform="simulated"} 1"#
        ),
        "{body}"
    );
    assert!(body.contains("timescales_test_requests_total 3"), "{body}");
    assert!(body.ends_with("# EOF\n"), "{body}");

    let (status, _, _) = get(&router, "/nothing").await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}
