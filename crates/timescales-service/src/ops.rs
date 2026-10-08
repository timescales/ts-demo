//! The ops listener (`/livez`, `/readyz`, `/metrics`), the metrics
//! registry and graceful shutdown.

use std::sync::Arc;

use axum::Router;
use axum::extract::State;
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use prometheus_client::metrics::family::Family;
use prometheus_client::metrics::gauge::Gauge;
use prometheus_client::registry::Registry;

use crate::{BoxFuture, BuildInfo};

/// Content type of `/metrics` (OpenMetrics text).
pub const OPENMETRICS_CONTENT_TYPE: &str =
    "application/openmetrics-text; version=1.0.0; charset=utf-8";

pub struct Metrics {
    pub registry: prometheus_client::registry::Registry,
}

impl core::fmt::Debug for Metrics {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Metrics").finish_non_exhaustive()
    }
}

impl Metrics {
    /// A registry holding `timescales_build_info{version, git_sha,
    /// simulation, sim_platform, tee_platform} 1`. Services
    /// register their own families in `registry` before sharing it.
    pub fn new(build: &BuildInfo, tee_platform: &str) -> Self {
        let mut registry = Registry::default();
        let info = Family::<Vec<(String, String)>, Gauge>::default();
        info.get_or_create(&vec![
            ("version".to_owned(), build.version.to_owned()),
            ("git_sha".to_owned(), build.git_sha.to_owned()),
            ("simulation".to_owned(), build.simulation.to_string()),
            ("sim_platform".to_owned(), build.sim_platform.to_string()),
            ("tee_platform".to_owned(), tee_platform.to_owned()),
        ])
        .set(1);
        registry.register(
            "timescales_build_info",
            "What this binary was built with; always 1",
            info,
        );
        Self { registry }
    }

    /// The registry in the OpenMetrics text format.
    pub fn encode(&self) -> Result<String, std::fmt::Error> {
        let mut out = String::new();
        prometheus_client::encoding::text::encode(&mut out, &self.registry)?;
        Ok(out)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Readiness {
    pub ready: bool,
    /// Named checks and whether each passed.
    pub checks: Vec<(String, bool)>,
}

pub trait ReadinessProbe: Send + Sync {
    fn ready(&self) -> BoxFuture<'_, Readiness>;
}

#[derive(Clone)]
struct Ops {
    metrics: Arc<Metrics>,
    ready: Arc<dyn ReadinessProbe>,
}

/// `/livez`, `/readyz`, `/metrics`.
///
/// `/livez` answers 200 while the process serves requests. `/readyz`
/// answers 200 or 503 with `{"status": "ready" | "not_ready", "checks":
/// {name: bool}}`. `/metrics` is the registry in OpenMetrics text.
pub fn ops_router(metrics: Arc<Metrics>, ready: Arc<dyn ReadinessProbe>) -> axum::Router {
    Router::new()
        .route("/livez", get(livez))
        .route("/readyz", get(readyz))
        .route("/metrics", get(metrics_text))
        .with_state(Ops { metrics, ready })
}

async fn livez() -> Response {
    axum::Json(serde_json::json!({ "status": "ok" })).into_response()
}

async fn readyz(State(ops): State<Ops>) -> Response {
    let r = ops.ready.ready().await;
    let checks: serde_json::Map<String, serde_json::Value> = r
        .checks
        .into_iter()
        .map(|(name, ok)| (name, serde_json::Value::Bool(ok)))
        .collect();
    let (status, word) = if r.ready {
        (StatusCode::OK, "ready")
    } else {
        (StatusCode::SERVICE_UNAVAILABLE, "not_ready")
    };
    (
        status,
        [(header::CACHE_CONTROL, "no-store")],
        axum::Json(serde_json::json!({ "status": word, "checks": checks })),
    )
        .into_response()
}

async fn metrics_text(State(ops): State<Ops>) -> Response {
    match ops.metrics.encode() {
        Ok(text) => (
            [
                (header::CONTENT_TYPE, OPENMETRICS_CONTENT_TYPE),
                (header::CACHE_CONTROL, "no-store"),
            ],
            text,
        )
            .into_response(),
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}

/// Resolves on SIGTERM or Ctrl-C: the trigger for a graceful shutdown
/// (`axum::serve(..).with_graceful_shutdown(shutdown_signal)`).
pub async fn shutdown_signal() {
    let interrupt = async {
        if let Err(e) = tokio::signal::ctrl_c().await {
            tracing::error!(error = %e, "cannot listen for Ctrl-C");
            std::future::pending::<()>().await;
        }
    };
    #[cfg(unix)]
    let terminate = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut s) => {
                s.recv().await;
            }
            Err(e) => {
                tracing::error!(error = %e, "cannot listen for SIGTERM");
                std::future::pending::<()>().await;
            }
        }
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();
    tokio::select! {
        () = interrupt => tracing::info!("interrupt received; shutting down"),
        () = terminate => tracing::info!("SIGTERM received; shutting down"),
    }
}
