//! `PUT /internal/v1/markets/{m}/epochs/{e}/key`: the dealer's
//! `KeyBundlePut` in a `SignedEnvelope` from one of `dealer_keys`, checked
//! prefix first and against the replay guard. The answer is an
//! empty envelope signed by the node's service key. `POST` is accepted on
//! the same path because `SignedClient` sends every call as a POST.

use std::sync::Arc;

use axum::Router;
use axum::extract::{FromRef, Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::put;
use timescales_core::Decode;
use timescales_service::wire::{EnvelopeSigner, EpochKeyBundle, MessageKind, ReplayGuard};
use timescales_service::{EnvelopeAuth, EnvelopeRejection, VerifiedEnvelope, sealed_response};

use super::reads::{parse_epoch, parse_market};
use crate::config::AdminConfig;
use crate::{Clock, NodeApi, NodeError};

/// Envelopes remembered against replay.
const REPLAY_CAPACITY: usize = 100_000;

#[derive(Clone)]
struct Internal {
    node: Arc<dyn NodeApi>,
    auth: EnvelopeAuth,
    signer: Arc<dyn EnvelopeSigner>,
    clock: Arc<dyn Clock>,
}

impl FromRef<Internal> for EnvelopeAuth {
    fn from_ref(s: &Internal) -> EnvelopeAuth {
        s.auth.clone()
    }
}

fn dealer_keys(cfg: &AdminConfig) -> Vec<[u8; 32]> {
    cfg.dealer_keys
        .iter()
        .filter_map(|k| {
            let key = hex::decode(k)
                .ok()
                .and_then(|b| <[u8; 32]>::try_from(b.as_slice()).ok());
            if key.is_none() {
                tracing::error!(key = %k, "ignoring a dealer key that is not 32 bytes of hex");
            }
            key
        })
        .collect()
}

fn plain(status: StatusCode, detail: impl Into<String>) -> Response {
    (status, detail.into()).into_response()
}

async fn put_key(
    State(st): State<Internal>,
    Path((market, epoch)): Path<(String, String)>,
    env: Result<VerifiedEnvelope, EnvelopeRejection>,
) -> Response {
    let env = match env {
        Ok(env) => env,
        Err(e) => return e.into_response(),
    };
    let (m, e) = match (parse_market(&market), parse_epoch(&epoch)) {
        (Ok(m), Ok(e)) => (m, e),
        (Err(err), _) | (_, Err(err)) => return plain(StatusCode::BAD_REQUEST, err.detail.clone()),
    };
    let bundle = match EpochKeyBundle::decode_exact(&env.body) {
        Ok(b) => b,
        Err(err) => return plain(StatusCode::BAD_REQUEST, format!("bundle: {err}")),
    };
    let a = &bundle.announcement;
    if a.market != m || a.epoch.0 != e {
        return plain(
            StatusCode::BAD_REQUEST,
            "the bundle's market and epoch are not the path's",
        );
    }
    match st.node.put_key_bundle(m, bundle).await {
        Ok(()) => sealed_response(
            MessageKind::Empty,
            &*st.signer,
            env.sender,
            st.clock.now_ms(),
            Vec::new(),
        ),
        Err(NodeError::MarketUnknown(_)) => plain(StatusCode::NOT_FOUND, "no such market"),
        Err(NodeError::Api { code, detail }) => plain(
            StatusCode::from_u16(code.http_status()).unwrap_or(StatusCode::BAD_REQUEST),
            format!("{code}: {detail}"),
        ),
        Err(NodeError::ShuttingDown) => plain(StatusCode::SERVICE_UNAVAILABLE, "shutting down"),
        Err(other) => {
            tracing::error!(error = %other, "key bundle not stored");
            plain(StatusCode::INTERNAL_SERVER_ERROR, "internal error")
        }
    }
}

async fn unavailable() -> Response {
    plain(
        StatusCode::SERVICE_UNAVAILABLE,
        "internal routes need the node's service key",
    )
}

pub(super) fn router(
    node: Arc<dyn NodeApi>,
    cfg: &AdminConfig,
    service: Option<Arc<dyn EnvelopeSigner>>,
    clock: Arc<dyn Clock>,
    skew_ms: u64,
) -> Router {
    const PATH: &str = "/internal/v1/markets/{market}/epochs/{epoch}/key";
    let Some(signer) = service else {
        return Router::new().route(PATH, put(unavailable).post(unavailable));
    };
    let dealers = dealer_keys(cfg);
    let now = clock.clone();
    let auth = EnvelopeAuth {
        me: signer.public(),
        allowed: Arc::new(move |sender: &[u8; 32], kind: MessageKind| {
            kind == MessageKind::KeyBundlePut && dealers.contains(sender)
        }),
        replay: Arc::new(ReplayGuard::new(REPLAY_CAPACITY, 2 * skew_ms)),
        skew_ms,
        now_ms: Arc::new(move || now.now_ms()),
    };
    Router::new()
        .route(PATH, put(put_key).post(put_key))
        .with_state(Internal {
            node,
            auth,
            signer,
            clock,
        })
}
