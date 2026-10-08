//! [`SignedEnvelope`]s over HTTP: the request extractor and signed
//! responses (service to service).

use std::sync::Arc;
use std::time::Duration;

use crate::wire::{
    EnvelopePrefix, EnvelopeSigner, MessageKind, PREFIX_LEN, ReplayGuard, SignedEnvelope, WireError,
};
use axum::body::Body;
use axum::extract::{FromRef, FromRequest, Request};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use futures::StreamExt;
use rand_core::OsRng;
use thiserror::Error;
use timescales_core::Encode;

/// Media type of every envelope body.
pub const ENVELOPE_CONTENT_TYPE: &str = "application/vnd.timescales.envelope";

/// Body and rate limits of a service's HTTP listener.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HttpLimits {
    pub max_body_bytes: usize,
    pub request_timeout: Duration,
    pub max_concurrency: usize,
    pub per_caller_rps: u32,
    pub per_caller_burst: u32,
}

/// A request body that arrived in a valid [`crate::wire::SignedEnvelope`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedEnvelope {
    pub sender: [u8; 32],
    pub kind: MessageKind,
    pub body: Vec<u8>,
}

/// Which senders may send which message kinds.
pub type SenderPolicy = dyn Fn(&[u8; 32], MessageKind) -> bool + Send + Sync;

/// What the [`VerifiedEnvelope`] extractor checks against. Routers expose it
/// through their state.
#[derive(Clone)]
pub struct EnvelopeAuth {
    pub me: [u8; 32],
    pub allowed: Arc<SenderPolicy>,
    pub replay: Arc<ReplayGuard>,
    pub skew_ms: u64,
    pub now_ms: Arc<dyn Fn() -> u64 + Send + Sync>,
}

impl core::fmt::Debug for EnvelopeAuth {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("EnvelopeAuth")
            .field("me", &self.me)
            .field("skew_ms", &self.skew_ms)
            .finish_non_exhaustive()
    }
}

/// Why the extractor refused a request.
#[derive(Debug, Error)]
pub enum EnvelopeRejection {
    #[error("unsupported media type")]
    MediaType,
    #[error("body: {0}")]
    Body(String),
    #[error(transparent)]
    Wire(#[from] WireError),
}

impl EnvelopeRejection {
    /// 415 media type. 400 malformed. 413 over the kind's limit. 403
    /// audience or sender. 401 signature, clock skew or replay. 503 when
    /// the replay guard is full (it fails closed).
    pub fn status(&self) -> StatusCode {
        match self {
            EnvelopeRejection::MediaType => StatusCode::UNSUPPORTED_MEDIA_TYPE,
            EnvelopeRejection::Body(_) => StatusCode::BAD_REQUEST,
            EnvelopeRejection::Wire(e) => match e {
                WireError::TooLarge { .. } => StatusCode::PAYLOAD_TOO_LARGE,
                WireError::Audience | WireError::Sender => StatusCode::FORBIDDEN,
                WireError::BadSignature | WireError::Skew { .. } | WireError::Replay => {
                    StatusCode::UNAUTHORIZED
                }
                WireError::ReplayGuardFull => StatusCode::SERVICE_UNAVAILABLE,
                _ => StatusCode::BAD_REQUEST,
            },
        }
    }
}

impl IntoResponse for EnvelopeRejection {
    fn into_response(self) -> Response {
        let status = self.status();
        let mut response = (status, self.to_string()).into_response();
        if status == StatusCode::SERVICE_UNAVAILABLE {
            response
                .headers_mut()
                .insert(header::RETRY_AFTER, HeaderValue::from_static("1"));
        }
        response
    }
}

/// Reads the 94-byte prefix, checks it (sender, kind, audience, length)
/// **before** reading the body, then verifies the signature and the
/// replay guard.
///
/// Only then is the rest of the body read, and exactly `body_len + 64`
/// bytes of it: a body that is shorter, longer or disagrees with its
/// `Content-Length` is refused. The replay guard records a (sender, nonce)
/// only once the signature verified, so unsigned traffic cannot fill it.
impl<S> FromRequest<S> for VerifiedEnvelope
where
    S: Send + Sync,
    EnvelopeAuth: FromRef<S>,
{
    type Rejection = EnvelopeRejection;

    async fn from_request(req: Request, state: &S) -> Result<Self, Self::Rejection> {
        let auth = EnvelopeAuth::from_ref(state);
        check_media_type(req.headers())?;
        let declared = content_length(req.headers())?;
        if declared.is_some_and(|len| len < SignedEnvelope::MIN_ENCODED_LEN) {
            return Err(EnvelopeRejection::Body(
                "shorter than an envelope".to_owned(),
            ));
        }
        let mut body = Body::into_data_stream(req.into_body());

        let mut prefix = [0u8; PREFIX_LEN];
        let mut filled = 0;
        let mut rest = Vec::new();
        while filled < PREFIX_LEN {
            let chunk = next_chunk(&mut body).await?;
            let take = chunk.len().min(PREFIX_LEN - filled);
            prefix[filled..filled + take].copy_from_slice(&chunk[..take]);
            filled += take;
            if take < chunk.len() {
                // Bytes past the prefix are kept, not looked at, until the
                // prefix passed.
                rest.push(chunk.slice(take..));
            }
        }
        let p = EnvelopePrefix::check(&prefix, &auth.me, &*auth.allowed)?;

        let need = usize::try_from(p.body_len)
            .map_err(|_| EnvelopeRejection::Body("body length".to_owned()))?
            + 64;
        if declared.is_some_and(|len| len != PREFIX_LEN + need) {
            return Err(EnvelopeRejection::Body(
                "content length does not match the envelope".to_owned(),
            ));
        }
        let mut tail = Vec::with_capacity(need);
        for chunk in rest {
            push_bounded(&mut tail, &chunk, need)?;
        }
        while tail.len() < need {
            let chunk = next_chunk(&mut body).await?;
            push_bounded(&mut tail, &chunk, need)?;
        }
        // Anything after the signature is refused, not ignored.
        while let Some(chunk) = body.next().await {
            let chunk = chunk.map_err(|e| EnvelopeRejection::Body(e.to_string()))?;
            if !chunk.is_empty() {
                return Err(EnvelopeRejection::Body("trailing bytes".to_owned()));
            }
        }

        let env = SignedEnvelope::from_prefix(&p, &tail)?;
        let now = (auth.now_ms)();
        env.open(&auth.me, &*auth.allowed, now, auth.skew_ms)?;
        auth.replay
            .check_and_insert(&env.sender, &env.nonce, env.issued_at_ms, now)?;
        Ok(VerifiedEnvelope {
            sender: env.sender,
            kind: env.kind,
            body: env.body,
        })
    }
}

fn check_media_type(headers: &HeaderMap) -> Result<(), EnvelopeRejection> {
    let ok = headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.split(';').next())
        .is_some_and(|v| v.trim().eq_ignore_ascii_case(ENVELOPE_CONTENT_TYPE));
    if ok {
        Ok(())
    } else {
        Err(EnvelopeRejection::MediaType)
    }
}

fn content_length(headers: &HeaderMap) -> Result<Option<usize>, EnvelopeRejection> {
    headers
        .get(header::CONTENT_LENGTH)
        .map(|v| {
            v.to_str()
                .ok()
                .and_then(|s| s.parse::<usize>().ok())
                .ok_or_else(|| EnvelopeRejection::Body("invalid content length".to_owned()))
        })
        .transpose()
}

async fn next_chunk(
    body: &mut axum::body::BodyDataStream,
) -> Result<axum::body::Bytes, EnvelopeRejection> {
    match body.next().await {
        Some(Ok(chunk)) => Ok(chunk),
        Some(Err(e)) => Err(EnvelopeRejection::Body(e.to_string())),
        None => Err(EnvelopeRejection::Body("truncated envelope".to_owned())),
    }
}

fn push_bounded(tail: &mut Vec<u8>, chunk: &[u8], need: usize) -> Result<(), EnvelopeRejection> {
    if tail.len() + chunk.len() > need {
        return Err(EnvelopeRejection::Body("trailing bytes".to_owned()));
    }
    tail.extend_from_slice(chunk);
    Ok(())
}

/// A response carrying `body` in an envelope of `kind` signed by
/// `signer` and addressed to `audience` (the requester).
pub fn sealed_response(
    kind: MessageKind,
    signer: &dyn EnvelopeSigner,
    audience: [u8; 32],
    now_ms: u64,
    body: Vec<u8>,
) -> Response {
    sealed_response_with_status(StatusCode::OK, kind, signer, audience, now_ms, body)
}

/// [`sealed_response`] with another status, for refusals that carry signed
/// evidence.
pub fn sealed_response_with_status(
    status: StatusCode,
    kind: MessageKind,
    signer: &dyn EnvelopeSigner,
    audience: [u8; 32],
    now_ms: u64,
    body: Vec<u8>,
) -> Response {
    let env = SignedEnvelope::seal(kind, signer, audience, now_ms, &mut OsRng, body);
    (
        status,
        [(header::CONTENT_TYPE, ENVELOPE_CONTENT_TYPE)],
        env.to_bytes(),
    )
        .into_response()
}
