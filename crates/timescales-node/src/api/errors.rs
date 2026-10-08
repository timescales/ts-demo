//! Problem documents: every refusal of the public listener is an
//! `application/problem+json` body built from an [`ErrorCode`].
//!
//! Handlers return [`ApiError`]. Its response carries the problem in an
//! extension. The outer middleware ([`super::limits::frame`]) fills in the
//! request id and writes the body, so every problem names the request it
//! answers whichever layer produced it.

use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use serde_json::Value;
use timescales_service::api::{
    B58, BadRequestDetails, ErrorCode, Problem, ProblemDetails, RateLimitScope, RateLimitedDetails,
};
use timescales_service::store::StoreError;

use crate::{NodeError, SessionError};

/// Media type of every problem body.
pub(crate) const PROBLEM_CONTENT_TYPE: &str = "application/problem+json";

/// A refusal on its way to becoming a [`Problem`]. Boxed, because
/// handlers return it on every path.
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct ApiError(Box<ApiErrorParts>);

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct ApiErrorParts {
    pub(crate) code: ErrorCode,
    pub(crate) detail: String,
    pub(crate) details: Option<Value>,
    pub(crate) market: Option<[u8; 32]>,
    pub(crate) epoch: Option<u64>,
    pub(crate) retry_after_ms: Option<u64>,
    /// Extra response headers, for example the rate-limit state.
    pub(crate) headers: Vec<(&'static str, String)>,
}

/// The problem a response stands for, before the request id is known.
#[derive(Clone, Debug)]
pub(crate) struct PendingProblem(pub(crate) Problem);

impl std::ops::Deref for ApiError {
    type Target = ApiErrorParts;

    fn deref(&self) -> &ApiErrorParts {
        &self.0
    }
}

impl std::ops::DerefMut for ApiError {
    fn deref_mut(&mut self) -> &mut ApiErrorParts {
        &mut self.0
    }
}

impl ApiError {
    pub(crate) fn new(code: ErrorCode, detail: impl Into<String>) -> Self {
        ApiError(Box::new(ApiErrorParts {
            code,
            detail: detail.into(),
            details: None,
            market: None,
            epoch: None,
            retry_after_ms: None,
            headers: Vec::new(),
        }))
    }

    /// `BAD_REQUEST` naming the offending field, query parameter, path
    /// segment or header.
    pub(crate) fn bad_request(field: &str, detail: impl Into<String>) -> Self {
        ApiError::from_details(
            ProblemDetails::BadRequest(BadRequestDetails {
                field: field.to_owned(),
            }),
            detail,
        )
    }

    pub(crate) fn from_details(details: ProblemDetails, detail: impl Into<String>) -> Self {
        let mut e = ApiError::new(details.code(), detail);
        e.details = Some(details.to_value());
        e
    }

    pub(crate) fn rate_limited(scope: RateLimitScope, retry_after_ms: u64) -> Self {
        let mut e = ApiError::from_details(
            ProblemDetails::RateLimited(RateLimitedDetails { scope }),
            "too many requests; retry after the indicated time",
        );
        e.retry_after_ms = Some(retry_after_ms);
        e
    }

    pub(crate) fn market_unknown(market: [u8; 32]) -> Self {
        ApiError::new(ErrorCode::MarketUnknown, "no such market on this node").with_market(market)
    }

    /// `INTERNAL`, logged with the cause. The problem never names it.
    pub(crate) fn internal(cause: impl std::fmt::Display) -> Self {
        tracing::error!(%cause, "request failed");
        ApiError::new(ErrorCode::Internal, "internal error")
    }

    pub(crate) fn with_market(mut self, market: [u8; 32]) -> Self {
        self.market = Some(market);
        self
    }

    pub(crate) fn with_epoch(mut self, epoch: u64) -> Self {
        self.epoch = Some(epoch);
        self
    }

    pub(crate) fn with_retry_after_ms(mut self, ms: u64) -> Self {
        self.retry_after_ms = Some(ms);
        self
    }

    pub(crate) fn with_header(mut self, name: &'static str, value: String) -> Self {
        self.headers.push((name, value));
        self
    }

    /// The problem document, for `request_id`.
    pub(crate) fn to_problem(&self, request_id: &str) -> Problem {
        let mut p = Problem::new(self.code, self.detail.clone(), request_id);
        p.details = self.details.clone();
        p.market = self.market.map(B58);
        p.epoch = self.epoch.map(timescales_service::api::U64);
        p.retry_after_ms = self.retry_after_ms;
        p
    }
}

impl From<StoreError> for ApiError {
    fn from(e: StoreError) -> Self {
        match e {
            StoreError::Full => {
                ApiError::new(ErrorCode::Overloaded, "store queue full").with_retry_after_ms(1000)
            }
            other => ApiError::internal(other),
        }
    }
}

impl From<NodeError> for ApiError {
    fn from(e: NodeError) -> Self {
        match e {
            NodeError::Api { code, detail } => ApiError::new(code, detail),
            NodeError::MarketUnknown(m) => ApiError::market_unknown(m),
            NodeError::ShuttingDown => {
                ApiError::new(ErrorCode::Draining, "the node is shutting down")
            }
            NodeError::Store(s) => s.into(),
            other => ApiError::internal(other),
        }
    }
}

impl From<SessionError> for ApiError {
    fn from(e: SessionError) -> Self {
        match e {
            SessionError::Refused { code, detail } => ApiError::new(code, detail),
            SessionError::Node(n) => n.into(),
        }
    }
}

/// Seconds for `Retry-After`, rounded up. At least one.
pub(crate) fn retry_after_secs(ms: u64) -> u64 {
    ms.div_ceil(1000).max(1)
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let status = StatusCode::from_u16(self.code.http_status())
            .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
        let mut response = status.into_response();
        let headers = response.headers_mut();
        if matches!(status.as_u16(), 429 | 503) {
            let secs = retry_after_secs(self.retry_after_ms.unwrap_or(1000));
            if let Ok(v) = HeaderValue::from_str(&secs.to_string()) {
                headers.insert(header::RETRY_AFTER, v);
            }
        }
        for (name, value) in &self.headers {
            if let Ok(v) = HeaderValue::from_str(value) {
                headers.insert(*name, v);
            }
        }
        // The request id is filled in by the framing middleware.
        response
            .extensions_mut()
            .insert(PendingProblem(self.to_problem("")));
        response
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn node_errors_map_to_their_codes() {
        let e: ApiError = NodeError::Api {
            code: ErrorCode::EpochTooFar,
            detail: "x".into(),
        }
        .into();
        assert_eq!(e.code, ErrorCode::EpochTooFar);
        let e: ApiError = NodeError::ShuttingDown.into();
        assert_eq!(e.code, ErrorCode::Draining);
        let e: ApiError = NodeError::MarketUnknown([3; 32]).into();
        assert_eq!(e.code, ErrorCode::MarketUnknown);
        assert_eq!(e.market, Some([3; 32]));
        let e: ApiError = NodeError::Store(StoreError::Full).into();
        assert_eq!(e.code, ErrorCode::Overloaded);
        let e: ApiError = NodeError::Store(StoreError::Closed).into();
        assert_eq!(e.code, ErrorCode::Internal);
        assert_eq!(e.detail, "internal error");
    }

    #[test]
    fn retry_after_rounds_up() {
        assert_eq!(retry_after_secs(0), 1);
        assert_eq!(retry_after_secs(1000), 1);
        assert_eq!(retry_after_secs(1001), 2);
    }
}
