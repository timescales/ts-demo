//! [`SignedClient`]: service-to-service calls in [`SignedEnvelope`]s.

use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::wire::{
    EnvelopePrefix, EnvelopeSigner, MessageKind, PREFIX_LEN, ReplayGuard, SignedEnvelope, WireError,
};
use rand_core::OsRng;
use thiserror::Error;
use timescales_core::{DecodeError, Encode};

use crate::VerifiedEnvelope;
use crate::envelope::ENVELOPE_CONTENT_TYPE;
use crate::tls::{TlsConfig, client_config, refusing_client_config};

/// Clock skew accepted on responses (+/-30 s).
pub const RESPONSE_SKEW_MS: u64 = 30_000;

/// Responses remembered against replay (100k entries).
const RESPONSE_REPLAY_CAPACITY: usize = 100_000;

#[derive(Debug, Error)]
pub enum ClientError {
    #[error("TLS setup: {0}")]
    Tls(String),
    #[error("transport: {0}")]
    Transport(String),
    /// A non-2xx answer without a valid envelope from the peer.
    #[error("HTTP status {0}")]
    Status(u16),
    /// A non-2xx answer whose body is a valid envelope from the peer, for
    /// example a member's 409 naming the announcement it holds.
    #[error("refused with HTTP status {status}")]
    Refused {
        status: u16,
        envelope: VerifiedEnvelope,
    },
    #[error("timed out")]
    Timeout,
    #[error(transparent)]
    Wire(#[from] WireError),
    #[error("response from an unexpected sender")]
    Peer,
}

/// HTTP client that sends and expects [`crate::wire::SignedEnvelope`]s:
/// reqwest over rustls (optionally mutual TLS), signing with an
/// [`EnvelopeSigner`] and accepting responses from one peer identity.
///
/// With a [`TlsConfig`] it speaks only `https` with mutual TLS 1.3 and
/// pinned peers. Without one only plain `http` (profile local). Either way
/// the response must be an envelope from `peer`, addressed to this
/// client's key, within +/-30 s, and not seen before. Its prefix is checked
/// before the rest of the response is read. Redirects and proxies are not
/// followed.
pub struct SignedClient {
    http: reqwest::Client,
    signer: Arc<dyn EnvelopeSigner>,
    peer: [u8; 32],
    tls: bool,
    replay: ReplayGuard,
}

impl core::fmt::Debug for SignedClient {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SignedClient")
            .field("me", &self.signer.public())
            .field("peer", &self.peer)
            .field("tls", &self.tls)
            .finish_non_exhaustive()
    }
}

impl SignedClient {
    pub fn new(
        signer: Arc<dyn EnvelopeSigner>,
        peer: [u8; 32],
        tls: Option<TlsConfig>,
        timeout: Duration,
    ) -> Result<Self, ClientError> {
        let tls_config = match &tls {
            Some(cfg) => client_config(cfg)?,
            None => refusing_client_config()?,
        };
        let http = reqwest::Client::builder()
            .tls_backend_preconfigured(tls_config)
            .https_only(tls.is_some())
            .redirect(reqwest::redirect::Policy::none())
            .no_proxy()
            .timeout(timeout)
            .build()
            .map_err(|e| ClientError::Tls(e.to_string()))?;
        Ok(Self {
            http,
            signer,
            peer,
            tls: tls.is_some(),
            replay: ReplayGuard::new(RESPONSE_REPLAY_CAPACITY, 2 * RESPONSE_SKEW_MS),
        })
    }

    /// Sends `body` as an envelope of `kind` to `url` and returns the
    /// verified response. A non-2xx status is [`ClientError::Refused`] when
    /// its body is an envelope that passes the same checks, and
    /// [`ClientError::Status`] otherwise.
    pub async fn call(
        &self,
        url: &str,
        kind: MessageKind,
        body: Vec<u8>,
    ) -> Result<VerifiedEnvelope, ClientError> {
        self.check_scheme(url)?;
        let request =
            SignedEnvelope::seal(kind, &*self.signer, self.peer, now_ms(), &mut OsRng, body);
        let response = self
            .http
            .post(url)
            .header(reqwest::header::CONTENT_TYPE, ENVELOPE_CONTENT_TYPE)
            .body(request.to_bytes())
            .send()
            .await
            .map_err(transport)?;
        let status = response.status();
        if status.is_success() {
            return self.read_envelope(response).await;
        }
        let status = status.as_u16();
        let sealed = response
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .is_some_and(|v| v.as_bytes() == ENVELOPE_CONTENT_TYPE.as_bytes());
        if !sealed {
            return Err(ClientError::Status(status));
        }
        // A refusal body that does not verify carries nothing to trust.
        match self.read_envelope(response).await {
            Ok(envelope) => Err(ClientError::Refused { status, envelope }),
            Err(_) => Err(ClientError::Status(status)),
        }
    }

    /// Reads a response body as an envelope from the peer, addressed to
    /// this client, fresh and not seen before, checking its prefix before
    /// reading the rest.
    async fn read_envelope(
        &self,
        mut response: reqwest::Response,
    ) -> Result<VerifiedEnvelope, ClientError> {
        let mut prefix = [0u8; PREFIX_LEN];
        let mut filled = 0;
        let mut rest = Vec::new();
        while filled < PREFIX_LEN {
            let chunk = next_chunk(&mut response)
                .await?
                .ok_or(truncated(PREFIX_LEN, filled))?;
            let take = chunk.len().min(PREFIX_LEN - filled);
            prefix[filled..filled + take].copy_from_slice(&chunk[..take]);
            filled += take;
            rest.extend_from_slice(&chunk[take..]);
        }
        let me = self.signer.public();
        let peer = self.peer;
        let from_peer = move |sender: &[u8; 32], _: MessageKind| *sender == peer;
        let p = EnvelopePrefix::check(&prefix, &me, &from_peer).map_err(|e| match e {
            WireError::Sender => ClientError::Peer,
            other => ClientError::Wire(other),
        })?;
        let need = usize::try_from(p.body_len)
            .unwrap_or(usize::MAX)
            .saturating_add(64);
        if rest.len() > need {
            return Err(trailing(rest.len() - need));
        }
        rest.reserve_exact(need - rest.len());
        while rest.len() < need {
            let chunk = next_chunk(&mut response)
                .await?
                .ok_or(truncated(need, rest.len()))?;
            if rest.len() + chunk.len() > need {
                return Err(trailing(rest.len() + chunk.len() - need));
            }
            rest.extend_from_slice(&chunk);
        }
        if let Some(extra) = next_chunk(&mut response).await?.filter(|c| !c.is_empty()) {
            return Err(trailing(extra.len()));
        }

        let env = SignedEnvelope::from_prefix(&p, &rest)?;
        let now = now_ms();
        env.open(&me, &from_peer, now, RESPONSE_SKEW_MS)?;
        self.replay
            .check_and_insert(&env.sender, &env.nonce, env.issued_at_ms, now)?;
        Ok(VerifiedEnvelope {
            sender: env.sender,
            kind: env.kind,
            body: env.body,
        })
    }

    fn check_scheme(&self, url: &str) -> Result<(), ClientError> {
        let scheme = url.split_once("://").map(|(s, _)| s.to_ascii_lowercase());
        match (scheme.as_deref(), self.tls) {
            (Some("https"), true) | (Some("http"), false) => Ok(()),
            (Some("http"), true) => Err(ClientError::Tls(
                "mutual TLS is configured; refusing a plain http URL".to_owned(),
            )),
            (Some("https"), false) => Err(ClientError::Tls(
                "an https URL needs a [tls] section with pinned peers".to_owned(),
            )),
            _ => Err(ClientError::Transport(format!("unsupported URL {url:?}"))),
        }
    }
}

async fn next_chunk(
    response: &mut reqwest::Response,
) -> Result<Option<axum::body::Bytes>, ClientError> {
    response.chunk().await.map_err(transport)
}

fn truncated(needed: usize, remaining: usize) -> ClientError {
    ClientError::Wire(WireError::Decode(DecodeError::UnexpectedEof {
        needed,
        remaining,
    }))
}

fn trailing(extra: usize) -> ClientError {
    ClientError::Wire(WireError::Decode(DecodeError::TrailingBytes(extra)))
}

fn transport(e: reqwest::Error) -> ClientError {
    if e.is_timeout() {
        ClientError::Timeout
    } else {
        // The source chain names the TLS or connection failure.
        let mut message = e.to_string();
        let mut source = std::error::Error::source(&e);
        while let Some(s) = source {
            message.push_str(": ");
            message.push_str(&s.to_string());
            source = s.source();
        }
        ClientError::Transport(message)
    }
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
        .unwrap_or(0)
}
