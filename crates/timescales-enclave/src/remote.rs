//! Key-release members reached over HTTP.

use std::sync::Arc;
use std::time::Duration;

use timescales_core::{Decode, Encode, EpochId, ExecutorId, Hash32, MarketId};
use timescales_executor::tee::{
    BoxFuture, KeyReleaseRequest, KeyReleaseService, ReleaseError, SealedShare,
};
use timescales_service::wire::{
    ChallengeRequest, ChallengeResponse, EnvelopeSigner, MessageKind, ReleaseResponse,
};
use timescales_service::{ClientError, SignedClient, TlsConfig};

/// `KeyReleaseService` over `SignedEnvelope` HTTP (mutual TLS in
/// production), signed with the executor key.
///
/// Requests go to `{url}/krc/v1/challenge` and `{url}/krc/v1/release`.
/// Answers must be envelopes signed by the member's identity from the
/// committee description, addressed to the executor. A refusal is a
/// member-signed `ReleaseResponse` with tag 1, under an error status for
/// a challenge. Transport failures and anything unsigned read as
/// [`ReleaseError::Unavailable`].
#[derive(Debug)]
#[non_exhaustive]
pub struct RemoteMember {
    index: u8,
    market: [u8; 32],
    executor: ExecutorId,
    url: String,
    client: SignedClient,
}

impl RemoteMember {
    /// Member `index` of the committee of the market at `market`, whose
    /// identity key is `identity`, at `url`. `signer` is the enclave's
    /// typed envelope signer: its public key is the executor id the member
    /// checks against the market's registrations.
    pub fn new(
        index: u8,
        url: &str,
        identity: [u8; 32],
        market: [u8; 32],
        signer: Arc<dyn EnvelopeSigner>,
        tls: Option<TlsConfig>,
        timeout: Duration,
    ) -> Result<Self, ClientError> {
        let executor = ExecutorId(signer.public());
        Ok(Self {
            index,
            market,
            executor,
            url: url.trim_end_matches('/').to_owned(),
            client: SignedClient::new(signer, identity, tls, timeout)?,
        })
    }

    pub fn url(&self) -> &str {
        &self.url
    }

    async fn call(
        &self,
        path: &str,
        kind: MessageKind,
        body: Vec<u8>,
    ) -> Result<(MessageKind, Vec<u8>), ReleaseError> {
        match self
            .client
            .call(&format!("{}{path}", self.url), kind, body)
            .await
        {
            Ok(env) => Ok((env.kind, env.body)),
            // A refusal the member signed, under an error status.
            Err(ClientError::Refused { envelope, .. }) => Ok((envelope.kind, envelope.body)),
            Err(e) => {
                tracing::debug!(member = self.index, error = %e, "member call failed");
                Err(ReleaseError::Unavailable)
            }
        }
    }
}

/// The error a member's signed refusal stands for. Anything else in a
/// `ReleaseResponse` is not an answer to the call that was made.
fn refusal(body: &[u8]) -> ReleaseError {
    match ReleaseResponse::decode_exact(body) {
        Ok(ReleaseResponse::Refused { code, .. }) => code.into(),
        _ => ReleaseError::BadRequest,
    }
}

impl KeyReleaseService for RemoteMember {
    fn index(&self) -> u8 {
        self.index
    }

    fn challenge(
        &self,
        // The wire request names the market account this member was built
        // for. The member ties it to the header's market id through that
        // account's parameters.
        _market: MarketId,
        epoch: EpochId,
    ) -> BoxFuture<'_, Result<Hash32, ReleaseError>> {
        Box::pin(async move {
            let req = ChallengeRequest {
                market: self.market,
                epoch,
                executor: self.executor,
            };
            let (kind, body) = self
                .call(
                    "/krc/v1/challenge",
                    MessageKind::ChallengeRequest,
                    req.to_bytes(),
                )
                .await?;
            match kind {
                MessageKind::ChallengeResponse => {
                    let c = ChallengeResponse::decode_exact(&body)
                        .map_err(|_| ReleaseError::BadRequest)?;
                    if c.member != self.index || c.market != self.market || c.epoch != epoch {
                        return Err(ReleaseError::BadRequest);
                    }
                    Ok(c.nonce)
                }
                MessageKind::ReleaseResponse => Err(refusal(&body)),
                _ => Err(ReleaseError::BadRequest),
            }
        })
    }

    fn release(&self, req: KeyReleaseRequest) -> BoxFuture<'_, Result<SealedShare, ReleaseError>> {
        Box::pin(async move {
            let (kind, body) = self
                .call(
                    "/krc/v1/release",
                    MessageKind::ReleaseRequest,
                    req.to_bytes(),
                )
                .await?;
            if kind != MessageKind::ReleaseResponse {
                return Err(ReleaseError::BadRequest);
            }
            match ReleaseResponse::decode_exact(&body).map_err(|_| ReleaseError::BadRequest)? {
                ReleaseResponse::Share(share) if share.member == self.index => Ok(share),
                // A share labelled with another member is dropped by the
                // enclave anyway. Name it here.
                ReleaseResponse::Share(_) => Err(ReleaseError::BadRequest),
                ReleaseResponse::Refused { code, .. } => Err(code.into()),
            }
        })
    }
}
