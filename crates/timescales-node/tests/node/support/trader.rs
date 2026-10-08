//! A trader as the SDK would act: a funded wallet with a Trader account, a
//! SIWS session granted by the wallet over the exact text, and orders the
//! wallet signs, sealed to the epoch key and submitted by the session key.

use std::sync::Arc;

use rand::SeedableRng;
use rand::rngs::StdRng;
use timescales_chain::TxSigner;
use timescales_core::identity::TraderKey;
use timescales_core::intent::{PrivateIntent, SealedEnvelope};
use timescales_core::{
    CommitmentScheme, EpochId, Lots, MarketId, Order, OrderCommitment, OrderKind, Role, Side, Tick,
    TraderId,
};
use timescales_node::{NodeApi, SessionRef, VerifiedSubmission};
use timescales_service::api::{B58, B64, CreateSessionRequest, GrantMethodJson, Session};
use timescales_service::relay::{RelayConfig, Submission, verify_submission};
use timescales_service::wire::{ChainId, SESSION_STATEMENT, SessionGrant, render_session_message};

pub struct Trader {
    pub wallet: Arc<dyn TxSigner>,
    pub key: TraderKey,
    pub session_key: TraderKey,
    pub session: Option<SessionRef>,
    pub session_seed: [u8; 32],
    /// The world's index of this trader.
    pub index: u64,
    nonce: std::sync::atomic::AtomicU64,
    rng: parking_lot::Mutex<StdRng>,
}

impl Trader {
    pub fn new(
        wallet: Arc<dyn TxSigner>,
        seed: [u8; 32],
        session_seed: [u8; 32],
        index: u64,
    ) -> Self {
        Self {
            wallet,
            key: TraderKey::from_seed(seed),
            session_key: TraderKey::from_seed(session_seed),
            session: None,
            session_seed,
            index,
            nonce: std::sync::atomic::AtomicU64::new(1),
            rng: parking_lot::Mutex::new(StdRng::seed_from_u64(u64::from(seed[0]))),
        }
    }

    pub fn id(&self) -> [u8; 32] {
        self.wallet.address()
    }

    /// The SIWS grant text of a session for `market`, as the SDK renders it.
    pub fn grant_text(
        &self,
        nonce: [u8; 16],
        now_ms: u64,
        market: [u8; 32],
        program: [u8; 32],
    ) -> String {
        render_session_message(&SessionGrant {
            domain: "localhost:4173".into(),
            wallet: self.id(),
            statement: SESSION_STATEMENT.into(),
            uri: "http://localhost:4173".into(),
            chain_id: ChainId::Localnet,
            nonce,
            issued_at_ms: now_ms,
            expires_at_ms: now_ms + 3_600_000,
            not_before_ms: None,
            session_key: self.session_key.id().0,
            program,
            market: Some(market),
        })
    }

    pub fn grant(&self, text: &str) -> CreateSessionRequest {
        CreateSessionRequest {
            wallet: B58(self.id()),
            message: text.to_owned(),
            signature_b64: B64(self.wallet.sign(text.as_bytes()).to_vec()),
            method: GrantMethodJson::SignIn,
            min_context_slot: None,
        }
    }

    /// Creates the session through the node.
    pub async fn login(
        &mut self,
        node: &dyn NodeApi,
        now_ms: u64,
        market: [u8; 32],
        program: [u8; 32],
    ) -> Session {
        let nonce = node.session_nonce().await.unwrap();
        let nonce: [u8; 16] = nonce.nonce.0.try_into().unwrap();
        let text = self.grant_text(nonce, now_ms, market, program);
        let s = node.create_session(self.grant(&text), None).await.unwrap();
        self.session = Some(SessionRef {
            session_key: self.session_key.id().0,
            wallet: self.id(),
            market: Some(market),
        });
        s
    }

    /// A limit order for `epoch` only.
    #[allow(clippy::too_many_arguments)]
    pub fn order(
        &self,
        cfg: &RelayConfig,
        market_id: MarketId,
        epoch: u64,
        epoch_pk: &[u8; 32],
        side: Side,
        role: Role,
        tick: u64,
        lots: u64,
    ) -> (VerifiedSubmission, OrderCommitment) {
        let order = Order {
            market: market_id,
            trader: TraderId(self.id()),
            nonce: self
                .nonce
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed),
            side,
            role,
            kind: OrderKind::Limit,
            limit: Tick(tick),
            quantity: Lots(lots),
            valid_from: EpochId(epoch),
            expires_at: EpochId(epoch),
        };
        let mut rng = self.rng.lock();
        let (intent, c) =
            PrivateIntent::place(&mut *rng, &self.key, CommitmentScheme::Sha256, order).unwrap();
        let env = SealedEnvelope::seal(&mut *rng, market_id, EpochId(epoch), epoch_pk, c, &intent)
            .unwrap();
        (self.submission(cfg, env), c)
    }

    /// The session key's submission of `env`.
    pub fn submission(&self, cfg: &RelayConfig, env: SealedEnvelope) -> VerifiedSubmission {
        let sub = Submission::sign(&self.session_key, env, None);
        let raw = timescales_core::Encode::to_bytes(&sub);
        VerifiedSubmission {
            raw,
            inner: verify_submission(cfg, &sub).unwrap(),
        }
    }
}
