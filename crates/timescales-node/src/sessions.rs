//! Sessions: SIWS grant verification, stateless nonces,
//! idempotent re-submission of an identical grant, oldest-session eviction
//! and `Authorization: TimescalesSession` request authentication.
//!
//! A grant is checked in this order: size and ABNF parse, the wallet it
//! names, the grant method, the semantic fields (domain, URI, chain,
//! program, statement, lifetime), the wallet's signature over the exact
//! text, then - unless this exact grant already made a session - the
//! nonce's MAC and age, the wallet's eligibility at the client's
//! `min_context_slot`, and only then is the nonce recorded as used. A grant
//! that fails eligibility leaves its nonce usable.

use std::collections::{BTreeMap, VecDeque};
use std::sync::Arc;

use parking_lot::Mutex;
use rand_core::OsRng;
use timescales_core::crypto::Signature;
use timescales_service::api::{
    B58, CreateSessionRequest, ErrorCode, GrantMethodJson, Hex, Hex32, Quotas, Session,
    SessionNonce, U64, Usage,
};
use timescales_service::store::node::{NodeRepo, SessionRow};
use timescales_service::wire::{
    ChainId, GrantExpectations, GrantMethod, MAX_SESSION_TEXT_BYTES, SESSION_STATEMENT,
    SessionAuthorization, WireError, check_session_nonce, issue_session_nonce,
    parse_session_message,
};
use zeroize::Zeroizing;

use crate::clock::Clock;
use crate::config::{ApiConfig, Cluster, MarketConfig, SessionsConfig};
use crate::intake::{Eligibility, Ineligible};
use crate::{Address, NodeError, SessionError, SessionRef};

/// Session-request authentications remembered against replay.
const AUTH_REPLAY_CAPACITY: usize = 100_000;

fn refuse(code: ErrorCode, detail: impl Into<String>) -> SessionError {
    SessionError::Refused {
        code,
        detail: detail.into(),
    }
}

/// The chain id a SIWS grant names for a cluster.
pub fn chain_id(cluster: Cluster) -> ChainId {
    match cluster {
        Cluster::Localnet => ChainId::Localnet,
        Cluster::Devnet => ChainId::Devnet,
        Cluster::MainnetBeta => ChainId::Mainnet,
    }
}

/// Per-market session quotas, as a `Session` reports them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MarketQuotas {
    pub max_envelopes_per_wallet_per_epoch: u32,
    pub max_parked_per_wallet: u32,
}

impl From<&MarketConfig> for MarketQuotas {
    fn from(m: &MarketConfig) -> Self {
        Self {
            max_envelopes_per_wallet_per_epoch: m.quota.max_envelopes_per_wallet_per_epoch,
            max_parked_per_wallet: m.quota.max_parked_per_wallet,
        }
    }
}

/// Session service shared by the API calls.
pub struct Sessions {
    cfg: SessionsConfig,
    domains: Vec<String>,
    uri: String,
    chain: ChainId,
    program: Address,
    nonce_key: Zeroizing<[u8; 32]>,
    repo: Arc<NodeRepo>,
    clock: Arc<dyn Clock>,
    eligibility: Arc<Eligibility>,
    quotas: BTreeMap<Address, MarketQuotas>,
    /// `(session key, ts, signature)` of recent authenticated requests.
    replay: Mutex<ReplayCache>,
}

impl core::fmt::Debug for Sessions {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Sessions")
            .field("domains", &self.domains)
            .finish_non_exhaustive()
    }
}

#[derive(Default)]
struct ReplayCache {
    seen: BTreeMap<AuthKey, ()>,
    order: VecDeque<(u64, AuthKey)>,
}

/// `(session key, ts, signature)` of one authenticated request.
type AuthKey = ([u8; 32], u64, [u8; 64]);

impl ReplayCache {
    /// Remembers `key` until `expires_ms`. False when it was seen or the
    /// cache is full of live entries (fails closed).
    fn insert(&mut self, key: AuthKey, now_ms: u64, expires_ms: u64) -> bool {
        while let Some((exp, k)) = self.order.front() {
            if *exp > now_ms {
                break;
            }
            self.seen.remove(k);
            self.order.pop_front();
        }
        if self.seen.contains_key(&key) || self.seen.len() >= AUTH_REPLAY_CAPACITY {
            return false;
        }
        self.seen.insert(key, ());
        self.order.push_back((expires_ms, key));
        true
    }
}

/// Inputs of [`Sessions::new`].
pub struct SessionsInit {
    pub cfg: SessionsConfig,
    pub api: ApiConfig,
    pub cluster: Cluster,
    pub program: Address,
    pub nonce_key: Zeroizing<[u8; 32]>,
    pub repo: Arc<NodeRepo>,
    pub clock: Arc<dyn Clock>,
    pub eligibility: Arc<Eligibility>,
    pub quotas: BTreeMap<Address, MarketQuotas>,
}

impl core::fmt::Debug for SessionsInit {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SessionsInit").finish_non_exhaustive()
    }
}

impl Sessions {
    pub fn new(init: SessionsInit) -> Self {
        Self {
            cfg: init.cfg,
            domains: init.api.session_domains,
            uri: init.api.public_base_url,
            chain: chain_id(init.cluster),
            program: init.program,
            nonce_key: init.nonce_key,
            repo: init.repo,
            clock: init.clock,
            eligibility: init.eligibility,
            quotas: init.quotas,
            replay: Mutex::new(ReplayCache::default()),
        }
    }

    /// A fresh stateless nonce. Issuing one writes nothing.
    pub fn nonce(&self) -> SessionNonce {
        let now = self.clock.now_ms();
        let nonce = issue_session_nonce(&self.nonce_key, now, &mut OsRng);
        // The nonce carries its issue time in seconds. It expires that
        // many seconds after.
        let issued_ms =
            u64::from(u32::from_le_bytes([nonce[0], nonce[1], nonce[2], nonce[3]])) * 1000;
        SessionNonce {
            nonce: Hex(nonce.to_vec()),
            expires_at_ms: issued_ms.saturating_add(self.cfg.nonce_ttl_s.saturating_mul(1000)),
            domain: self.domains.first().cloned().unwrap_or_default(),
            uri: self.uri.clone(),
            chain_id: self.chain.as_str().to_owned(),
            statement: SESSION_STATEMENT.to_owned(),
            template_version: 1,
        }
    }

    fn quotas_for(&self, market: Option<Address>) -> Quotas {
        let q = market
            .and_then(|m| self.quotas.get(&m))
            .or_else(|| self.quotas.values().next())
            .copied()
            .unwrap_or(MarketQuotas {
                max_envelopes_per_wallet_per_epoch: 0,
                max_parked_per_wallet: 0,
            });
        Quotas {
            max_envelopes_per_wallet_per_epoch: q.max_envelopes_per_wallet_per_epoch,
            max_parked_per_wallet: q.max_parked_per_wallet,
        }
    }

    fn dto(&self, row: &SessionRow, evicted: Option<u32>, usage: Option<Usage>) -> Session {
        Session {
            session_key: Hex32(row.session_pk),
            wallet: B58(row.wallet),
            market: row.market.map(B58),
            expires_at_ms: row.expires_at_ms.unwrap_or(0),
            quotas: self.quotas_for(row.market),
            usage,
            evicted,
        }
    }

    /// `POST /v1/sessions`. `Ok((session, created))`: `created` is false
    /// when an identical grant already made this session (200, not 201).
    pub async fn create(
        &self,
        req: CreateSessionRequest,
        min_context_slot: Option<u64>,
    ) -> Result<(Session, bool), SessionError> {
        let now = self.clock.now_ms();
        if req.message.len() > MAX_SESSION_TEXT_BYTES {
            return Err(refuse(
                ErrorCode::SessionTemplateInvalid,
                "grant text exceeds 1024 bytes",
            ));
        }
        let grant = parse_session_message(&req.message)
            .map_err(|e| refuse(ErrorCode::SessionTemplateInvalid, e.to_string()))?;
        if grant.wallet != req.wallet.0 {
            return Err(refuse(
                ErrorCode::SessionTemplateInvalid,
                "the grant names another wallet",
            ));
        }
        let method = match req.method {
            GrantMethodJson::SignIn => GrantMethod::SignIn,
            GrantMethodJson::SignMessage if self.cfg.allow_sign_message_grants => {
                GrantMethod::SignMessage
            }
            GrantMethodJson::SignMessage => {
                return Err(refuse(
                    ErrorCode::SessionMethodRefused,
                    "sign_message grants are refused by this deployment",
                ));
            }
        };
        let expect = GrantExpectations {
            domains: &self.domains,
            uri: &self.uri,
            chain_id: self.chain,
            program: self.program,
            now_ms: now,
            max_ttl_ms: self.cfg.max_ttl_s.saturating_mul(1000),
        };
        grant.check(&expect).map_err(|e| match e {
            WireError::Audience => refuse(
                ErrorCode::SessionDomainMismatch,
                "the grant names another domain",
            ),
            WireError::Expired => refuse(ErrorCode::SessionExpired, "the grant has expired"),
            other => refuse(ErrorCode::SessionTemplateInvalid, other.to_string()),
        })?;
        if let Some(m) = grant.market
            && !self.quotas.contains_key(&m)
        {
            return Err(refuse(
                ErrorCode::MarketUnknown,
                "the grant names a market this node does not serve",
            ));
        }
        let signature: [u8; 64] = req
            .signature_b64
            .0
            .as_slice()
            .try_into()
            .map_err(|_| refuse(ErrorCode::BadSignature, "the signature is not 64 bytes"))?;
        if !ed25519::verify_strict(&grant.wallet, req.message.as_bytes(), &signature) {
            return Err(refuse(
                ErrorCode::BadSignature,
                "the wallet signature does not verify",
            ));
        }

        // The same grant again (a client retry) returns the session it made.
        if let Some(existing) = self
            .repo
            .session_by_grant(grant.wallet, grant.nonce)
            .await
            .map_err(NodeError::from)?
        {
            if existing.session_pk == grant.session_key && existing.signature == signature {
                return Ok((self.dto(&existing, None, None), false));
            }
            return Err(refuse(
                ErrorCode::SessionNonceInvalid,
                "the nonce was used by another grant",
            ));
        }

        let ttl_ms = self.cfg.nonce_ttl_s.saturating_mul(1000);
        check_session_nonce(&self.nonce_key, &grant.nonce, now, ttl_ms).map_err(|e| match e {
            WireError::Expired => refuse(ErrorCode::SessionNonceInvalid, "the nonce has expired"),
            _ => refuse(
                ErrorCode::SessionNonceInvalid,
                "the nonce was not issued here",
            ),
        })?;

        // Eligibility before the nonce is consumed.
        let markets: Vec<Address> = match grant.market {
            Some(m) => vec![m],
            None => self.quotas.keys().copied().collect(),
        };
        let mut last = None;
        let mut eligible = false;
        for m in markets {
            match self
                .eligibility
                .check(m, grant.wallet, min_context_slot)
                .await
            {
                Ok(_) => {
                    eligible = true;
                    break;
                }
                Err(e) => last = Some(e),
            }
        }
        if !eligible {
            let detail = match last {
                Some(Ineligible::NoTraderAccount) => "no Trader account".to_owned(),
                Some(Ineligible::Insufficient { min }) => {
                    format!("available value below {min} quote atoms")
                }
                Some(Ineligible::Unavailable(e)) => {
                    return Err(SessionError::Node(NodeError::Api {
                        code: ErrorCode::MarketUnavailable,
                        detail: e,
                    }));
                }
                None => "no market".to_owned(),
            };
            return Err(refuse(ErrorCode::WalletNotEligible, detail));
        }

        let nonce_expires = now.saturating_add(ttl_ms);
        let fresh = self
            .repo
            .use_nonce(grant.nonce, nonce_expires)
            .await
            .map_err(NodeError::from)?;
        if !fresh {
            return Err(refuse(
                ErrorCode::SessionNonceInvalid,
                "the nonce was already used",
            ));
        }
        let row = SessionRow {
            session_pk: grant.session_key,
            wallet: grant.wallet,
            market: grant.market,
            grant_text: req.message,
            signature,
            method,
            nonce: grant.nonce,
            issued_at_ms: Some(grant.issued_at_ms),
            expires_at_ms: Some(grant.expires_at_ms),
            revoked: false,
            keep_until_epoch: None,
        };
        let (row, evicted) = self
            .repo
            .insert_session(row, self.cfg.max_per_wallet)
            .await
            .map_err(|e| match e {
                timescales_service::store::StoreError::Conflict(why) => {
                    refuse(ErrorCode::SessionNonceInvalid, why)
                }
                other => SessionError::Node(other.into()),
            })?;
        tracing::info!(
            wallet_tag = %timescales_service::wallet_tag(&row.wallet),
            evicted,
            "session created"
        );
        let evicted = (evicted > 0).then_some(evicted);
        Ok((self.dto(&row, evicted, None), true))
    }

    /// The active session of `key`, or why it is not usable.
    pub async fn active(&self, key: [u8; 32]) -> Result<SessionRow, ErrorCode> {
        let row = self
            .repo
            .session(key)
            .await
            .map_err(|_| ErrorCode::Internal)?
            .ok_or(ErrorCode::SessionUnknown)?;
        if row.revoked {
            return Err(ErrorCode::SessionRevoked);
        }
        if row.expires_at_ms.is_none_or(|e| self.clock.now_ms() >= e) {
            return Err(ErrorCode::SessionExpired);
        }
        Ok(row)
    }

    pub async fn get(
        &self,
        key: [u8; 32],
        usage: Option<Usage>,
    ) -> Result<Option<Session>, NodeError> {
        Ok(self
            .repo
            .session(key)
            .await?
            .map(|row| self.dto(&row, None, usage)))
    }

    pub async fn revoke(&self, key: [u8; 32]) -> Result<(), NodeError> {
        self.repo.revoke_session(key).await?;
        Ok(())
    }

    /// `Authorization: TimescalesSession <pk>.<ts>.<sig>`: the
    /// signature, +/-`skew_ms`, an active session, and no replay of the same
    /// `(pk, ts, sig)`.
    pub async fn authenticate(
        &self,
        header: &str,
        method: &str,
        path_and_query: &str,
        body: &[u8],
    ) -> Result<SessionRef, SessionError> {
        let auth = SessionAuthorization::parse(header).map_err(|_| {
            refuse(
                ErrorCode::SessionUnknown,
                "malformed TimescalesSession header",
            )
        })?;
        let now = self.clock.now_ms();
        auth.verify(method, path_and_query, body, now, self.cfg.skew_ms)
            .map_err(|e| match e {
                WireError::Skew { .. } => refuse(ErrorCode::Skew, "request time outside the skew"),
                _ => refuse(ErrorCode::BadSignature, "session request signature"),
            })?;
        let row = self
            .active(auth.session_key)
            .await
            .map_err(|code| refuse(code, "session not usable"))?;
        let key = (auth.session_key, auth.ts_ms, auth.signature.0);
        let fresh = self.replay.lock().insert(
            key,
            now,
            auth.ts_ms
                .saturating_add(self.cfg.skew_ms.saturating_mul(2)),
        );
        if !fresh {
            return Err(refuse(ErrorCode::BadSignature, "replayed session request"));
        }
        Ok(SessionRef {
            session_key: row.session_pk,
            wallet: row.wallet,
            market: row.market,
        })
    }
}

/// A `Usage` for `GET /v1/sessions/current`.
pub fn usage(epoch: u64, used: u32, parked: u32) -> Usage {
    Usage {
        epoch: U64(epoch),
        used,
        parked,
    }
}

/// The SIWS grant check, for the test enclaves that verify provenance
/// until the core crypto provides a message verifier.
#[cfg(feature = "test-util")]
pub fn verify_grant_signature(public: &[u8; 32], message: &[u8], signature: &[u8; 64]) -> bool {
    ed25519::verify_strict(public, message, signature)
}

/// The signature of a grant as the provenance record carries it.
pub fn grant_signature(row: &SessionRow) -> Signature {
    Signature(row.signature)
}

/// Strict Ed25519 verification of a message of any length (RFC 8032 with
/// the `verify_strict` rules of ed25519-dalek: canonical `S`, no
/// small-order `A` or `R`, cofactorless equation).
///
/// The core crypto only verifies 32-byte digests, and the node's
/// manifest may not add `ed25519-dalek`, so this assembles the
/// check from the curve operations it exposes and a
/// SHA-512 implementation.
/// Wallets sign SIWS grants over the raw text, so a digest check cannot
/// stand in for it. Crate-private so nothing outside the node comes to
/// rely on it before that replacement lands.
pub(crate) mod ed25519 {
    use core::ops::{Add, Mul};

    use timescales_core::crypto::threshold::{ScalarShare, decompress_canonical};

    /// The Ed25519 base point, compressed.
    pub(super) const BASEPOINT: [u8; 32] = {
        let mut b = [0x66u8; 32];
        b[0] = 0x58;
        b
    };

    /// `sum bytes[i]*256^i` in the scalar field of `witness`'s type.
    pub(super) fn reduce_le<T>(witness: &T, bytes: &[u8]) -> T
    where
        T: From<u64> + Copy + Add<Output = T> + Mul<Output = T>,
    {
        let _ = witness;
        let radix = T::from(256);
        bytes
            .iter()
            .rev()
            .fold(T::from(0), |acc, b| acc * radix + T::from(u64::from(*b)))
    }

    pub(crate) fn verify_strict(public: &[u8; 32], message: &[u8], signature: &[u8; 64]) -> bool {
        let Some(a) = decompress_canonical(public) else {
            return false;
        };
        let (r_bytes, s_bytes) = signature.split_at(32);
        let Ok(r_bytes) = <[u8; 32]>::try_from(r_bytes) else {
            return false;
        };
        let Ok(s_bytes) = <[u8; 32]>::try_from(s_bytes) else {
            return false;
        };
        let Some(r) = decompress_canonical(&r_bytes) else {
            return false;
        };
        if a.is_small_order() || r.is_small_order() {
            return false;
        }
        // Canonical S (below the group order) or nothing.
        let Some(s) = ScalarShare::from_bytes(1, &s_bytes) else {
            return false;
        };
        let s = s.value;
        let Some(b) = decompress_canonical(&BASEPOINT) else {
            return false;
        };
        let mut h = super::sha512::Sha512::new();
        h.update(&r_bytes);
        h.update(public);
        h.update(message);
        let k = reduce_le(&s, &h.finalize());
        b * s == r + a * k
    }
}

/// SHA-512 (FIPS 180-4), only for [`ed25519`].
mod sha512 {
    const K: [u64; 80] = [
        0x428a2f98d728ae22,
        0x7137449123ef65cd,
        0xb5c0fbcfec4d3b2f,
        0xe9b5dba58189dbbc,
        0x3956c25bf348b538,
        0x59f111f1b605d019,
        0x923f82a4af194f9b,
        0xab1c5ed5da6d8118,
        0xd807aa98a3030242,
        0x12835b0145706fbe,
        0x243185be4ee4b28c,
        0x550c7dc3d5ffb4e2,
        0x72be5d74f27b896f,
        0x80deb1fe3b1696b1,
        0x9bdc06a725c71235,
        0xc19bf174cf692694,
        0xe49b69c19ef14ad2,
        0xefbe4786384f25e3,
        0x0fc19dc68b8cd5b5,
        0x240ca1cc77ac9c65,
        0x2de92c6f592b0275,
        0x4a7484aa6ea6e483,
        0x5cb0a9dcbd41fbd4,
        0x76f988da831153b5,
        0x983e5152ee66dfab,
        0xa831c66d2db43210,
        0xb00327c898fb213f,
        0xbf597fc7beef0ee4,
        0xc6e00bf33da88fc2,
        0xd5a79147930aa725,
        0x06ca6351e003826f,
        0x142929670a0e6e70,
        0x27b70a8546d22ffc,
        0x2e1b21385c26c926,
        0x4d2c6dfc5ac42aed,
        0x53380d139d95b3df,
        0x650a73548baf63de,
        0x766a0abb3c77b2a8,
        0x81c2c92e47edaee6,
        0x92722c851482353b,
        0xa2bfe8a14cf10364,
        0xa81a664bbc423001,
        0xc24b8b70d0f89791,
        0xc76c51a30654be30,
        0xd192e819d6ef5218,
        0xd69906245565a910,
        0xf40e35855771202a,
        0x106aa07032bbd1b8,
        0x19a4c116b8d2d0c8,
        0x1e376c085141ab53,
        0x2748774cdf8eeb99,
        0x34b0bcb5e19b48a8,
        0x391c0cb3c5c95a63,
        0x4ed8aa4ae3418acb,
        0x5b9cca4f7763e373,
        0x682e6ff3d6b2b8a3,
        0x748f82ee5defb2fc,
        0x78a5636f43172f60,
        0x84c87814a1f0ab72,
        0x8cc702081a6439ec,
        0x90befffa23631e28,
        0xa4506cebde82bde9,
        0xbef9a3f7b2c67915,
        0xc67178f2e372532b,
        0xca273eceea26619c,
        0xd186b8c721c0c207,
        0xeada7dd6cde0eb1e,
        0xf57d4f7fee6ed178,
        0x06f067aa72176fba,
        0x0a637dc5a2c898a6,
        0x113f9804bef90dae,
        0x1b710b35131c471b,
        0x28db77f523047d84,
        0x32caab7b40c72493,
        0x3c9ebe0a15c9bebc,
        0x431d67c49c100d4c,
        0x4cc5d4becb3e42b6,
        0x597f299cfc657e2a,
        0x5fcb6fab3ad6faec,
        0x6c44198c4a475817,
    ];

    const INIT: [u64; 8] = [
        0x6a09e667f3bcc908,
        0xbb67ae8584caa73b,
        0x3c6ef372fe94f82b,
        0xa54ff53a5f1d36f1,
        0x510e527fade682d1,
        0x9b05688c2b3e6c1f,
        0x1f83d9abfb41bd6b,
        0x5be0cd19137e2179,
    ];

    pub(super) struct Sha512 {
        state: [u64; 8],
        block: [u8; 128],
        filled: usize,
        /// Message length in bytes.
        len: u128,
    }

    impl Sha512 {
        pub(super) fn new() -> Self {
            Self {
                state: INIT,
                block: [0; 128],
                filled: 0,
                len: 0,
            }
        }

        pub(super) fn update(&mut self, mut data: &[u8]) {
            self.len = self.len.wrapping_add(data.len() as u128);
            while !data.is_empty() {
                let take = (128 - self.filled).min(data.len());
                self.block[self.filled..self.filled + take].copy_from_slice(&data[..take]);
                self.filled += take;
                data = &data[take..];
                if self.filled == 128 {
                    let block = self.block;
                    compress(&mut self.state, &block);
                    self.filled = 0;
                }
            }
        }

        pub(super) fn finalize(mut self) -> [u8; 64] {
            let bits = self.len.wrapping_mul(8);
            let mut pad = [0u8; 256];
            pad[0] = 0x80;
            // Pad to 112 mod 128, then the 128-bit big-endian bit length.
            let zeros = if self.filled < 112 {
                112 - self.filled
            } else {
                240 - self.filled
            };
            let mut tail = pad[..zeros].to_vec();
            tail.extend_from_slice(&bits.to_be_bytes());
            let len = self.len;
            self.update(&tail);
            self.len = len;
            let mut out = [0u8; 64];
            for (chunk, word) in out.as_chunks_mut::<8>().0.iter_mut().zip(self.state) {
                *chunk = word.to_be_bytes();
            }
            out
        }
    }

    fn compress(state: &mut [u64; 8], block: &[u8; 128]) {
        let mut w = [0u64; 80];
        for (word, chunk) in w.iter_mut().zip(block.as_chunks::<8>().0) {
            *word = u64::from_be_bytes(*chunk);
        }
        for i in 16..80 {
            let s0 = w[i - 15].rotate_right(1) ^ w[i - 15].rotate_right(8) ^ (w[i - 15] >> 7);
            let s1 = w[i - 2].rotate_right(19) ^ w[i - 2].rotate_right(61) ^ (w[i - 2] >> 6);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }
        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = *state;
        for i in 0..80 {
            let s1 = e.rotate_right(14) ^ e.rotate_right(18) ^ e.rotate_right(41);
            let ch = (e & f) ^ (!e & g);
            let t1 = h
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(28) ^ a.rotate_right(34) ^ a.rotate_right(39);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let t2 = s0.wrapping_add(maj);
            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }
        for (s, v) in state.iter_mut().zip([a, b, c, d, e, f, g, h]) {
            *s = s.wrapping_add(v);
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        fn hex(d: &[u8]) -> String {
            hex::encode(d)
        }

        #[test]
        fn fips_vectors() {
            let mut h = Sha512::new();
            h.update(b"abc");
            assert_eq!(
                hex(&h.finalize()),
                "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a\
                 2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"
            );
            assert_eq!(
                hex(&Sha512::new().finalize()),
                "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce\
                 47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
            );
            let mut h = Sha512::new();
            h.update(
                b"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmno\
                  ijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
            );
            assert_eq!(
                hex(&h.finalize()),
                "8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa17299aeadb6889018\
                 501d289e4900f7e4331b99dec4b5433ac7d329eeb6dd26545e96e55b874be909"
            );
        }

        #[test]
        fn split_updates_equal_one_update() {
            let data: Vec<u8> = (0..1000u32).map(|i| (i % 251) as u8).collect();
            let mut one = Sha512::new();
            one.update(&data);
            let mut many = Sha512::new();
            for chunk in data.chunks(37) {
                many.update(chunk);
            }
            assert_eq!(one.finalize(), many.finalize());
        }
    }
}

#[cfg(test)]
mod tests {
    use timescales_chain::{FileSigner, TxSigner};
    use timescales_core::Hash32;
    use timescales_core::crypto::Keypair;

    use super::*;

    fn signer(seed: [u8; 32]) -> FileSigner {
        let kp = Keypair::from_seed(seed);
        let mut bytes = Zeroizing::new([0u8; 64]);
        bytes[..32].copy_from_slice(&seed);
        bytes[32..].copy_from_slice(&kp.public());
        FileSigner::from_bytes(bytes).unwrap()
    }

    #[test]
    fn rfc8032_vectors() {
        let pk = <[u8; 32]>::try_from(
            hex::decode("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
                .unwrap(),
        )
        .unwrap();
        let sig = <[u8; 64]>::try_from(
            hex::decode(
                "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a3\
                 3bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
            )
            .unwrap(),
        )
        .unwrap();
        assert!(ed25519::verify_strict(&pk, b"", &sig));
        assert!(!ed25519::verify_strict(&pk, b"x", &sig));
    }

    #[test]
    fn agrees_with_the_signers_the_services_use() {
        // Raw-message signatures from the Solana keypair (ed25519-dalek).
        let s = signer([9; 32]);
        for len in [0usize, 1, 31, 32, 111, 112, 127, 128, 129, 300, 1024] {
            let msg: Vec<u8> = (0..len).map(|i| (i * 7 % 256) as u8).collect();
            let sig = s.sign(&msg);
            assert!(
                ed25519::verify_strict(&s.address(), &msg, &sig),
                "len {len}"
            );
            let mut bad = sig;
            bad[5] ^= 1;
            assert!(!ed25519::verify_strict(&s.address(), &msg, &bad));
            let mut other = msg.clone();
            other.push(0);
            assert!(!ed25519::verify_strict(&s.address(), &other, &sig));
        }
        // Digest signatures of the core crypto are signatures over 32
        // raw bytes.
        let kp = Keypair::from_seed([4; 32]);
        let d = Hash32([0x11; 32]);
        let sig = kp.sign_digest(&d);
        assert!(ed25519::verify_strict(&kp.public(), d.as_bytes(), &sig.0));
        let wrong = Keypair::from_seed([5; 32]);
        assert!(!ed25519::verify_strict(
            &wrong.public(),
            d.as_bytes(),
            &sig.0
        ));
    }

    #[test]
    fn non_canonical_s_and_small_order_keys_are_refused() {
        let s = signer([3; 32]);
        let msg = b"timescales";
        let sig = s.sign(msg);
        // S + L is the same scalar, but not canonical.
        let l: [u8; 32] =
            hex::decode("edd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010")
                .unwrap()
                .try_into()
                .unwrap();
        let mut high = sig;
        let mut carry = 0u16;
        for i in 0..32 {
            let v = u16::from(high[32 + i]) + u16::from(l[i]) + carry;
            high[32 + i] = (v & 0xff) as u8;
            carry = v >> 8;
        }
        if carry == 0 {
            assert!(!ed25519::verify_strict(&s.address(), msg, &high));
        }
        // The identity point as a public key is small order.
        let mut identity = [0u8; 32];
        identity[0] = 1;
        assert!(!ed25519::verify_strict(&identity, msg, &sig));
    }

    /// Edge cases of strict verification (small-order and mixed-order
    /// points, non-canonical point and scalar encodings), each checked
    /// against ed25519-dalek's `verify_strict`, which `verify_digest` runs
    /// over a 32-byte message.
    #[test]
    fn edge_cases_agree_with_dalek_verify_strict() {
        use timescales_core::crypto::threshold::{ScalarShare, decompress_canonical};
        use timescales_core::crypto::{Signature, verify_digest};

        let check = |what: &str, pk: &[u8; 32], msg: &[u8; 32], sig: &[u8; 64]| -> bool {
            let ours = ed25519::verify_strict(pk, msg, sig);
            let dalek = verify_digest(pk, &Hash32(*msg), &Signature(*sig)).is_ok();
            assert_eq!(ours, dalek, "{what}");
            ours
        };
        let sha = |parts: &[&[u8]]| {
            let mut h = sha512::Sha512::new();
            for p in parts {
                h.update(p);
            }
            h.finalize()
        };
        let mut one = [0u8; 32];
        one[0] = 1;
        let one = ScalarShare::from_bytes(1, &one).unwrap().value;
        let b = decompress_canonical(&ed25519::BASEPOINT).unwrap();
        let identity = (b * ed25519::reduce_le(&one, &[0])).compress().to_bytes();

        // A key whose secret scalar the test derives itself (RFC 8032 5.1.5).
        let seed = [7u8; 32];
        let kp = Keypair::from_seed(seed);
        let mut clamped = <[u8; 32]>::try_from(&sha(&[&seed])[..32]).unwrap();
        clamped[0] &= 248;
        clamped[31] &= 127;
        clamped[31] |= 64;
        let a = ed25519::reduce_le(&one, &clamped);
        assert_eq!((b * a).compress().to_bytes(), kp.public());

        let msg = [0x42u8; 32];
        let sig = kp.sign_digest(&Hash32(msg)).0;
        assert!(check("valid", &kp.public(), &msg, &sig));

        // An order-8 point: the torsion part of a point off the prime-order
        // subgroup.
        let inv8 = ed25519::reduce_le(&one, &[8]).invert();
        let four = ed25519::reduce_le(&one, &[4]);
        let t = (0u32..)
            .find_map(|c| {
                let mut y = <[u8; 32]>::try_from(&sha(&[&c.to_le_bytes()])[..32]).unwrap();
                y[31] &= 0x7f;
                let p = decompress_canonical(&y)?;
                let t = p - p.mul_by_cofactor() * inv8;
                ((t * four).compress().to_bytes() != identity).then_some(t)
            })
            .unwrap();
        let small: Vec<[u8; 32]> = (0u8..8)
            .map(|k| (t * ed25519::reduce_le(&one, &[k])).compress().to_bytes())
            .collect();
        assert_eq!(
            small
                .iter()
                .collect::<std::collections::BTreeSet<_>>()
                .len(),
            8
        );

        // y = p + j (j < 19) with either sign bit, and the sign bit set on
        // the two points with x = 0.
        let mut non_canonical = Vec::new();
        for j in 0u8..19 {
            let mut y = [0xffu8; 32];
            y[0] = 0xed + j;
            y[31] = 0x7f;
            non_canonical.push(y);
            y[31] = 0xff;
            non_canonical.push(y);
        }
        let mut neg_identity = identity;
        neg_identity[31] |= 0x80;
        non_canonical.push(neg_identity);
        let mut neg_order_two = [0xffu8; 32];
        neg_order_two[0] = 0xec;
        non_canonical.push(neg_order_two);

        for (i, point) in small.iter().chain(&non_canonical).enumerate() {
            let mut bad_r = sig;
            bad_r[..32].copy_from_slice(point);
            assert!(!check(&format!("R #{i}"), &kp.public(), &msg, &bad_r));
            assert!(!check(&format!("A #{i}"), point, &msg, &sig));
        }

        // S + L and an S with every bit set.
        let l: [u8; 32] =
            hex::decode("edd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010")
                .unwrap()
                .try_into()
                .unwrap();
        let mut high = sig;
        let mut carry = 0u16;
        for i in 0..32 {
            let v = u16::from(high[32 + i]) + u16::from(l[i]) + carry;
            high[32 + i] = (v & 0xff) as u8;
            carry = v >> 8;
        }
        assert_eq!(carry, 0);
        assert!(!check("S + L", &kp.public(), &msg, &high));
        let mut ones = sig;
        ones[32..].fill(0xff);
        assert!(!check("S = 2^256 - 1", &kp.public(), &msg, &ones));

        // A mixed-order key A + T. With k = H(R || A + T || M) a multiple of
        // eight, k*T vanishes and the cofactorless equation holds for a
        // signature made with A's secret. Otherwise it does not.
        let mixed = (b * a + t).compress().to_bytes();
        let (mut zero, mut nonzero) = (None, None);
        for c in 0u32.. {
            let r = ed25519::reduce_le(&one, &sha(&[b"nonce", &c.to_le_bytes()]));
            let r_enc = (b * r).compress().to_bytes();
            let k_bytes = sha(&[&r_enc, &mixed, &msg]);
            let k = ed25519::reduce_le(&one, &k_bytes);
            let mut forged = [0u8; 64];
            forged[..32].copy_from_slice(&r_enc);
            forged[32..].copy_from_slice(&(r + k * a).to_bytes());
            if k.to_bytes()[0] % 8 == 0 {
                zero.get_or_insert(forged);
            } else {
                nonzero.get_or_insert(forged);
            }
            if zero.is_some() && nonzero.is_some() {
                break;
            }
        }
        // verify_strict refuses small-order keys only. A mixed-order key
        // passes when the equation holds, in both implementations.
        assert!(check(
            "mixed-order key, k ≡ 0 mod 8",
            &mixed,
            &msg,
            &zero.unwrap()
        ));
        assert!(!check(
            "mixed-order key, k ≢ 0 mod 8",
            &mixed,
            &msg,
            &nonzero.unwrap()
        ));
    }

    #[test]
    fn replay_cache_fails_closed_and_expires() {
        let mut c = ReplayCache::default();
        let k = ([1; 32], 10, [2; 64]);
        assert!(c.insert(k, 100, 200));
        assert!(!c.insert(k, 150, 250));
        assert!(c.insert(k, 201, 300));
    }
}
