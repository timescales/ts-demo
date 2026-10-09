//! The authenticated envelope every internal request and response travels in.
//!
//! ```text
//! prefix (94) = ver u8 || kind u8 || sender32 || audience32 || issued_at_ms u64 || nonce16 || u32 len
//! envelope    = prefix || body (len <= kind.max_body) || sig64
//! ```
//!
//! The signature is the sender's over `H(RPC_ENVELOPE, prefix || body)`. A
//! receiver reads the fixed prefix first and checks version, kind, length,
//! audience and sender with [`EnvelopePrefix::check`] before it reads a
//! single body byte. [`SignedEnvelope::open`] then verifies the signature and
//! the clock skew, and a [`ReplayGuard`] rejects repeats.

use std::collections::{BTreeSet, HashSet};

use parking_lot::Mutex;
use rand_core::CryptoRngCore;
use timescales_core::crypto::{Hasher, Keypair, Signature, domain, hash, verify_digest};
use timescales_core::{Decode, DecodeError, Encode, Reader};

pub const WIRE_VERSION: u8 = 1;

/// Length of the envelope prefix: version, kind, sender, audience,
/// issued_at, nonce and body length.
pub const PREFIX_LEN: usize = 94;

#[derive(Debug, thiserror::Error)]
pub enum WireError {
    #[error("decode: {0}")]
    Decode(#[from] DecodeError),
    #[error("unsupported wire version {0}")]
    Version(u8),
    #[error("unknown message kind {0}")]
    Kind(u8),
    #[error("signature invalid")]
    BadSignature,
    #[error("envelope addressed to another party")]
    Audience,
    #[error("sender not allowed for this message kind")]
    Sender,
    #[error("body of {len} bytes exceeds {max}")]
    TooLarge { len: u32, max: u32 },
    #[error("clock skew: now {now_ms} ms, issued at {issued_at_ms} ms")]
    Skew { now_ms: u64, issued_at_ms: u64 },
    #[error("replayed envelope")]
    Replay,
    #[error("replay guard full")]
    ReplayGuardFull,
    #[error("{got} of {need} required acknowledgements")]
    Threshold { got: u8, need: u8 },
    #[error("unknown committee member {0}")]
    UnknownMember(u8),
    #[error("committee digest mismatch")]
    CommitteeMismatch,
    #[error("invalid committee: {0}")]
    Committee(&'static str),
    #[error("key scheme not allowed")]
    Scheme,
    #[error("invalid curve point: {0}")]
    BadPoint(&'static str),
    #[error("session message does not follow the template: {0}")]
    Template(&'static str),
    #[error("expired")]
    Expired,
    #[error("invalid nonce")]
    Nonce,
    #[error("policy: {0}")]
    Policy(&'static str),
}

#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum MessageKind {
    ShareDelivery = 1,
    EpochKeyAck = 2,
    ChallengeRequest = 3,
    ChallengeResponse = 4,
    ReleaseRequest = 5,
    ReleaseResponse = 6,
    ExecuteRequest = 7,
    ExecuteReady = 8,
    KeyBundlePut = 9,
    Empty = 10,
    ErrorResponse = 11,
    PublishRequest = 12,
    ExecutePosted = 13,
    AnnouncementQuery = 14,
    AnnouncementReply = 15,
}

impl MessageKind {
    pub const ALL: [MessageKind; 15] = [
        MessageKind::ShareDelivery,
        MessageKind::EpochKeyAck,
        MessageKind::ChallengeRequest,
        MessageKind::ChallengeResponse,
        MessageKind::ReleaseRequest,
        MessageKind::ReleaseResponse,
        MessageKind::ExecuteRequest,
        MessageKind::ExecuteReady,
        MessageKind::KeyBundlePut,
        MessageKind::Empty,
        MessageKind::ErrorResponse,
        MessageKind::PublishRequest,
        MessageKind::ExecutePosted,
        MessageKind::AnnouncementQuery,
        MessageKind::AnnouncementReply,
    ];

    /// Largest body accepted for this kind.
    pub const fn max_body(self) -> usize {
        match self {
            MessageKind::ShareDelivery => 2 * 1024,
            MessageKind::EpochKeyAck => 128,
            MessageKind::ChallengeRequest | MessageKind::ChallengeResponse => 256,
            MessageKind::ReleaseRequest => 18 * 1024,
            MessageKind::ReleaseResponse => 512,
            MessageKind::ExecuteRequest => 16 * 1024 * 1024,
            MessageKind::ExecuteReady => 8 * 1024,
            MessageKind::PublishRequest => 1024,
            MessageKind::ExecutePosted => 8 * 1024 * 1024,
            MessageKind::KeyBundlePut => 4 * 1024,
            MessageKind::AnnouncementQuery => 64,
            MessageKind::AnnouncementReply => 1024,
            MessageKind::Empty => 0,
            MessageKind::ErrorResponse => 512,
        }
    }

    pub const fn from_u8(tag: u8) -> Option<Self> {
        Some(match tag {
            1 => MessageKind::ShareDelivery,
            2 => MessageKind::EpochKeyAck,
            3 => MessageKind::ChallengeRequest,
            4 => MessageKind::ChallengeResponse,
            5 => MessageKind::ReleaseRequest,
            6 => MessageKind::ReleaseResponse,
            7 => MessageKind::ExecuteRequest,
            8 => MessageKind::ExecuteReady,
            9 => MessageKind::KeyBundlePut,
            10 => MessageKind::Empty,
            11 => MessageKind::ErrorResponse,
            12 => MessageKind::PublishRequest,
            13 => MessageKind::ExecutePosted,
            14 => MessageKind::AnnouncementQuery,
            15 => MessageKind::AnnouncementReply,
            _ => return None,
        })
    }

    /// Largest HTTP body that can carry an envelope of this kind.
    pub const fn max_envelope_len(self) -> usize {
        PREFIX_LEN + self.max_body() + 64
    }
}

/// Signs envelope bytes. Implemented by `Keypair` (services) and by
/// `timescales_executor::tee::Enclave` (typed, see), so the executor key
/// never leaves the enclave and is never a raw digest-signing oracle.
/// `sign_envelope` always signs H(RPC_ENVELOPE, bytes_before_sig). The
/// domain is fixed inside the implementation.
pub trait EnvelopeSigner: Send + Sync {
    fn public(&self) -> [u8; 32];
    fn sign_envelope(&self, bytes_before_sig: &[u8]) -> Signature;
}

impl EnvelopeSigner for Keypair {
    fn public(&self) -> [u8; 32] {
        Keypair::public(self)
    }

    fn sign_envelope(&self, bytes_before_sig: &[u8]) -> Signature {
        self.sign_digest(&hash(domain::RPC_ENVELOPE, bytes_before_sig))
    }
}

// Implemented here rather than in timescales-enclave, which owns neither the
// trait nor the type.
impl EnvelopeSigner for timescales_executor::tee::Enclave {
    fn public(&self) -> [u8; 32] {
        self.executor_id().0
    }

    fn sign_envelope(&self, bytes_before_sig: &[u8]) -> Signature {
        self.sign_rpc_envelope(bytes_before_sig)
    }
}

/// Authenticated envelope for every internal request and response (HTTP
/// body, `application/vnd.timescales.envelope`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedEnvelope {
    pub version: u8,
    pub kind: MessageKind,
    pub sender: [u8; 32],
    pub audience: [u8; 32],
    pub issued_at_ms: u64,
    pub nonce: [u8; 16],
    pub body: Vec<u8>,
    pub signature: Signature,
}

/// The fixed 94-byte prefix (version, kind, sender, audience, issued_at,
/// nonce, body length). Parsed before the body is read.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EnvelopePrefix {
    pub version: u8,
    pub kind: MessageKind,
    pub sender: [u8; 32],
    pub audience: [u8; 32],
    pub issued_at_ms: u64,
    pub nonce: [u8; 16],
    pub body_len: u32,
}

impl EnvelopePrefix {
    /// Version, kind and length only. No allocation. Most receivers want
    /// [`EnvelopePrefix::check`], which also checks audience and sender.
    pub fn parse(prefix: &[u8; PREFIX_LEN]) -> Result<Self, WireError> {
        let mut r = Reader::new(prefix);
        let version = r.u8()?;
        if version != WIRE_VERSION {
            return Err(WireError::Version(version));
        }
        let tag = r.u8()?;
        let kind = MessageKind::from_u8(tag).ok_or(WireError::Kind(tag))?;
        let sender = r.array()?;
        let audience = r.array()?;
        let issued_at_ms = r.u64()?;
        let nonce = r.array()?;
        let body_len = r.u32()?;
        check_body_len(kind, body_len)?;
        Ok(EnvelopePrefix {
            version,
            kind,
            sender,
            audience,
            issued_at_ms,
            nonce,
            body_len,
        })
    }

    /// version, kind known, body_len <= kind.max_body, audience == me,
    /// sender allowed. No allocation.
    pub fn check(
        prefix: &[u8; PREFIX_LEN],
        me: &[u8; 32],
        allowed: &dyn Fn(&[u8; 32], MessageKind) -> bool,
    ) -> Result<Self, WireError> {
        let p = Self::parse(prefix)?;
        if &p.audience != me {
            return Err(WireError::Audience);
        }
        if !allowed(&p.sender, p.kind) {
            return Err(WireError::Sender);
        }
        Ok(p)
    }

    pub fn to_bytes(&self) -> [u8; PREFIX_LEN] {
        let mut p = [0u8; PREFIX_LEN];
        p[0] = self.version;
        p[1] = self.kind as u8;
        p[2..34].copy_from_slice(&self.sender);
        p[34..66].copy_from_slice(&self.audience);
        p[66..74].copy_from_slice(&self.issued_at_ms.to_le_bytes());
        p[74..90].copy_from_slice(&self.nonce);
        p[90..94].copy_from_slice(&self.body_len.to_le_bytes());
        p
    }
}

fn check_body_len(kind: MessageKind, len: u32) -> Result<(), WireError> {
    let max = kind.max_body();
    if usize::try_from(len).unwrap_or(usize::MAX) > max {
        return Err(WireError::TooLarge {
            len,
            max: u32::try_from(max).unwrap_or(u32::MAX),
        });
    }
    Ok(())
}

impl SignedEnvelope {
    /// Prefix and signature of an empty body.
    pub const MIN_ENCODED_LEN: usize = PREFIX_LEN + 64;

    pub fn seal(
        kind: MessageKind,
        signer: &dyn EnvelopeSigner,
        audience: [u8; 32],
        now_ms: u64,
        rng: &mut impl CryptoRngCore,
        body: Vec<u8>,
    ) -> Self {
        let mut nonce = [0u8; 16];
        rng.fill_bytes(&mut nonce);
        let mut env = SignedEnvelope {
            version: WIRE_VERSION,
            kind,
            sender: signer.public(),
            audience,
            issued_at_ms: now_ms,
            nonce,
            body,
            signature: Signature([0; 64]),
        };
        env.signature = signer.sign_envelope(&env.bytes_before_sig());
        env
    }

    /// The prefix this envelope encodes with. A body longer than `u32::MAX`
    /// bytes is described as `u32::MAX`, which every kind refuses.
    pub fn prefix(&self) -> EnvelopePrefix {
        EnvelopePrefix {
            version: self.version,
            kind: self.kind,
            sender: self.sender,
            audience: self.audience,
            issued_at_ms: self.issued_at_ms,
            nonce: self.nonce,
            body_len: u32::try_from(self.body.len()).unwrap_or(u32::MAX),
        }
    }

    /// `prefix || body`: what the signature covers, under `RPC_ENVELOPE`.
    pub fn bytes_before_sig(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(PREFIX_LEN + self.body.len());
        out.extend_from_slice(&self.prefix().to_bytes());
        out.extend_from_slice(&self.body);
        out
    }

    /// [`Self::from_prefix`] over the tail as it arrived: the body keeps
    /// that buffer and only the signature is split off, so a request body
    /// is not copied a second time.
    pub fn from_prefix_owned(
        prefix: &EnvelopePrefix,
        mut tail: Vec<u8>,
    ) -> Result<Self, WireError> {
        check_body_len(prefix.kind, prefix.body_len)?;
        let body_len = usize::try_from(prefix.body_len).unwrap_or(usize::MAX);
        if tail.len() < body_len {
            return Self::from_prefix(prefix, &tail);
        }
        let sig = tail.split_off(body_len);
        let mut r = Reader::new(&sig);
        let signature = Signature::decode(&mut r)?;
        r.finish()?;
        Ok(SignedEnvelope {
            version: prefix.version,
            kind: prefix.kind,
            sender: prefix.sender,
            audience: prefix.audience,
            issued_at_ms: prefix.issued_at_ms,
            nonce: prefix.nonce,
            body: tail,
            signature,
        })
    }

    /// The envelope whose prefix was already read and checked, from the
    /// `body_len + 64` bytes that follow it.
    pub fn from_prefix(prefix: &EnvelopePrefix, rest: &[u8]) -> Result<Self, WireError> {
        check_body_len(prefix.kind, prefix.body_len)?;
        let body_len = usize::try_from(prefix.body_len).unwrap_or(usize::MAX);
        let mut r = Reader::new(rest);
        let body = r.take(body_len)?.to_vec();
        let signature = Signature::decode(&mut r)?;
        r.finish()?;
        Ok(SignedEnvelope {
            version: prefix.version,
            kind: prefix.kind,
            sender: prefix.sender,
            audience: prefix.audience,
            issued_at_ms: prefix.issued_at_ms,
            nonce: prefix.nonce,
            body,
            signature,
        })
    }

    /// Prefix checks + verify_strict + |now - issued_at| <= skew. Replay is
    /// the caller's [`ReplayGuard`].
    pub fn open(
        &self,
        me: &[u8; 32],
        allowed: &dyn Fn(&[u8; 32], MessageKind) -> bool,
        now_ms: u64,
        skew_ms: u64,
    ) -> Result<&[u8], WireError> {
        if self.version != WIRE_VERSION {
            return Err(WireError::Version(self.version));
        }
        check_body_len(self.kind, self.prefix().body_len)?;
        if &self.audience != me {
            return Err(WireError::Audience);
        }
        if !allowed(&self.sender, self.kind) {
            return Err(WireError::Sender);
        }
        if now_ms.abs_diff(self.issued_at_ms) > skew_ms {
            return Err(WireError::Skew {
                now_ms,
                issued_at_ms: self.issued_at_ms,
            });
        }
        let digest = Hasher::new(domain::RPC_ENVELOPE)
            .chain(&self.prefix().to_bytes())
            .chain(&self.body)
            .finalize();
        verify_digest(&self.sender, &digest, &self.signature)
            .map_err(|_| WireError::BadSignature)?;
        Ok(&self.body)
    }
}

impl Encode for SignedEnvelope {
    fn encode(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.prefix().to_bytes());
        out.extend_from_slice(&self.body);
        self.signature.encode(out);
    }
}

impl Decode for SignedEnvelope {
    fn decode(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        let prefix: [u8; PREFIX_LEN] = r.array()?;
        let p = EnvelopePrefix::parse(&prefix).map_err(|e| match e {
            WireError::Version(_) => DecodeError::InvalidValue("SignedEnvelope.version"),
            WireError::Kind(tag) => DecodeError::InvalidTag {
                ty: "MessageKind",
                tag,
            },
            WireError::TooLarge { len, max } => DecodeError::LengthExceeded {
                len: usize::try_from(len).unwrap_or(usize::MAX),
                max: usize::try_from(max).unwrap_or(usize::MAX),
            },
            WireError::Decode(d) => d,
            _ => DecodeError::InvalidValue("SignedEnvelope"),
        })?;
        let body_len = usize::try_from(p.body_len).unwrap_or(usize::MAX);
        Ok(SignedEnvelope {
            version: p.version,
            kind: p.kind,
            sender: p.sender,
            audience: p.audience,
            issued_at_ms: p.issued_at_ms,
            nonce: p.nonce,
            body: r.take(body_len)?.to_vec(),
            signature: Signature::decode(r)?,
        })
    }
}

/// Bounded set of (sender, nonce) within 2 x skew. When full it **fails
/// closed** (`ReplayGuardFull` -> 503), never evicts live entries.
///
/// An entry lives through `issued_at + window`. An envelope issued more
/// than `window` before or after `now` is refused with `Skew`: the guard
/// could not remember it for long enough, or would have to remember it too
/// long. So every accepted (sender, nonce) is remembered for as long as it
/// could be accepted again.
pub struct ReplayGuard {
    capacity: usize,
    window_ms: u64,
    seen: Mutex<Seen>,
}

#[derive(Default)]
struct Seen {
    live: HashSet<ReplayKey>,
    /// `(expires_at, key)`, so expired entries come off the front.
    expiry: BTreeSet<(u64, ReplayKey)>,
}

type ReplayKey = ([u8; 32], [u8; 16]);

impl core::fmt::Debug for ReplayGuard {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ReplayGuard")
            .field("capacity", &self.capacity)
            .field("window_ms", &self.window_ms)
            .field("live", &self.seen.lock().live.len())
            .finish()
    }
}

impl ReplayGuard {
    pub fn new(capacity: usize, window_ms: u64) -> Self {
        Self {
            capacity,
            window_ms,
            seen: Mutex::new(Seen::default()),
        }
    }

    pub fn check_and_insert(
        &self,
        sender: &[u8; 32],
        nonce: &[u8; 16],
        issued_at_ms: u64,
        now_ms: u64,
    ) -> Result<(), WireError> {
        if now_ms.abs_diff(issued_at_ms) > self.window_ms {
            return Err(WireError::Skew {
                now_ms,
                issued_at_ms,
            });
        }
        let expires_at = issued_at_ms.saturating_add(self.window_ms);
        let key = (*sender, *nonce);
        let mut seen = self.seen.lock();
        while let Some(&(at, k)) = seen.expiry.first() {
            if at >= now_ms {
                break;
            }
            seen.expiry.pop_first();
            seen.live.remove(&k);
        }
        if seen.live.contains(&key) {
            return Err(WireError::Replay);
        }
        if seen.live.len() >= self.capacity {
            return Err(WireError::ReplayGuardFull);
        }
        seen.live.insert(key);
        seen.expiry.insert((expires_at, key));
        Ok(())
    }

    /// Entries currently remembered (expired ones are dropped lazily).
    pub fn len(&self) -> usize {
        self.seen.lock().live.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use timescales_core::Hash32;
    use timescales_core::crypto::verify_digest;
    use timescales_executor::attestation::{Evidence, Measurement, Platform};
    use timescales_executor::tee::{Enclave, Quoter};

    use super::*;

    struct NoQuotes;

    impl Quoter for NoQuotes {
        fn quote(&self, _: Measurement, _: bool, _: [u8; 64]) -> Evidence {
            Evidence {
                platform: Platform::Simulated,
                quote: Vec::new(),
            }
        }
    }

    #[test]
    fn enclave_signs_envelopes_under_the_rpc_domain_with_its_executor_key() {
        let enclave: Arc<dyn EnvelopeSigner> = Arc::new(Enclave::boot(
            Arc::new(NoQuotes),
            Measurement(Hash32::ZERO),
            false,
        ));
        let bytes = b"bytes before the signature";
        let sig = enclave.sign_envelope(bytes);
        verify_digest(&enclave.public(), &hash(domain::RPC_ENVELOPE, bytes), &sig).unwrap();
    }

    #[test]
    fn expired_entries_leave_the_guard_in_expiry_order() {
        let g = ReplayGuard::new(8, 100);
        for i in 0..4u8 {
            g.check_and_insert(&[i; 32], &[0; 16], 1_000 + u64::from(i) * 10, 1_000)
                .unwrap();
        }
        assert_eq!(g.len(), 4);
        // The first entry expires at 1_100: kept at 1_100, gone at 1_101.
        assert!(matches!(
            g.check_and_insert(&[0; 32], &[0; 16], 1_000, 1_100),
            Err(WireError::Replay)
        ));
        g.check_and_insert(&[9; 32], &[0; 16], 1_101, 1_101)
            .unwrap();
        assert_eq!(g.len(), 4);
        g.check_and_insert(&[10; 32], &[0; 16], 1_131, 1_131)
            .unwrap();
        assert_eq!(g.len(), 2);
    }
}
