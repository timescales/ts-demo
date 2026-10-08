//! SIWS session grants, session request digests and stateless
//! session nonces.
//!
//! The canonical grant text is
//!
//! ```text
//! {domain} wants you to sign in with your Solana account:
//! {wallet base58}
//!
//! {statement}
//!
//! URI: {uri}
//! Version: 1
//! Chain ID: {localnet|devnet|mainnet}
//! Nonce: {32 hex}
//! Issued At: {RFC 3339 UTC, ms}
//! Expiration Time: {RFC 3339 UTC, ms}
//! Resources:
//! - timescales:session:{session key hex}
//! - timescales:program:{program base58}
//! - timescales:market:{market base58}
//! ```
//!
//! without a trailing newline. The market line is absent for an all-markets
//! grant. Wallets build the text themselves, so [`parse_session_message`]
//! follows the SIWS ABNF and accepts every variant the SDK's
//! `parseSessionMessage` accepts: no statement (with or without the extra
//! blank line), RFC 3339 times with any offset, lowercase `t`/`z` and up to
//! nine fractional digits (digits below the millisecond must be zero), a
//! `solana:`-prefixed chain id, an informational `Request ID`, and resources
//! in any order. It refuses CR, a trailing newline, out-of-order or repeated
//! fields, `Not Before`, a version other than 1, unknown or repeated
//! resources, non-canonical base58 and texts over 1024 bytes.

use hmac::{Hmac, Mac};
use rand_core::CryptoRngCore;
use sha2::{Digest, Sha256};
use timescales_core::Hash32;
use timescales_core::crypto::{Hasher, Keypair, Signature, domain, verify_digest};

use crate::wire::WireError;

/// The statement the SDK asks wallets to show.
pub const SESSION_STATEMENT: &str = "Authorize a Timescales trading session. This key can submit \
    encrypted orders for this wallet. Timescales executes only orders this wallet signs. It \
    cannot sign orders or move funds.";

/// Largest grant text.
pub const MAX_SESSION_TEXT_BYTES: usize = 1024;

const HEADER_SUFFIX: &str = " wants you to sign in with your Solana account:";
/// `9999-12-31T23:59:59.999Z`, the last instant a four-digit year can name.
const MAX_TIME_MS: u64 = 253_402_300_799_999;
const MS_PER_DAY: u64 = 86_400_000;

/// SIWS session grant. Parsed with the SIWS ABNF (field order fixed,
/// optional SIWS fields allowed). `render_session_message(g)` is the SDK's
/// canonical text. Any ABNF-conformant text with matching semantic fields is
/// accepted.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SessionGrant {
    pub domain: String,
    pub wallet: [u8; 32],
    pub statement: String,
    pub uri: String,
    pub chain_id: ChainId,
    pub nonce: [u8; 16],
    pub issued_at_ms: u64,
    pub expires_at_ms: u64,
    /// Always `None` from [`parse_session_message`], which refuses `Not
    /// Before` as the SDK does. [`SessionGrant::check`] refuses `Some`.
    pub not_before_ms: Option<u64>,
    pub session_key: [u8; 32],
    pub program: [u8; 32],
    pub market: Option<[u8; 32]>,
}

/// Text `"localnet"`, `"devnet"` or `"mainnet"` (cluster mainnet-beta).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChainId {
    Localnet,
    Devnet,
    Mainnet,
}

impl ChainId {
    pub fn as_str(self) -> &'static str {
        match self {
            ChainId::Localnet => "localnet",
            ChainId::Devnet => "devnet",
            ChainId::Mainnet => "mainnet",
        }
    }

    /// The bare name, or the SIWS form with a `solana:` prefix.
    pub fn parse(s: &str) -> Option<Self> {
        match s.strip_prefix("solana:").unwrap_or(s) {
            "localnet" => Some(ChainId::Localnet),
            "devnet" => Some(ChainId::Devnet),
            "mainnet" => Some(ChainId::Mainnet),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct GrantExpectations<'a> {
    pub domains: &'a [String],
    pub uri: &'a str,
    pub chain_id: ChainId,
    pub program: [u8; 32],
    pub now_ms: u64,
    pub max_ttl_ms: u64,
}

pub fn render_session_message(g: &SessionGrant) -> String {
    let mut lines = vec![
        format!("{}{HEADER_SUFFIX}", g.domain),
        bs58::encode(g.wallet).into_string(),
        String::new(),
    ];
    if !g.statement.is_empty() {
        lines.push(g.statement.clone());
        lines.push(String::new());
    }
    lines.push(format!("URI: {}", g.uri));
    lines.push("Version: 1".to_owned());
    // Wallets check a Chain ID against the network they are on and refuse a
    // text they cannot match. None of them knows a local validator, so a
    // localnet grant leaves the optional field out (and parses back as one).
    if g.chain_id != ChainId::Localnet {
        lines.push(format!("Chain ID: {}", g.chain_id.as_str()));
    }
    lines.push(format!("Nonce: {}", hex::encode(g.nonce)));
    lines.push(format!("Issued At: {}", rfc3339(g.issued_at_ms)));
    lines.push(format!("Expiration Time: {}", rfc3339(g.expires_at_ms)));
    if let Some(nb) = g.not_before_ms {
        lines.push(format!("Not Before: {}", rfc3339(nb)));
    }
    lines.push("Resources:".to_owned());
    lines.push(format!(
        "- timescales:session:{}",
        hex::encode(g.session_key)
    ));
    lines.push(format!(
        "- timescales:program:{}",
        bs58::encode(g.program).into_string()
    ));
    if let Some(m) = g.market {
        lines.push(format!(
            "- timescales:market:{}",
            bs58::encode(m).into_string()
        ));
    }
    lines.join("\n")
}

/// The fields after the statement, in ABNF order.
const FIELDS: [&str; 8] = [
    "URI: ",
    "Version: ",
    "Chain ID: ",
    "Nonce: ",
    "Issued At: ",
    "Expiration Time: ",
    "Not Before: ",
    "Request ID: ",
];
const URI: usize = 0;
const VERSION: usize = 1;
const CHAIN_ID: usize = 2;
const NONCE: usize = 3;
const ISSUED_AT: usize = 4;
const EXPIRATION_TIME: usize = 5;
const NOT_BEFORE: usize = 6;

fn is_field_line(line: &str) -> bool {
    line == "Resources:" || FIELDS.iter().any(|p| line.starts_with(p))
}

pub fn parse_session_message(text: &str) -> Result<SessionGrant, WireError> {
    let bad = WireError::Template;
    if text.len() > MAX_SESSION_TEXT_BYTES {
        return Err(bad("grant text exceeds 1024 bytes"));
    }
    if text.contains('\r') {
        return Err(bad("CR is not allowed"));
    }
    let lines: Vec<&str> = text.split('\n').collect();
    let header = lines[0];
    let domain = header
        .strip_suffix(HEADER_SUFFIX)
        .ok_or(bad("missing SIWS header line"))?;
    if !valid_domain(domain) {
        return Err(bad("invalid domain"));
    }
    let wallet = parse_address(lines.get(1).ok_or(bad("missing address"))?)?;
    let mut i = 2;

    let mut statement = "";
    if i < lines.len() {
        if !lines[i].is_empty() {
            return Err(bad("expected a blank line after the address"));
        }
        i += 1;
        let line = *lines.get(i).ok_or(bad("unexpected end of message"))?;
        if line.is_empty() {
            i += 1;
        } else if !is_field_line(line) {
            statement = line;
            i += 1;
            if lines.get(i).is_none_or(|l| !l.is_empty()) {
                return Err(bad("expected a blank line after the statement"));
            }
            i += 1;
        }
    }

    let mut values: [Option<&str>; 8] = [None; 8];
    let mut next_field = 0;
    while i < lines.len() && lines[i] != "Resources:" {
        let line = lines[i];
        let (at, value) = FIELDS
            .iter()
            .enumerate()
            .skip(next_field)
            .find_map(|(at, p)| line.strip_prefix(p).map(|v| (at, v)))
            .ok_or(bad("unexpected line"))?;
        if value.is_empty() {
            return Err(bad("empty field"));
        }
        values[at] = Some(value);
        next_field = at + 1;
        i += 1;
    }

    let mut resources = Vec::new();
    if lines.get(i) == Some(&"Resources:") {
        i += 1;
        for line in &lines[i..] {
            match line.strip_prefix("- ") {
                Some(r) if !r.is_empty() => resources.push(r),
                _ => return Err(bad("unexpected line")),
            }
        }
    }

    let required = |at: usize, missing: &'static str| values[at].ok_or(bad(missing));
    if values[NOT_BEFORE].is_some() {
        return Err(bad("Not Before is not supported in a session grant"));
    }
    let uri = required(URI, "missing URI")?;
    if !valid_uri(uri) {
        return Err(bad("invalid URI"));
    }
    if required(VERSION, "missing Version")? != "1" {
        return Err(bad("unsupported SIWS version"));
    }
    let chain_id = match values[CHAIN_ID] {
        None => ChainId::Localnet,
        Some(c) => match ChainId::parse(c).ok_or(bad("unsupported chain id"))? {
            // A localnet grant is written without the field. One way only.
            ChainId::Localnet => return Err(bad("a localnet grant has no Chain ID")),
            other => other,
        },
    };
    let nonce = lower_hex::<16>(required(NONCE, "missing Nonce")?)
        .ok_or(bad("nonce must be 32 lowercase hex digits"))?;
    let issued_at_ms = parse_time(required(ISSUED_AT, "missing Issued At")?)?;
    let expires_at_ms = parse_time(required(EXPIRATION_TIME, "missing Expiration Time")?)?;
    if expires_at_ms <= issued_at_ms {
        return Err(bad("expiration must follow issuance"));
    }

    let mut session_key = None;
    let mut program = None;
    let mut market = None;
    for r in resources {
        if let Some(k) = r.strip_prefix("timescales:session:") {
            if session_key.is_some() {
                return Err(bad("repeated session resource"));
            }
            session_key =
                Some(lower_hex::<32>(k).ok_or(bad("session key must be 64 lowercase hex digits"))?);
        } else if let Some(p) = r.strip_prefix("timescales:program:") {
            if program.is_some() {
                return Err(bad("repeated program resource"));
            }
            program = Some(parse_address(p)?);
        } else if let Some(m) = r.strip_prefix("timescales:market:") {
            if market.is_some() {
                return Err(bad("repeated market resource"));
            }
            market = Some(parse_address(m)?);
        } else {
            return Err(bad("unknown resource"));
        }
    }

    Ok(SessionGrant {
        domain: domain.to_owned(),
        wallet,
        statement: statement.to_owned(),
        uri: uri.to_owned(),
        chain_id,
        nonce,
        issued_at_ms,
        expires_at_ms,
        not_before_ms: None,
        session_key: session_key.ok_or(bad("missing session resource"))?,
        program: program.ok_or(bad("missing program resource"))?,
        market,
    })
}

impl SessionGrant {
    /// Domain, URI, chain, program, TTL and statement.
    ///
    /// The domain must be one of `domains` exactly (`Audience` otherwise).
    /// The statement is the canonical one or empty, because wallets may
    /// drop it. The lifetime may not exceed `max_ttl_ms`, measured from
    /// issuance and from `now`, so a grant dated in the future cannot
    /// outlive the limit (`Policy`). A grant at or past its expiry is
    /// `Expired`.
    pub fn check(&self, e: &GrantExpectations<'_>) -> Result<(), WireError> {
        if !e.domains.contains(&self.domain) {
            return Err(WireError::Audience);
        }
        if self.uri != e.uri {
            return Err(WireError::Template("URI is not this deployment's"));
        }
        if self.chain_id != e.chain_id {
            return Err(WireError::Template("chain id is not this deployment's"));
        }
        if self.program != e.program {
            return Err(WireError::Template("program is not this deployment's"));
        }
        if !self.statement.is_empty() && self.statement != SESSION_STATEMENT {
            return Err(WireError::Template("statement"));
        }
        if self.not_before_ms.is_some() {
            return Err(WireError::Template("Not Before is not supported"));
        }
        if self.expires_at_ms <= self.issued_at_ms {
            return Err(WireError::Template("expiration must follow issuance"));
        }
        if self.expires_at_ms - self.issued_at_ms > e.max_ttl_ms
            || self.expires_at_ms > e.now_ms.saturating_add(e.max_ttl_ms)
        {
            return Err(WireError::Policy("session lifetime exceeds the maximum"));
        }
        if e.now_ms >= self.expires_at_ms {
            return Err(WireError::Expired);
        }
        Ok(())
    }
}

/// `H(SESSION, "request" || method || 0x00 || path_and_query || 0x00 || ts u64 ||
/// SHA-256(body))`.
pub fn session_request_digest(
    method: &str,
    path_and_query: &str,
    ts_ms: u64,
    body: &[u8],
) -> Hash32 {
    Hasher::new(domain::SESSION)
        .chain(b"request")
        .chain(method.as_bytes())
        .chain(&[0])
        .chain(path_and_query.as_bytes())
        .chain(&[0])
        .chain(&ts_ms.to_le_bytes())
        .chain(&Sha256::digest(body))
        .finalize()
}

/// `Authorization: TimescalesSession <session_pk hex>.<ts_ms>.<sig hex>`,
/// where `sig` is the session key's signature over [`session_request_digest`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SessionAuthorization {
    pub session_key: [u8; 32],
    pub ts_ms: u64,
    pub signature: Signature,
}

impl SessionAuthorization {
    pub const SCHEME: &'static str = "TimescalesSession";

    pub fn sign(
        key: &Keypair,
        method: &str,
        path_and_query: &str,
        ts_ms: u64,
        body: &[u8],
    ) -> Self {
        SessionAuthorization {
            session_key: key.public(),
            ts_ms,
            signature: key.sign_digest(&session_request_digest(
                method,
                path_and_query,
                ts_ms,
                body,
            )),
        }
    }

    /// The header value.
    pub fn render(&self) -> String {
        format!(
            "{} {}.{}.{}",
            Self::SCHEME,
            hex::encode(self.session_key),
            self.ts_ms,
            hex::encode(self.signature.0)
        )
    }

    /// Parses a header value: the scheme exactly, one space, lowercase hex
    /// and a decimal timestamp without leading zeros.
    pub fn parse(header: &str) -> Result<Self, WireError> {
        let bad = || WireError::Template("not a TimescalesSession authorization");
        let rest = header
            .strip_prefix(Self::SCHEME)
            .and_then(|r| r.strip_prefix(' '))
            .ok_or_else(bad)?;
        let mut parts = rest.split('.');
        let (Some(pk), Some(ts), Some(sig), None) =
            (parts.next(), parts.next(), parts.next(), parts.next())
        else {
            return Err(bad());
        };
        let canonical_ts = !ts.is_empty()
            && ts.bytes().all(|b| b.is_ascii_digit())
            && (ts == "0" || !ts.starts_with('0'));
        if !canonical_ts {
            return Err(bad());
        }
        Ok(SessionAuthorization {
            session_key: lower_hex::<32>(pk).ok_or_else(bad)?,
            ts_ms: ts.parse().map_err(|_| bad())?,
            signature: Signature(lower_hex::<64>(sig).ok_or_else(bad)?),
        })
    }

    /// `|now - ts| <= skew` and the signature by `session_key`. That `ts`
    /// strictly increases per session is the caller's state to keep.
    pub fn verify(
        &self,
        method: &str,
        path_and_query: &str,
        body: &[u8],
        now_ms: u64,
        skew_ms: u64,
    ) -> Result<(), WireError> {
        if now_ms.abs_diff(self.ts_ms) > skew_ms {
            return Err(WireError::Skew {
                now_ms,
                issued_at_ms: self.ts_ms,
            });
        }
        let digest = session_request_digest(method, path_and_query, self.ts_ms, body);
        verify_digest(&self.session_key, &digest, &self.signature)
            .map_err(|_| WireError::BadSignature)
    }
}

type NonceMac = Hmac<Sha256>;

fn nonce_mac(key: &[u8; 32], issued_and_random: &[u8]) -> NonceMac {
    // HMAC takes keys of any length, so this cannot fail.
    let mut mac = NonceMac::new_from_slice(key).unwrap_or_else(|_| unreachable!());
    mac.update(domain::SESSION_NONCE);
    mac.update(issued_and_random);
    mac
}

/// Stateless nonce: issued_at_s u32 || random u32 ||
/// trunc8(HMAC-SHA256(nonce_key, SESSION_NONCE || issued_at_s || random)).
pub fn issue_session_nonce(key: &[u8; 32], now_ms: u64, rng: &mut impl CryptoRngCore) -> [u8; 16] {
    let issued_at_s = u32::try_from(now_ms / 1000).unwrap_or(u32::MAX);
    let mut nonce = [0u8; 16];
    nonce[..4].copy_from_slice(&issued_at_s.to_le_bytes());
    rng.fill_bytes(&mut nonce[4..8]);
    let tag = nonce_mac(key, &nonce[..8]).finalize().into_bytes();
    nonce[8..].copy_from_slice(&tag[..8]);
    nonce
}

/// The MAC (in constant time) first, so a forged nonce is `Nonce` whatever
/// its time. Then `Nonce` for one issued in the future and `Expired` for one
/// older than `ttl_ms`.
pub fn check_session_nonce(
    key: &[u8; 32],
    nonce: &[u8; 16],
    now_ms: u64,
    ttl_ms: u64,
) -> Result<(), WireError> {
    nonce_mac(key, &nonce[..8])
        .verify_truncated_left(&nonce[8..])
        .map_err(|_| WireError::Nonce)?;
    let mut issued_at_s = [0u8; 4];
    issued_at_s.copy_from_slice(&nonce[..4]);
    let issued_ms = u64::from(u32::from_le_bytes(issued_at_s)) * 1000;
    if issued_ms > now_ms {
        return Err(WireError::Nonce);
    }
    if now_ms - issued_ms > ttl_ms {
        return Err(WireError::Expired);
    }
    Ok(())
}

/// Exactly `2N` lowercase hex digits.
fn lower_hex<const N: usize>(s: &str) -> Option<[u8; N]> {
    if s.len() != 2 * N || !s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
        return None;
    }
    let mut out = [0u8; N];
    hex::decode_to_slice(s, &mut out).ok()?;
    Some(out)
}

/// A 32-byte key in canonical base58.
fn parse_address(s: &str) -> Result<[u8; 32], WireError> {
    let bytes = bs58::decode(s)
        .into_vec()
        .map_err(|_| WireError::Template("not a base58 public key"))?;
    let key = <[u8; 32]>::try_from(bytes.as_slice())
        .map_err(|_| WireError::Template("not a base58 public key"))?;
    if bs58::encode(key).into_string() != s {
        return Err(WireError::Template("not canonical base58"));
    }
    Ok(key)
}

/// `host [":" port]` as the SDK's `DOMAIN_RE` reads it: dot-separated LDH
/// labels or a bracketed IP literal, and at most five port digits.
fn valid_domain(s: &str) -> bool {
    let (host, port) = if s.starts_with('[') {
        match s.find(']') {
            Some(close) => s.split_at(close + 1),
            None => return false,
        }
    } else {
        match s.find(':') {
            Some(colon) => s.split_at(colon),
            None => (s, ""),
        }
    };
    let port_ok = port.is_empty()
        || port
            .strip_prefix(':')
            .is_some_and(|p| (1..=5).contains(&p.len()) && p.bytes().all(|b| b.is_ascii_digit()));
    let host_ok = match host.strip_prefix('[').and_then(|h| h.strip_suffix(']')) {
        Some(ip) => {
            !ip.is_empty()
                && ip
                    .bytes()
                    .all(|b| b.is_ascii_hexdigit() || b == b':' || b == b'.')
        }
        None => host.split('.').all(|label| {
            let b = label.as_bytes();
            !b.is_empty()
                && b[0].is_ascii_alphanumeric()
                && b[b.len() - 1].is_ascii_alphanumeric()
                && b.iter().all(|c| c.is_ascii_alphanumeric() || *c == b'-')
        }),
    };
    port_ok && host_ok
}

/// `scheme ":" 1*VCHAR`, the SDK's `URI_RE`.
fn valid_uri(s: &str) -> bool {
    let Some((scheme, rest)) = s.split_once(':') else {
        return false;
    };
    let mut scheme = scheme.bytes();
    scheme.next().is_some_and(|b| b.is_ascii_alphabetic())
        && scheme.all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'.' | b'-'))
        && !rest.is_empty()
        && rest.bytes().all(|b| (0x21..=0x7e).contains(&b))
}

/// `YYYY-MM-DDTHH:MM:SS.mmmZ`. A time past year 9999 is written with more
/// year digits, which [`parse_time`] refuses.
fn rfc3339(ms: u64) -> String {
    let (y, mo, d) = civil_from_days(ms / MS_PER_DAY);
    let in_day = ms % MS_PER_DAY;
    format!(
        "{y:04}-{mo:02}-{d:02}T{:02}:{:02}:{:02}.{:03}Z",
        in_day / 3_600_000,
        in_day / 60_000 % 60,
        in_day / 1000 % 60,
        in_day % 1000
    )
}

/// RFC 3339 `date-time` to Unix milliseconds:
/// `YYYY-MM-DD[Tt]HH:MM:SS[.1-9 digits]([Zz]|[+-]HH:MM)`. The date must
/// exist, seconds stop at 59 (no leap seconds), digits below the
/// millisecond must be zero, and the instant must lie in
/// `1970-01-01T00:00:00Z..= 9999-12-31T23:59:59.999Z`.
fn parse_time(s: &str) -> Result<u64, WireError> {
    let bad = || WireError::Template("not an RFC 3339 timestamp");
    let b = s.as_bytes();
    let digits = |from: usize, len: usize| -> Option<u64> {
        let part = b.get(from..from + len)?;
        part.iter().try_fold(0u64, |acc, c| {
            c.is_ascii_digit().then(|| acc * 10 + u64::from(c - b'0'))
        })
    };
    let at = |i: usize, allowed: &[u8]| b.get(i).is_some_and(|c| allowed.contains(c));
    if !(at(4, b"-") && at(7, b"-") && at(10, b"Tt") && at(13, b":") && at(16, b":")) {
        return Err(bad());
    }
    let year = digits(0, 4).ok_or_else(bad)?;
    let month = digits(5, 2).ok_or_else(bad)?;
    let day = digits(8, 2).ok_or_else(bad)?;
    let hour = digits(11, 2).ok_or_else(bad)?;
    let minute = digits(14, 2).ok_or_else(bad)?;
    let second = digits(17, 2).ok_or_else(bad)?;

    let mut i = 19;
    let mut millis = 0;
    if b.get(i) == Some(&b'.') {
        let start = i + 1;
        let len = b[start..].iter().take_while(|c| c.is_ascii_digit()).count();
        if !(1..=9).contains(&len) {
            return Err(bad());
        }
        let frac = &b[start..start + len];
        if frac.iter().skip(3).any(|c| *c != b'0') {
            return Err(WireError::Template("sub-millisecond precision"));
        }
        millis = frac
            .iter()
            .chain(std::iter::repeat(&b'0'))
            .take(3)
            .fold(0, |acc, c| acc * 10 + u64::from(c - b'0'));
        i = start + len;
    }
    let offset_minutes: i64 = match b.get(i..) {
        Some([b'Z' | b'z']) => 0,
        Some([sign @ (b'+' | b'-'), _, _, b':', _, _]) => {
            let oh = digits(i + 1, 2).ok_or_else(bad)?;
            let om = digits(i + 4, 2).ok_or_else(bad)?;
            if oh > 23 || om > 59 {
                return Err(bad());
            }
            let minutes = i64::try_from(oh * 60 + om).map_err(|_| bad())?;
            if *sign == b'-' { -minutes } else { minutes }
        }
        _ => return Err(bad()),
    };

    if !(1..=12).contains(&month)
        || day == 0
        || day > days_in_month(year, month)
        || hour > 23
        || minute > 59
        || second > 59
    {
        return Err(WireError::Template("invalid date or time"));
    }
    let local_ms = days_from_civil(year, month, day) * 86_400_000
        + i64::try_from((hour * 3600 + minute * 60 + second) * 1000 + millis).map_err(|_| bad())?;
    let utc_ms = local_ms - offset_minutes * 60_000;
    u64::try_from(utc_ms)
        .ok()
        .filter(|t| *t <= MAX_TIME_MS)
        .ok_or(WireError::Template("time out of range"))
}

fn days_in_month(year: u64, month: u64) -> u64 {
    match month {
        2 if year.is_multiple_of(4) && (!year.is_multiple_of(100) || year.is_multiple_of(400)) => {
            29
        }
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    }
}

/// Days since 1970-01-01 of a proleptic Gregorian date (H. Hinnant's
/// `days_from_civil`). Negative before 1970.
fn days_from_civil(year: u64, month: u64, day: u64) -> i64 {
    let y = i64::try_from(year).unwrap_or(i64::MAX) - i64::from(month <= 2);
    let m = i64::try_from(month).unwrap_or(0);
    let d = i64::try_from(day).unwrap_or(0);
    let era = y.div_euclid(400);
    let yoe = y.rem_euclid(400);
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// The date `days` after 1970-01-01 (H. Hinnant's `civil_from_days`).
fn civil_from_days(days: u64) -> (u64, u64, u64) {
    let z = days + 719_468;
    let era = z / 146_097;
    let doe = z % 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + u64::from(month <= 2);
    (year, month, day)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn localnet_grants_carry_no_chain_id() {
        let grant = |chain_id| SessionGrant {
            domain: "localhost:4173".to_owned(),
            wallet: [7; 32],
            statement: String::new(),
            uri: "http://localhost:4173".to_owned(),
            chain_id,
            nonce: [1; 16],
            issued_at_ms: 1_791_374_400_000,
            expires_at_ms: 1_791_378_000_000,
            not_before_ms: None,
            session_key: [2; 32],
            program: [3; 32],
            market: None,
        };
        let local = render_session_message(&grant(ChainId::Localnet));
        assert!(!local.contains("Chain ID"));
        assert_eq!(
            parse_session_message(&local).unwrap().chain_id,
            ChainId::Localnet
        );
        let devnet = render_session_message(&grant(ChainId::Devnet));
        assert!(devnet.contains("Chain ID: devnet"));
        assert_eq!(
            parse_session_message(&devnet).unwrap().chain_id,
            ChainId::Devnet
        );
        // Written one way only.
        let explicit = devnet.replace("Chain ID: devnet", "Chain ID: localnet");
        assert!(parse_session_message(&explicit).is_err());
    }

    #[test]
    fn calendar_conversions_invert() {
        for days in [0u64, 1, 59, 60, 365, 11_016, 19_000, 2_932_896] {
            let (y, m, d) = civil_from_days(days);
            assert_eq!(days_from_civil(y, m, d), i64::try_from(days).unwrap());
        }
        assert_eq!(civil_from_days(0), (1970, 1, 1));
        assert_eq!(civil_from_days(11_016), (2000, 2, 29));
        assert_eq!(days_from_civil(1969, 12, 31), -1);
        assert_eq!(rfc3339(MAX_TIME_MS), "9999-12-31T23:59:59.999Z");
        assert_eq!(rfc3339(MAX_TIME_MS + 1), "10000-01-01T00:00:00.000Z");
        assert!(parse_time(&rfc3339(MAX_TIME_MS + 1)).is_err());
    }

    #[test]
    fn times_parse_like_the_sdk() {
        let t = |s: &str| parse_time(s).ok();
        assert_eq!(t("1970-01-01T00:00:00Z"), Some(0));
        assert_eq!(t("2026-10-07T12:00:00.123Z"), Some(1_791_374_400_123));
        assert_eq!(t("2026-10-07t12:00:00.123z"), Some(1_791_374_400_123));
        assert_eq!(t("2026-10-07T14:30:00.123+02:30"), Some(1_791_374_400_123));
        assert_eq!(t("2026-10-07T12:00:00.123000000Z"), Some(1_791_374_400_123));
        assert_eq!(t("2026-10-07T12:00:00.1Z"), Some(1_791_374_400_100));
        assert_eq!(t("1969-12-31T23:59:59-00:01"), Some(59_000));
        assert_eq!(t("9999-12-31T23:59:59.999Z"), Some(MAX_TIME_MS));
        for bad in [
            "1969-12-31T23:59:59Z",
            "9999-12-31T23:59:59.999-00:01",
            "2026-10-07T12:00:00.1234Z",
            "2026-10-07T12:00:00.Z",
            "2026-10-07T12:00:00.0000000000Z",
            "2026-02-29T12:00:00Z",
            "2026-12-31T23:59:60Z",
            "2026-13-01T00:00:00Z",
            "2026-00-01T00:00:00Z",
            "2026-01-00T00:00:00Z",
            "2026-01-01T24:00:00Z",
            "2026-01-01T00:60:00Z",
            "2026-01-01T00:00:00+24:00",
            "2026-01-01T00:00:00+00:60",
            "2026-01-01T00:00:00",
            "2026-01-01 00:00:00Z",
            "2026-1-01T00:00:00Z",
            "+2026-01-01T00:00:00Z",
            "2026-01-01T00:00:00Zz",
            "2026-01-01T00:00:00+0000",
            "２026-01-01T00:00:00Z",
        ] {
            assert_eq!(t(bad), None, "{bad}");
        }
        assert_eq!(t("2024-02-29T00:00:00Z"), Some(1_709_164_800_000));
        assert_eq!(t("2000-02-29T00:00:00Z"), Some(951_782_400_000));
        assert_eq!(t("2100-02-29T00:00:00Z"), None);
    }

    #[test]
    fn domains_follow_the_sdk_pattern() {
        for ok in [
            "app.timescales.example",
            "localhost",
            "localhost:4173",
            "a",
            "a-b.c",
            "[::1]",
            "[::1]:8080",
            "127.0.0.1:99999",
            "xn--bcher-kva.example",
        ] {
            assert!(valid_domain(ok), "{ok}");
        }
        for bad in [
            "",
            "-a.example",
            "a-.example",
            "a..b",
            "a.",
            ".a",
            "a_b.example",
            "app.example/x",
            "app.example:",
            "app.example:123456",
            "app.example:1:2",
            "[]",
            "[::1",
            "[::g]",
            "bad domain",
            "üñí.example",
        ] {
            assert!(!valid_domain(bad), "{bad}");
        }
    }

    #[test]
    fn uris_follow_the_sdk_pattern() {
        for ok in [
            "https://app.timescales.example",
            "http://localhost:5173",
            "a:b",
            "x+y.z-w:/",
        ] {
            assert!(valid_uri(ok), "{ok}");
        }
        for bad in [
            "",
            "https",
            "https:",
            "1http://x",
            "ht_tp://x",
            "https://a b",
            "https://é",
        ] {
            assert!(!valid_uri(bad), "{bad}");
        }
    }
}
