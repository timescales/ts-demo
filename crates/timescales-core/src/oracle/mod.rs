//! Reference prices.
//!
//! ```text
//! External API -> TLS proof -> selective claim -> PriceCommitment -> band
//! ```
//!
//! Each configured source is a server plus the JSON field holding its
//! price. A source's claim is accepted only from a verified
//! [`Presentation`](crate::tls_proof::Presentation) of that server. The
//! reference tick is the median of the accepted claims, and the spread
//! between claims must stay within a configured bound, so one wrong source
//! moves nothing and many disagreeing sources stop the epoch instead of
//! producing an arbitrary band.
//!
//! A TLS proof shows what a server said. It does not show the server was
//! right: a source that publishes a manipulated price passes verification.
//! The median and the dispersion bound are the only defences, and both
//! assume most sources are honest.
//!
//! Prices are parsed as decimal strings straight into integers. No floating
//! point is involved.

#![cfg_attr(test, allow(clippy::unwrap_used, clippy::cast_possible_truncation))]

pub mod codec;

use crate::crypto::{Hasher, domain};
use crate::tls_proof::{Presentation, TlsProofError, Trust, verify};
use crate::{Encode, EpochId, Hash32, MarketId, Tick};
use thiserror::Error;

/// Whether this build includes simulation-only components.
pub const SIMULATION_BUILD: bool = cfg!(feature = "simulation");

#[cfg(feature = "simulation")]
#[used]
static SIMULATION_MARKER: [u8; 29] = *b"timescales:SIMULATION_BUILD=1";

/// Proof that an external value came from a named server.
pub type ExternalDataProof = Presentation;

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum OracleError {
    #[error("source {0}: {1}")]
    Proof(u32, TlsProofError),
    #[error("source {0}: proof is for {1}")]
    WrongServer(u32, String),
    #[error("source {0}: field not found in disclosed bytes")]
    MissingField(u32),
    #[error("source {0}: unparsable price")]
    BadNumber(u32),
    #[error("only {got} valid sources, need {need}")]
    TooFewSources { got: usize, need: usize },
    #[error("claims spread {spread} ticks, limit {limit}")]
    Dispersed { spread: u64, limit: u64 },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Source {
    pub id: u32,
    pub server: String,
    /// JSON key whose string or number value is the price.
    pub field: String,
    /// Decimal places kept from the quoted price.
    pub decimals: u8,
    /// Quote atoms per lot per unit of the scaled price: tick =
    /// scaled_price * atoms_per_unit / tick_size.
    pub atoms_per_unit: u64,
}

#[derive(Clone, Debug)]
pub struct OracleConfig {
    pub market: MarketId,
    pub tick_size: u64,
    pub sources: Vec<Source>,
    pub min_sources: usize,
    pub max_spread_ticks: u64,
    pub trust: Trust,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Observation {
    pub source: u32,
    pub tick: Tick,
    pub time: u64,
}

/// The external price an epoch's band is built around.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PriceCommitment {
    pub market: MarketId,
    pub epoch: EpochId,
    pub reference: Tick,
    pub observations: Vec<Observation>,
    /// Digest over the presentations the observations came from.
    pub proofs: Hash32,
}

impl PriceCommitment {
    pub fn digest(&self) -> Hash32 {
        let mut h = Hasher::new(domain::PRICE_COMMITMENT)
            .chain(&self.market.to_bytes())
            .chain(&self.epoch.to_bytes())
            .chain(&self.reference.to_bytes());
        for o in &self.observations {
            h.update(&o.source.to_le_bytes());
            h.update(&o.tick.to_bytes());
            h.update(&o.time.to_le_bytes());
        }
        h.update(self.proofs.as_bytes());
        h.finalize()
    }
}

/// Parse a decimal like `142.37` into `14237` at `decimals = 2`. Extra
/// digits are truncated, missing ones are zero-filled.
pub fn parse_decimal(s: &[u8], decimals: u8) -> Option<u128> {
    let (int, frac) = match s.iter().position(|c| *c == b'.') {
        Some(i) => (&s[..i], &s[i + 1..]),
        None => (s, &s[s.len()..]),
    };
    if int.is_empty()
        || int.len() > 30
        || !int.iter().all(u8::is_ascii_digit)
        || !frac.iter().all(u8::is_ascii_digit)
    {
        return None;
    }
    let mut v: u128 = 0;
    for d in int {
        v = v.checked_mul(10)?.checked_add(u128::from(d - b'0'))?;
    }
    for i in 0..usize::from(decimals) {
        let d = frac.get(i).map_or(0, |c| c - b'0');
        v = v.checked_mul(10)?.checked_add(u128::from(d))?;
    }
    Some(v)
}

/// Find `"field": value` in `json` (value quoted or bare) and parse it.
/// Deliberately minimal: it needs only the disclosed bytes around the
/// field, not a full JSON document.
pub fn extract_field(json: &[u8], field: &str, decimals: u8) -> Option<u128> {
    let key = format!("\"{field}\"");
    let at = json.windows(key.len()).position(|w| w == key.as_bytes())? + key.len();
    let rest = &json[at..];
    let colon = rest.iter().position(|c| !c.is_ascii_whitespace())?;
    if rest[colon] != b':' {
        return None;
    }
    let rest = &rest[colon + 1..];
    let start = rest.iter().position(|c| !c.is_ascii_whitespace())?;
    let rest = &rest[start..];
    let (body, quoted) = if rest.first() == Some(&b'"') {
        (&rest[1..], true)
    } else {
        (rest, false)
    };
    let end = body.iter().position(|c| {
        if quoted {
            *c == b'"'
        } else {
            !(c.is_ascii_digit() || *c == b'.')
        }
    })?;
    parse_decimal(&body[..end], decimals)
}

pub fn observe(
    cfg: &OracleConfig,
    src: &Source,
    p: &Presentation,
    now: u64,
) -> Result<Observation, OracleError> {
    let d = verify(p, &cfg.trust, now).map_err(|e| OracleError::Proof(src.id, e))?;
    if d.server_name != src.server {
        return Err(OracleError::WrongServer(src.id, d.server_name));
    }
    let price = extract_field(&d.contiguous(), &src.field, src.decimals)
        .ok_or(OracleError::MissingField(src.id))?;
    let atoms = price
        .checked_mul(u128::from(src.atoms_per_unit))
        .ok_or(OracleError::BadNumber(src.id))?;
    let tick = u64::try_from(atoms / u128::from(cfg.tick_size.max(1)))
        .map_err(|_| OracleError::BadNumber(src.id))?;
    Ok(Observation {
        source: src.id,
        tick: Tick(tick),
        time: d.time,
    })
}

/// Build the epoch's price commitment from one presentation per source.
/// Invalid presentations are skipped, and a source counts at most once: only
/// its first valid presentation is observed, so one source (or one holder of
/// many notarised sessions) can neither fill the quorum nor move the median.
/// At least one valid source is always required, whatever `min_sources`
/// says.
pub fn price_commitment(
    cfg: &OracleConfig,
    epoch: EpochId,
    presentations: &[(u32, Presentation)],
    now: u64,
) -> Result<PriceCommitment, OracleError> {
    let mut obs: Vec<Observation> = Vec::new();
    let mut proofs = Hasher::new(domain::PRICE_COMMITMENT).chain(b"proofs");
    for (id, p) in presentations {
        if obs.iter().any(|o| o.source == *id) {
            continue;
        }
        let Some(src) = cfg.sources.iter().find(|s| s.id == *id) else {
            continue;
        };
        if let Ok(o) = observe(cfg, src, p, now) {
            proofs.update(p.digest().as_bytes());
            obs.push(o);
        }
    }
    let need = cfg.min_sources.max(1);
    if obs.len() < need {
        return Err(OracleError::TooFewSources {
            got: obs.len(),
            need,
        });
    }
    let mut ticks: Vec<u64> = obs.iter().map(|o| o.tick.0).collect();
    ticks.sort_unstable();
    // Lower median: deterministic for even counts.
    let reference = Tick(ticks[(ticks.len() - 1) / 2]);
    let spread = ticks[ticks.len() - 1] - ticks[0];
    // Outliers beyond the bound are tolerated as long as the median's
    // neighbourhood agrees: the bound applies to the central half.
    let lo = ticks[ticks.len() / 4];
    let hi = ticks[(3 * ticks.len()).div_ceil(4).saturating_sub(1)];
    if hi - lo > cfg.max_spread_ticks {
        return Err(OracleError::Dispersed {
            spread,
            limit: cfg.max_spread_ticks,
        });
    }
    obs.sort_by_key(|o| o.source);
    Ok(PriceCommitment {
        market: cfg.market,
        epoch,
        reference,
        observations: obs,
        proofs: proofs.finalize(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::Keypair;
    use crate::tls_proof::{Notary, Transcript};
    use rand::SeedableRng;

    #[test]
    fn decimals() {
        assert_eq!(parse_decimal(b"142.37", 2), Some(14237));
        assert_eq!(parse_decimal(b"142.3", 2), Some(14230));
        assert_eq!(parse_decimal(b"142.379", 2), Some(14237));
        assert_eq!(parse_decimal(b"142", 3), Some(142000));
        assert_eq!(parse_decimal(b"1e5", 0), None);
        assert_eq!(parse_decimal(b"-1", 0), None);
        assert_eq!(parse_decimal(b".5", 1), None);
        assert_eq!(
            extract_field(br#"{"price": "10.5"}"#, "price", 2),
            Some(1050)
        );
        assert_eq!(
            extract_field(br#"{"price":10.5,"x":1}"#, "price", 1),
            Some(105)
        );
        assert_eq!(extract_field(br#"{"prices":1}"#, "price", 1), None);
    }

    fn source(id: u32) -> Source {
        Source {
            id,
            server: format!("s{id}.test"),
            field: "price".into(),
            decimals: 2,
            atoms_per_unit: 1,
        }
    }

    fn presentation(
        n: &Notary,
        rng: &mut rand_chacha::ChaCha20Rng,
        id: u32,
        price: &str,
    ) -> Presentation {
        let body = format!(r#"{{"secret":"do-not-reveal","price":"{price}","ts":1}}"#);
        let (att, open) = n
            .notarize(
                rng,
                Transcript {
                    server_name: format!("s{id}.test"),
                    time: 100,
                    sent: b"GET".to_vec(),
                    received: body.into_bytes(),
                },
            )
            .unwrap();
        open.disclose_received(&att, 24..48)
    }

    #[test]
    fn median_of_attested_sources_and_outlier_resistance() {
        let mut rng = rand_chacha::ChaCha20Rng::seed_from_u64(3);
        let n = Notary::new(Keypair::generate(&mut rng));
        let cfg = OracleConfig {
            market: MarketId(1),
            tick_size: 1,
            sources: (1..=5).map(source).collect(),
            min_sources: 3,
            max_spread_ticks: 50,
            trust: Trust {
                notaries: [n.public_key()].into(),
                servers: (1..=5).map(|i| format!("s{i}.test")).collect(),
                max_age_secs: 30,
            },
        };
        let prices = ["100.00", "100.10", "99.95", "100.05", "250.00"];
        let ps: Vec<_> = prices
            .iter()
            .enumerate()
            .map(|(i, p)| (i as u32 + 1, presentation(&n, &mut rng, i as u32 + 1, p)))
            .collect();
        let pc = price_commitment(&cfg, EpochId(1), &ps, 110).unwrap();
        assert_eq!(
            pc.reference,
            Tick(10005),
            "lower median; the 250.00 outlier has no effect"
        );
        assert_eq!(pc.observations.len(), 5);

        // A presentation for the wrong source id is not counted.
        let swapped = vec![
            (1, ps[1].1.clone()),
            (2, ps[2].1.clone()),
            (3, ps[3].1.clone()),
        ];
        assert!(matches!(
            price_commitment(&cfg, EpochId(1), &swapped, 110),
            Err(OracleError::TooFewSources { .. })
        ));

        let wild: Vec<_> = ["10.00", "100.00", "500.00"]
            .iter()
            .enumerate()
            .map(|(i, p)| (i as u32 + 1, presentation(&n, &mut rng, i as u32 + 1, p)))
            .collect();
        assert!(matches!(
            price_commitment(&cfg, EpochId(1), &wild, 110),
            Err(OracleError::Dispersed { .. })
        ));
    }

    fn config(n: &Notary, min_sources: usize) -> OracleConfig {
        OracleConfig {
            market: MarketId(1),
            tick_size: 1,
            sources: (1..=5).map(source).collect(),
            min_sources,
            max_spread_ticks: 50,
            trust: Trust {
                notaries: [n.public_key()].into(),
                servers: (1..=5).map(|i| format!("s{i}.test")).collect(),
                max_age_secs: 30,
            },
        }
    }

    #[test]
    fn a_source_counts_once() {
        let mut rng = rand_chacha::ChaCha20Rng::seed_from_u64(4);
        let n = Notary::new(Keypair::generate(&mut rng));
        let cfg = config(&n, 3);
        // Three valid presentations, all from source 1: one observation.
        let same: Vec<_> = ["100.00", "100.01", "100.02"]
            .iter()
            .map(|p| (1, presentation(&n, &mut rng, 1, p)))
            .collect();
        assert_eq!(
            price_commitment(&cfg, EpochId(1), &same, 110),
            Err(OracleError::TooFewSources { got: 1, need: 3 })
        );

        // Extra presentations of source 3 cannot drag the median up.
        let mut ps: Vec<_> = [(1, "100.00"), (2, "100.10"), (3, "100.20")]
            .iter()
            .map(|(id, p)| (*id, presentation(&n, &mut rng, *id, p)))
            .collect();
        for _ in 0..4 {
            ps.push((3, presentation(&n, &mut rng, 3, "190.00")));
        }
        let pc = price_commitment(&cfg, EpochId(1), &ps, 110).unwrap();
        assert_eq!(pc.reference, Tick(10010));
        let sources: Vec<u32> = pc.observations.iter().map(|o| o.source).collect();
        assert_eq!(sources, [1, 2, 3]);
        assert_eq!(pc.observations[2].tick, Tick(10020));
    }

    #[test]
    fn an_invalid_presentation_does_not_use_up_its_source() {
        let mut rng = rand_chacha::ChaCha20Rng::seed_from_u64(5);
        let n = Notary::new(Keypair::generate(&mut rng));
        let cfg = config(&n, 2);
        let mut stale = presentation(&n, &mut rng, 1, "100.00");
        stale.attestation.time = 1;
        let ps = vec![
            (1, stale),
            (1, presentation(&n, &mut rng, 1, "100.00")),
            (2, presentation(&n, &mut rng, 2, "100.20")),
        ];
        let pc = price_commitment(&cfg, EpochId(1), &ps, 110).unwrap();
        assert_eq!(pc.observations.len(), 2);
        assert_eq!(pc.reference, Tick(10000));
    }

    #[test]
    fn at_least_one_source_is_required() {
        let mut rng = rand_chacha::ChaCha20Rng::seed_from_u64(6);
        let n = Notary::new(Keypair::generate(&mut rng));
        let cfg = config(&n, 0);
        assert_eq!(
            price_commitment(&cfg, EpochId(1), &[], 110),
            Err(OracleError::TooFewSources { got: 0, need: 1 })
        );
        // A presentation for an unknown source counts for nothing either.
        let unknown = vec![(9, presentation(&n, &mut rng, 1, "100.00"))];
        assert_eq!(
            price_commitment(&cfg, EpochId(1), &unknown, 110),
            Err(OracleError::TooFewSources { got: 0, need: 1 })
        );
        let one = vec![(1, presentation(&n, &mut rng, 1, "100.00"))];
        assert_eq!(
            price_commitment(&cfg, EpochId(1), &one, 110).map(|pc| pc.reference),
            Ok(Tick(10000))
        );
    }

    #[test]
    fn every_oracle_error_is_produced() {
        // Exhaustive on purpose: a new variant must be produced here.
        fn variant(e: &OracleError) -> usize {
            match e {
                OracleError::Proof(..) => 0,
                OracleError::WrongServer(..) => 1,
                OracleError::MissingField(_) => 2,
                OracleError::BadNumber(_) => 3,
                OracleError::TooFewSources { .. } => 4,
                OracleError::Dispersed { .. } => 5,
            }
        }
        let mut rng = rand_chacha::ChaCha20Rng::seed_from_u64(7);
        let n = Notary::new(Keypair::generate(&mut rng));
        let cfg = config(&n, 2);
        let p1 = presentation(&n, &mut rng, 1, "100.00");
        let unknown_field = Source {
            field: "volume".into(),
            ..source(1)
        };
        // 10^4 * (2^64 - 1) quote atoms per lot is a tick beyond u64.
        let overflowing = Source {
            atoms_per_unit: u64::MAX,
            ..source(1)
        };
        let far: Vec<_> = [(1, "100.00"), (2, "900.00")]
            .iter()
            .map(|(id, p)| (*id, presentation(&n, &mut rng, *id, p)))
            .collect();
        let errors = [
            observe(&cfg, &source(1), &p1, 1_000).map(|_| ()),
            observe(&cfg, &source(2), &p1, 110).map(|_| ()),
            observe(&cfg, &unknown_field, &p1, 110).map(|_| ()),
            observe(&cfg, &overflowing, &p1, 110).map(|_| ()),
            price_commitment(&cfg, EpochId(1), &far[..1], 110).map(|_| ()),
            price_commitment(&cfg, EpochId(1), &far, 110).map(|_| ()),
        ];
        let seen: Vec<usize> = errors
            .iter()
            .map(|e| variant(e.as_ref().unwrap_err()))
            .collect();
        assert_eq!(seen, [0, 1, 2, 3, 4, 5]);
        assert_eq!(errors[0], Err(OracleError::Proof(1, TlsProofError::Stale)));
    }
}
