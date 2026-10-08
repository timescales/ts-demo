//! Reference price sources: the tick an epoch's band is built
//! around, and the price commitment the epoch announcement binds.
//!
//! Production sources are operator-provided (`fixed`, `last_clearing`,
//! `operator`), and their commitments carry no observations. The
//! TLSNotary source is **modelled**: it fabricates notarised observations
//! around a configured tick and exists in profile local only, labelled
//! "modelled" everywhere it is shown.

use parking_lot::Mutex;
use thiserror::Error;
use timescales_core::crypto::{Hasher, domain};
use timescales_core::oracle::{Observation, PriceCommitment};
use timescales_core::{EpochId, MarketId, Tick};

use crate::config::{ReferenceConfig, ReferenceSource};

#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum ReferenceError {
    #[error("no operator reference price set")]
    NoOperatorPrice,
    #[error("modelled sources disagree: {got} of {need} needed")]
    TooFewSources { got: u32, need: u32 },
}

/// Where an epoch's reference tick comes from.
pub trait PriceSource: Send + Sync {
    fn reference(&self, epoch: u64) -> Result<(Tick, PriceCommitment), ReferenceError>;

    /// The source as `Info.trust.reference_price` names it.
    fn kind(&self) -> ReferenceSource;

    /// A posted epoch cleared at `tick` (`last_clearing` follows it).
    fn observe_clearing(&self, _tick: Tick) {}

    /// The admin set a new operator price (`operator` follows it).
    fn set_operator(&self, _tick: Tick) -> Result<(), ReferenceError> {
        Ok(())
    }

    /// The commitment an epoch opened with at `tick`, rebuilt after a
    /// restart.
    fn rebuild(&self, epoch: u64, tick: Tick) -> PriceCommitment;
}

/// Proof digest of a commitment without notarised observations: says which
/// operator-provided source chose the tick.
fn operator_proofs(source: &str) -> timescales_core::Hash32 {
    Hasher::new(domain::PRICE_COMMITMENT)
        .chain(b"operator-provided")
        .chain(source.as_bytes())
        .finalize()
}

fn commitment(market: MarketId, epoch: u64, tick: Tick, source: &str) -> PriceCommitment {
    PriceCommitment {
        market,
        epoch: EpochId(epoch),
        reference: tick,
        observations: Vec::new(),
        proofs: operator_proofs(source),
    }
}

/// Always the configured tick.
#[derive(Debug)]
pub struct Fixed {
    pub market: MarketId,
    pub tick: Tick,
}

impl PriceSource for Fixed {
    fn rebuild(&self, epoch: u64, tick: Tick) -> PriceCommitment {
        commitment(self.market, epoch, tick, "fixed")
    }

    fn reference(&self, epoch: u64) -> Result<(Tick, PriceCommitment), ReferenceError> {
        Ok((
            self.tick,
            commitment(self.market, epoch, self.tick, "fixed"),
        ))
    }

    fn kind(&self) -> ReferenceSource {
        ReferenceSource::Fixed
    }
}

/// The last clearing tick of a posted epoch, `initial` before any.
#[derive(Debug)]
pub struct LastClearing {
    pub market: MarketId,
    pub initial: Tick,
    last: Mutex<Option<Tick>>,
}

impl LastClearing {
    pub fn new(market: MarketId, initial: Tick) -> Self {
        Self {
            market,
            initial,
            last: Mutex::new(None),
        }
    }
}

impl PriceSource for LastClearing {
    fn rebuild(&self, epoch: u64, tick: Tick) -> PriceCommitment {
        commitment(self.market, epoch, tick, "last_clearing")
    }

    fn reference(&self, epoch: u64) -> Result<(Tick, PriceCommitment), ReferenceError> {
        let tick = self.last.lock().unwrap_or(self.initial);
        Ok((tick, commitment(self.market, epoch, tick, "last_clearing")))
    }

    fn kind(&self) -> ReferenceSource {
        ReferenceSource::LastClearing
    }

    fn observe_clearing(&self, tick: Tick) {
        *self.last.lock() = Some(tick);
    }
}

/// Whatever the admin API set last (`initial` until then).
#[derive(Debug)]
pub struct Operator {
    pub market: MarketId,
    current: Mutex<Tick>,
}

impl Operator {
    pub fn new(market: MarketId, initial: Tick) -> Self {
        Self {
            market,
            current: Mutex::new(initial),
        }
    }
}

impl PriceSource for Operator {
    fn rebuild(&self, epoch: u64, tick: Tick) -> PriceCommitment {
        commitment(self.market, epoch, tick, "operator")
    }

    fn reference(&self, epoch: u64) -> Result<(Tick, PriceCommitment), ReferenceError> {
        let tick = *self.current.lock();
        if tick.0 == 0 {
            return Err(ReferenceError::NoOperatorPrice);
        }
        Ok((tick, commitment(self.market, epoch, tick, "operator")))
    }

    fn kind(&self) -> ReferenceSource {
        ReferenceSource::Operator
    }

    fn set_operator(&self, tick: Tick) -> Result<(), ReferenceError> {
        if tick.0 == 0 {
            return Err(ReferenceError::NoOperatorPrice);
        }
        *self.current.lock() = tick;
        Ok(())
    }
}

/// **Modelled** TLSNotary source (profile local only): `sources` fabricated
/// observations within one tick of `tick`, of which the lower median is the
/// reference. Nothing is notarised. The observations only exercise the
/// commitment format clients verify.
#[derive(Debug)]
pub struct ModelledNotary {
    pub market: MarketId,
    pub tick: Tick,
    pub sources: u32,
    pub min_sources: u32,
}

impl PriceSource for ModelledNotary {
    fn rebuild(&self, epoch: u64, tick: Tick) -> PriceCommitment {
        match self.reference(epoch) {
            Ok((_, pc)) if pc.reference == tick => pc,
            _ => commitment(self.market, epoch, tick, "modelled_tlsnotary"),
        }
    }

    fn reference(&self, epoch: u64) -> Result<(Tick, PriceCommitment), ReferenceError> {
        if self.sources < self.min_sources || self.sources == 0 {
            return Err(ReferenceError::TooFewSources {
                got: self.sources,
                need: self.min_sources,
            });
        }
        let observations: Vec<Observation> = (0..self.sources)
            .map(|source| {
                // Deterministic spread of -1, 0, +1 ticks around the model.
                let offset = u64::from(source % 3);
                Observation {
                    source,
                    tick: Tick(self.tick.0.saturating_add(offset).saturating_sub(1)),
                    time: epoch,
                }
            })
            .collect();
        let mut ticks: Vec<u64> = observations.iter().map(|o| o.tick.0).collect();
        ticks.sort_unstable();
        let reference = Tick(ticks[(ticks.len() - 1) / 2]);
        let proofs = Hasher::new(domain::PRICE_COMMITMENT)
            .chain(b"modelled-tlsnotary")
            .chain(&epoch.to_le_bytes())
            .finalize();
        Ok((
            reference,
            PriceCommitment {
                market: self.market,
                epoch: EpochId(epoch),
                reference,
                observations,
                proofs,
            },
        ))
    }

    fn kind(&self) -> ReferenceSource {
        ReferenceSource::ModelledTlsnotary
    }
}

/// The source a `[market.reference]` table configures.
pub fn source(market: MarketId, cfg: &ReferenceConfig) -> Box<dyn PriceSource> {
    let initial = Tick(cfg.initial_tick.0);
    match cfg.source {
        ReferenceSource::Fixed => Box::new(Fixed {
            market,
            tick: initial,
        }),
        ReferenceSource::LastClearing => Box::new(LastClearing::new(market, initial)),
        ReferenceSource::Operator => Box::new(Operator::new(market, initial)),
        ReferenceSource::ModelledTlsnotary => Box::new(ModelledNotary {
            market,
            tick: initial,
            sources: cfg.modelled_sources.unwrap_or(1),
            min_sources: cfg.modelled_min_sources.unwrap_or(1),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn last_clearing_follows_posted_epochs() {
        let s = LastClearing::new(MarketId(1), Tick(100));
        assert_eq!(s.reference(5).unwrap().0, Tick(100));
        s.observe_clearing(Tick(120));
        let (tick, pc) = s.reference(6).unwrap();
        assert_eq!(tick, Tick(120));
        assert_eq!((pc.epoch, pc.reference), (EpochId(6), Tick(120)));
        assert!(pc.observations.is_empty());
    }

    #[test]
    fn operator_needs_a_price() {
        let s = Operator::new(MarketId(1), Tick(0));
        assert_eq!(s.reference(1), Err(ReferenceError::NoOperatorPrice));
        s.set_operator(Tick(77)).unwrap();
        assert_eq!(s.reference(1).unwrap().0, Tick(77));
        assert!(s.set_operator(Tick(0)).is_err());
    }

    #[test]
    fn modelled_commitments_carry_observations_and_differ_per_epoch() {
        let s = ModelledNotary {
            market: MarketId(1),
            tick: Tick(500),
            sources: 3,
            min_sources: 2,
        };
        let (tick, a) = s.reference(1).unwrap();
        assert_eq!(tick, Tick(500));
        assert_eq!(a.observations.len(), 3);
        let (_, b) = s.reference(2).unwrap();
        assert_ne!(a.digest(), b.digest());
        let bad = ModelledNotary {
            sources: 1,
            min_sources: 2,
            ..s
        };
        assert!(bad.reference(1).is_err());
    }

    #[test]
    fn fixed_commitments_name_their_source() {
        let f = Fixed {
            market: MarketId(1),
            tick: Tick(10),
        };
        let o = Operator::new(MarketId(1), Tick(10));
        assert_ne!(
            f.reference(1).unwrap().1.digest(),
            o.reference(1).unwrap().1.digest()
        );
    }
}
