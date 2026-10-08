//! Online phase: openings, multiplication, MAC checks, comparisons.
//!
//! Every interaction is metered. A "round" is one synchronous exchange in
//! which each party may send to every other party. Vectorised operations
//! open many values in one round. Bytes count every point-to-point message
//! (broadcast is `n - 1` sends). Latency over a real network is estimated
//! from these counts by `NetworkModel`. We never measure a real network.

use std::time::Duration;

use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use thiserror::Error;

use crate::mpc::dealer::{Dealer, PreprocessingCounts};
use crate::mpc::field::Fp;
use crate::mpc::shares::Shared;

/// Statistical security parameter for masked openings in comparisons.
pub const KAPPA: u32 = 40;
const ELEM: u64 = 16;

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum MpcError {
    #[error("party {party} unavailable in round {round}")]
    PartyUnavailable { party: usize, round: u64 },
    #[error("MAC check failed: an opened value was tampered with")]
    MacCheckFailed,
    #[error("comparison width {0} too large for the field")]
    Width(u32),
    #[error("invalid input: {0}")]
    Input(&'static str),
}

/// Prefix-product circuit used inside comparisons.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LtCircuit {
    /// `k - 1` sequential multiplications: fewest multiplications, `k` rounds.
    Ripple,
    /// Kogge-Stone suffix products: `log2 k` rounds, about `k log2 k`
    /// multiplications.
    LogDepth,
}

/// Faults the simulated parties can be told to exhibit in tests.
#[cfg(feature = "fault-injection")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Fault {
    /// Party stops responding from this round on.
    Crash { party: usize, round: u64 },
    /// Party adds 1 to every share it broadcasts from this round on.
    CorruptOpenings { party: usize, round: u64 },
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Meter {
    pub rounds: u64,
    pub bytes: u64,
    pub opened: u64,
    pub multiplications: u64,
    pub comparisons: u64,
    pub mac_checks: u64,
}

impl Meter {
    pub fn bytes_per_party(&self, parties: usize) -> u64 {
        self.bytes / parties.max(1) as u64
    }
}

/// Network used to turn counts into an estimated wall-clock overhead.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct NetworkModel {
    pub rtt: Duration,
    pub bits_per_sec: u64,
}

impl NetworkModel {
    pub const LAN: NetworkModel = NetworkModel {
        rtt: Duration::from_millis(1),
        bits_per_sec: 1_000_000_000,
    };
    pub const WAN: NetworkModel = NetworkModel {
        rtt: Duration::from_millis(50),
        bits_per_sec: 100_000_000,
    };

    /// One RTT per round plus serialisation of each party's outgoing bytes.
    pub fn overhead(&self, m: &Meter, parties: usize) -> Duration {
        let bits = u128::from(m.bytes_per_party(parties)) * 8;
        let nanos = bits * 1_000_000_000 / u128::from(self.bits_per_sec.max(1));
        let transfer = Duration::from_nanos(u64::try_from(nanos).unwrap_or(u64::MAX));
        self.rtt * u32::try_from(m.rounds).unwrap_or(u32::MAX) + transfer
    }
}

pub struct Engine {
    parties: usize,
    authenticated: bool,
    pub(crate) dealer: Dealer,
    pub(crate) meter: Meter,
    circuit: LtCircuit,
    #[cfg(feature = "fault-injection")]
    fault: Option<Fault>,
    /// Opened values awaiting a MAC check, and every party's MAC shares.
    pending_values: Vec<Fp>,
    pending_macs: Vec<Vec<Fp>>,
}

impl core::fmt::Debug for Engine {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Engine")
            .field("parties", &self.parties)
            .field("meter", &self.meter)
            .finish_non_exhaustive()
    }
}

impl Engine {
    pub fn new(parties: usize, authenticated: bool, circuit: LtCircuit, seed: u64) -> Self {
        // Expanded exactly as `seed_from_u64` does, so a u64 seed keeps the
        // stream it had before the dealer took a 32-byte seed.
        let seed = ChaCha20Rng::seed_from_u64(seed).get_seed();
        Self::with_dealer(Dealer::new(parties, authenticated, Some(seed)), circuit)
    }

    /// Run online over an existing preprocessing state (which holds the MAC
    /// key and any input masks already handed to traders).
    pub fn with_dealer(dealer: Dealer, circuit: LtCircuit) -> Self {
        let parties = dealer.parties();
        let authenticated = dealer.authenticated();
        assert!(parties >= 2, "MPC needs at least two parties");
        Self {
            parties,
            authenticated,
            dealer,
            meter: Meter::default(),
            circuit,
            #[cfg(feature = "fault-injection")]
            fault: None,
            pending_values: Vec::new(),
            pending_macs: vec![Vec::new(); parties],
        }
    }

    pub fn parties(&self) -> usize {
        self.parties
    }

    pub fn authenticated(&self) -> bool {
        self.authenticated
    }

    #[cfg(feature = "fault-injection")]
    pub fn set_fault(&mut self, f: Option<Fault>) {
        self.fault = f;
    }

    /// The party that crashed by now, if a crash was injected.
    #[cfg(feature = "fault-injection")]
    fn crashed(&self) -> Option<usize> {
        match self.fault {
            Some(Fault::Crash { party, round }) if self.meter.rounds >= round => Some(party),
            _ => None,
        }
    }

    #[cfg(not(feature = "fault-injection"))]
    fn crashed(&self) -> Option<usize> {
        None
    }

    /// The party corrupting its openings by now, if that was injected.
    #[cfg(feature = "fault-injection")]
    fn corrupting(&self) -> Option<usize> {
        match self.fault {
            Some(Fault::CorruptOpenings { party, round }) if self.meter.rounds >= round => {
                Some(party)
            }
            _ => None,
        }
    }

    #[cfg(not(feature = "fault-injection"))]
    fn corrupting(&self) -> Option<usize> {
        None
    }

    pub fn meter(&self) -> Meter {
        self.meter
    }

    pub fn preprocessing(&self) -> PreprocessingCounts {
        self.dealer.counts()
    }

    pub fn dealer_time(&self) -> Duration {
        self.dealer.elapsed()
    }

    pub fn alpha(&self) -> Vec<Fp> {
        self.dealer.alpha_shares().to_vec()
    }

    pub fn dealer(&mut self) -> &mut Dealer {
        &mut self.dealer
    }

    pub fn into_dealer(self) -> Dealer {
        self.dealer
    }

    fn round(&mut self, elems: u64) -> Result<(), MpcError> {
        self.meter.rounds += 1;
        let n = self.parties as u64;
        self.meter.bytes += elems * ELEM * n * (n - 1);
        if let Some(party) = self.crashed() {
            return Err(MpcError::PartyUnavailable {
                party,
                round: self.meter.rounds,
            });
        }
        Ok(())
    }

    /// Open a shared vector to all parties.
    pub fn open(&mut self, x: &Shared) -> Result<Vec<Fp>, MpcError> {
        self.round(x.len() as u64)?;
        let corrupt = self.corrupting();
        let mut out = vec![Fp::ZERO; x.len()];
        for (i, share) in x.v.iter().enumerate() {
            for (o, s) in out.iter_mut().zip(share) {
                *o += *s;
                if corrupt == Some(i) {
                    *o += Fp::ONE;
                }
            }
        }
        self.meter.opened += x.len() as u64;
        if self.authenticated {
            self.pending_values.extend_from_slice(&out);
            for (i, m) in x.m.iter().enumerate() {
                self.pending_macs[i].extend_from_slice(m);
            }
        }
        Ok(out)
    }

    /// Batched MAC check over everything opened since the last check
    /// (SPDZ): random combination, each party commits to and opens
    /// `sigma_i = sum r_j m_ij - alpha_i * sum r_j y_j`, and the sigmas must
    /// sum to zero.
    pub fn mac_check(&mut self) -> Result<(), MpcError> {
        if !self.authenticated || self.pending_values.is_empty() {
            return Ok(());
        }
        // Coin toss, then commit and open sigma: three rounds of tiny messages.
        let r = self.dealer.coins(self.pending_values.len());
        self.round(1)?;
        self.round(2)?;
        self.round(1)?;
        self.meter.mac_checks += 1;
        let y: Fp = r
            .iter()
            .zip(&self.pending_values)
            .map(|(a, b)| *a * *b)
            .sum();
        let alpha = self.dealer.alpha_shares().to_vec();
        let mut total = Fp::ZERO;
        for (i, macs) in self.pending_macs.iter().enumerate() {
            let s: Fp = r.iter().zip(macs).map(|(a, b)| *a * *b).sum();
            total += s - alpha[i] * y;
        }
        self.pending_values.clear();
        for m in &mut self.pending_macs {
            m.clear();
        }
        if total.is_zero() {
            Ok(())
        } else {
            Err(MpcError::MacCheckFailed)
        }
    }

    pub fn add_public(&self, x: &Shared, c: &[Fp]) -> Shared {
        x.add_public(c, self.dealer.alpha_shares())
    }

    pub fn add_const(&self, x: &Shared, c: Fp) -> Shared {
        x.add_const(c, self.dealer.alpha_shares())
    }

    /// `1 - x`, element-wise.
    pub fn not(&self, x: &Shared) -> Shared {
        self.add_const(&x.scale(-Fp::ONE), Fp::ONE)
    }

    /// Element-wise product, one Beaver triple per element, one round.
    pub fn mul(&mut self, x: &Shared, y: &Shared) -> Result<Shared, MpcError> {
        let len = x.len();
        debug_assert_eq!(len, y.len());
        if len == 0 {
            return Ok(x.clone());
        }
        let (a, b, c) = self.dealer.triples(len);
        let both = Shared::concat(&[&x.sub(&a), &y.sub(&b)]);
        let opened = self.open(&both)?;
        let (d, e) = opened.split_at(len);
        let de: Vec<Fp> = d.iter().zip(e).map(|(p, q)| *p * *q).collect();
        let z = c.add(&b.mul_public(d)).add(&a.mul_public(e));
        self.meter.multiplications += len as u64;
        Ok(self.add_public(&z, &de))
    }

    /// Several independent products in one round.
    pub fn mul_many(&mut self, pairs: &[(&Shared, &Shared)]) -> Result<Vec<Shared>, MpcError> {
        let lens: Vec<usize> = pairs.iter().map(|(x, _)| x.len()).collect();
        let xs: Vec<&Shared> = pairs.iter().map(|p| p.0).collect();
        let ys: Vec<&Shared> = pairs.iter().map(|p| p.1).collect();
        let prod = self.mul(&Shared::concat(&xs), &Shared::concat(&ys))?;
        Ok(prod.split(&lens))
    }

    /// `[c < r]` for public `c` and shared bits `r` (LSB first), element-wise.
    fn bit_lt(&mut self, c: &[u128], r: &[Shared]) -> Result<Shared, MpcError> {
        let k = r.len();
        let len = c.len();
        let cbit = |i: usize| -> Vec<Fp> {
            c.iter()
                .map(|x| if (x >> i) & 1 == 1 { Fp::ONE } else { Fp::ZERO })
                .collect()
        };
        // eq_i = [c_i == r_i]. gt_i = [r_i > c_i]. Both linear in r_i.
        let mut eq = Vec::with_capacity(k);
        let mut gt = Vec::with_capacity(k);
        for (i, ri) in r.iter().enumerate() {
            let ci = cbit(i);
            let not_ci: Vec<Fp> = ci.iter().map(|b| Fp::ONE - *b).collect();
            // eq = c*r + (1-c)(1-r) = (2c-1) r + (1-c)
            let coef: Vec<Fp> = ci.iter().map(|b| *b + *b - Fp::ONE).collect();
            eq.push(self.add_public(&ri.mul_public(&coef), &not_ci));
            gt.push(ri.mul_public(&not_ci));
        }
        // suffix[i] = prod_{j >= i} eq_j, so the weight of position i is suffix[i+1].
        let suffix = self.suffix_products(eq)?;
        let one = self.add_const(
            &Shared::zeros(self.parties, len, self.authenticated),
            Fp::ONE,
        );
        let weights: Vec<Shared> = (0..k)
            .map(|i| {
                if i + 1 < k {
                    suffix[i + 1].clone()
                } else {
                    one.clone()
                }
            })
            .collect();
        let pairs: Vec<(&Shared, &Shared)> = gt.iter().zip(weights.iter()).collect();
        let terms = self.mul_many(&pairs)?;
        let mut acc = Shared::zeros(self.parties, len, self.authenticated);
        for t in &terms {
            acc = acc.add(t);
        }
        Ok(acc)
    }

    fn suffix_products(&mut self, mut s: Vec<Shared>) -> Result<Vec<Shared>, MpcError> {
        let k = s.len();
        match self.circuit {
            LtCircuit::Ripple => {
                for i in (0..k.saturating_sub(1)).rev() {
                    s[i] = self.mul(&s[i], &s[i + 1])?;
                }
            }
            LtCircuit::LogDepth => {
                let mut d = 1;
                while d < k {
                    let idx: Vec<usize> = (0..k - d).collect();
                    let pairs: Vec<(&Shared, &Shared)> =
                        idx.iter().map(|&i| (&s[i], &s[i + d])).collect();
                    let prods = self.mul_many(&pairs)?;
                    for (i, p) in idx.into_iter().zip(prods) {
                        s[i] = p;
                    }
                    d <<= 1;
                }
            }
        }
        Ok(s)
    }

    /// `[a >= b]` element-wise, for values known to lie in `[0, 2^k)`.
    ///
    /// Catrina-de Hoogh style: with `z = a - b + 2^k in [0, 2^(k+1))`, the
    /// answer is bit `k` of `z`. Open `z + r` for a random `r` whose low `k`
    /// bits are shared bit-wise and whose high part has `KAPPA` extra bits
    /// for statistical hiding, compare the low parts with `bit_lt`, and
    /// derive `z mod 2^k` and hence `floor(z / 2^k)`.
    pub fn ge(&mut self, a: &Shared, b: &Shared, k: u32) -> Result<Shared, MpcError> {
        if k + KAPPA + 2 >= 127 {
            return Err(MpcError::Width(k));
        }
        let len = a.len();
        if len == 0 {
            return Ok(a.clone());
        }
        let two_k = Fp::pow2(k);
        let z = self.add_const(&a.sub(b), two_k);
        let rbits: Vec<Shared> = {
            let all = self.dealer.bits(len * k as usize);
            all.split(&vec![len; k as usize])
        };
        let rhigh = self.dealer.bounded(len, KAPPA);
        let mut r = rhigh.scale(two_k);
        for (i, bi) in rbits.iter().enumerate() {
            r = r.add(&bi.scale(Fp::pow2(u32::try_from(i).unwrap_or(0))));
        }
        let c = self.open(&z.add(&r))?;
        let mask = (1u128 << k) - 1;
        let clow: Vec<u128> = c.iter().map(|x| x.value() & mask).collect();
        let lt = self.bit_lt(&clow, &rbits)?;
        // z mod 2^k = c' - r' + 2^k [c' < r']
        let mut rlow = Shared::zeros(self.parties, len, self.authenticated);
        for (i, bi) in rbits.iter().enumerate() {
            rlow = rlow.add(&bi.scale(Fp::pow2(u32::try_from(i).unwrap_or(0))));
        }
        let clow_f: Vec<Fp> = clow.iter().map(|x| Fp::new(*x)).collect();
        let zmod = self.add_public(&lt.scale(two_k).sub(&rlow), &clow_f);
        self.meter.comparisons += len as u64;
        Ok(z.sub(&zmod).scale(two_k.inv()))
    }

    /// `[a < b] = 1 - [a >= b]`.
    pub fn lt(&mut self, a: &Shared, b: &Shared, k: u32) -> Result<Shared, MpcError> {
        let ge = self.ge(a, b, k)?;
        Ok(self.not(&ge))
    }

    /// `min(a, b)` element-wise, one comparison and one multiplication.
    pub fn min(&mut self, a: &Shared, b: &Shared, k: u32) -> Result<Shared, MpcError> {
        let a_lt_b = self.lt(a, b, k)?;
        let diff = a.sub(b);
        let pick = self.mul(&a_lt_b, &diff)?;
        Ok(b.add(&pick))
    }

    /// Share public values (party 0 holds them), e.g. constants that must
    /// enter a multiplication.
    pub fn constant(&self, c: &[Fp]) -> Shared {
        self.add_public(&Shared::zeros(self.parties, c.len(), self.authenticated), c)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn engine(c: LtCircuit) -> Engine {
        Engine::new(3, true, c, 7)
    }

    fn share(e: &mut Engine, xs: &[u64]) -> Shared {
        // Input via a fresh mask block owned by a dummy trader.
        let (off, masks) = e
            .dealer
            .input_masks(timescales_core::TraderId([0; 32]), xs.len());
        let s = e
            .dealer
            .take_masks(&timescales_core::TraderId([0; 32]), off, xs.len())
            .unwrap();
        let d: Vec<Fp> = xs
            .iter()
            .zip(&masks)
            .map(|(x, m)| Fp::from_u64(*x) - *m)
            .collect();
        e.add_public(&s, &d)
    }

    #[test]
    fn mul_and_mac_check() {
        let mut e = engine(LtCircuit::Ripple);
        let a = share(&mut e, &[3, 5, 0]);
        let b = share(&mut e, &[7, 11, 9]);
        let c = e.mul(&a, &b).unwrap();
        assert_eq!(
            e.open(&c).unwrap(),
            vec![Fp::from_u64(21), Fp::from_u64(55), Fp::ZERO]
        );
        assert!(e.mac_check().is_ok());
    }

    #[test]
    fn tampering_is_caught() {
        let mut e = engine(LtCircuit::Ripple);
        let a = share(&mut e, &[3]);
        e.set_fault(Some(Fault::CorruptOpenings { party: 1, round: 0 }));
        let _ = e.open(&a).unwrap();
        assert_eq!(e.mac_check(), Err(MpcError::MacCheckFailed));
    }

    #[test]
    fn crash_aborts() {
        let mut e = engine(LtCircuit::Ripple);
        let a = share(&mut e, &[3]);
        e.set_fault(Some(Fault::Crash { party: 2, round: 1 }));
        assert!(matches!(
            e.open(&a),
            Err(MpcError::PartyUnavailable { party: 2, .. })
        ));
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(32))]
        #[test]
        fn comparisons(xs in prop::collection::vec((0u64..1 << 20, 0u64..1 << 20), 1..12), log in any::<bool>()) {
            let mut e = engine(if log { LtCircuit::LogDepth } else { LtCircuit::Ripple });
            let a = share(&mut e, &xs.iter().map(|p| p.0).collect::<Vec<_>>());
            let b = share(&mut e, &xs.iter().map(|p| p.1).collect::<Vec<_>>());
            let ge = e.ge(&a, &b, 20).unwrap();
            let m = e.min(&a, &b, 20).unwrap();
            let ge = e.open(&ge).unwrap();
            let m = e.open(&m).unwrap();
            for (i, (x, y)) in xs.iter().enumerate() {
                prop_assert_eq!(ge[i], if x >= y { Fp::ONE } else { Fp::ZERO });
                prop_assert_eq!(m[i], Fp::from_u64(*x.min(y)));
            }
            prop_assert!(e.mac_check().is_ok());
        }
    }

    #[test]
    fn log_depth_uses_fewer_rounds() {
        let mut rounds = Vec::new();
        for c in [LtCircuit::Ripple, LtCircuit::LogDepth] {
            let mut e = engine(c);
            let a = share(&mut e, &[1, 2]);
            let b = share(&mut e, &[2, 1]);
            let before = e.meter().rounds;
            e.ge(&a, &b, 64).unwrap();
            rounds.push(e.meter().rounds - before);
        }
        assert!(rounds[1] < rounds[0], "{rounds:?}");
    }
}
