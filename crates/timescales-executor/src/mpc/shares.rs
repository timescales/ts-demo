//! Authenticated additive secret sharing (SPDZ style).
//!
//! A shared vector `[x]` is held as `n` additive share vectors `x^(i)` with
//! `sum_i x^(i) = x`, plus MAC shares `m^(i)` with `sum_i m^(i) = alpha * x`
//! for a global key `alpha` that is itself additively shared. Linear
//! operations are local. Anything else goes through `Engine`.
//!
//! The simulation stores all parties' shares side by side. Every operation
//! here touches each party's share using only that party's data (and its
//! own key share), exactly as party `i` would locally. Nothing here sums
//! across parties except `Engine::open`.
//!
//! In semi-honest mode the MAC vectors are empty and MAC work is skipped,
//! which is how the cost of active security is measured.

use crate::mpc::field::Fp;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Shared {
    /// `v[party][element]`
    pub(crate) v: Vec<Vec<Fp>>,
    /// `m[party][element]`. Empty when MACs are disabled.
    pub(crate) m: Vec<Vec<Fp>>,
}

impl Shared {
    pub fn zeros(parties: usize, len: usize, authenticated: bool) -> Self {
        Shared {
            v: vec![vec![Fp::ZERO; len]; parties],
            m: if authenticated {
                vec![vec![Fp::ZERO; len]; parties]
            } else {
                Vec::new()
            },
        }
    }

    pub fn len(&self) -> usize {
        self.v.first().map_or(0, Vec::len)
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn parties(&self) -> usize {
        self.v.len()
    }

    pub fn authenticated(&self) -> bool {
        !self.m.is_empty()
    }

    fn zip_with(&self, other: &Shared, f: impl Fn(Fp, Fp) -> Fp) -> Shared {
        debug_assert_eq!(self.len(), other.len());
        let pair = |a: &Vec<Vec<Fp>>, b: &Vec<Vec<Fp>>| -> Vec<Vec<Fp>> {
            a.iter()
                .zip(b)
                .map(|(x, y)| x.iter().zip(y).map(|(p, q)| f(*p, *q)).collect())
                .collect()
        };
        Shared {
            v: pair(&self.v, &other.v),
            m: if self.authenticated() {
                pair(&self.m, &other.m)
            } else {
                Vec::new()
            },
        }
    }

    fn map(&self, f: impl Fn(Fp) -> Fp) -> Shared {
        let one = |a: &Vec<Vec<Fp>>| -> Vec<Vec<Fp>> {
            a.iter()
                .map(|x| x.iter().map(|p| f(*p)).collect())
                .collect()
        };
        Shared {
            v: one(&self.v),
            m: one(&self.m),
        }
    }

    pub fn add(&self, other: &Shared) -> Shared {
        self.zip_with(other, |a, b| a + b)
    }

    pub fn sub(&self, other: &Shared) -> Shared {
        self.zip_with(other, |a, b| a - b)
    }

    pub fn scale(&self, s: Fp) -> Shared {
        self.map(|a| a * s)
    }

    /// Element-wise product with public values.
    pub fn mul_public(&self, c: &[Fp]) -> Shared {
        debug_assert_eq!(c.len(), self.len());
        let f = |a: &Vec<Vec<Fp>>| -> Vec<Vec<Fp>> {
            a.iter()
                .map(|x| x.iter().zip(c).map(|(p, q)| *p * *q).collect())
                .collect()
        };
        Shared {
            v: f(&self.v),
            m: f(&self.m),
        }
    }

    /// Add public values. Party 0 adds them to its share. Every party adds
    /// `alpha_i * c` to its MAC share.
    pub fn add_public(&self, c: &[Fp], alpha_shares: &[Fp]) -> Shared {
        debug_assert_eq!(c.len(), self.len());
        let mut out = self.clone();
        for (j, cj) in c.iter().enumerate() {
            out.v[0][j] += *cj;
        }
        for (i, mi) in out.m.iter_mut().enumerate() {
            for (j, cj) in c.iter().enumerate() {
                mi[j] += alpha_shares[i] * *cj;
            }
        }
        out
    }

    pub fn add_const(&self, c: Fp, alpha_shares: &[Fp]) -> Shared {
        self.add_public(&vec![c; self.len()], alpha_shares)
    }

    /// Elements `idx` in order.
    pub fn gather(&self, idx: &[usize]) -> Shared {
        let g = |a: &Vec<Vec<Fp>>| -> Vec<Vec<Fp>> {
            a.iter()
                .map(|x| idx.iter().map(|&j| x[j]).collect())
                .collect()
        };
        Shared {
            v: g(&self.v),
            m: g(&self.m),
        }
    }

    pub fn slice(&self, start: usize, len: usize) -> Shared {
        let g = |a: &Vec<Vec<Fp>>| -> Vec<Vec<Fp>> {
            a.iter().map(|x| x[start..start + len].to_vec()).collect()
        };
        Shared {
            v: g(&self.v),
            m: g(&self.m),
        }
    }

    pub fn concat(parts: &[&Shared]) -> Shared {
        let parties = parts.first().map_or(0, |p| p.parties());
        let auth = parts.first().is_some_and(|p| p.authenticated());
        let mut out = Shared {
            v: vec![Vec::new(); parties],
            m: if auth {
                vec![Vec::new(); parties]
            } else {
                Vec::new()
            },
        };
        for p in parts {
            for i in 0..parties {
                out.v[i].extend_from_slice(&p.v[i]);
                if auth {
                    out.m[i].extend_from_slice(&p.m[i]);
                }
            }
        }
        out
    }

    /// Split into consecutive chunks of the given lengths.
    pub fn split(&self, lens: &[usize]) -> Vec<Shared> {
        let mut at = 0;
        lens.iter()
            .map(|&l| {
                let s = self.slice(at, l);
                at += l;
                s
            })
            .collect()
    }

    /// One shared value per row: `out[r] = sum_j coeffs[r][j] * self[cols[r][j]]`.
    /// Used for every public linear map (curves, selections, prefix sums).
    pub fn linear(&self, rows: &[Vec<(usize, Fp)>]) -> Shared {
        let g = |a: &Vec<Vec<Fp>>| -> Vec<Vec<Fp>> {
            a.iter()
                .map(|x| {
                    rows.iter()
                        .map(|r| r.iter().map(|(j, c)| x[*j] * *c).sum())
                        .collect()
                })
                .collect()
        };
        Shared {
            v: g(&self.v),
            m: g(&self.m),
        }
    }

    /// Sum of all elements, as a length-1 vector.
    pub fn total(&self) -> Shared {
        let g = |a: &Vec<Vec<Fp>>| -> Vec<Vec<Fp>> {
            a.iter().map(|x| vec![x.iter().copied().sum()]).collect()
        };
        Shared {
            v: g(&self.v),
            m: g(&self.m),
        }
    }

    /// Prefix sums: `out[j] = sum_{l < j} self[l]`, length `len + 1`.
    pub fn exclusive_prefix(&self) -> Shared {
        let g = |a: &Vec<Vec<Fp>>| -> Vec<Vec<Fp>> {
            a.iter()
                .map(|x| {
                    let mut acc = Fp::ZERO;
                    let mut out = Vec::with_capacity(x.len() + 1);
                    out.push(acc);
                    for p in x {
                        acc += *p;
                        out.push(acc);
                    }
                    out
                })
                .collect()
        };
        Shared {
            v: g(&self.v),
            m: g(&self.m),
        }
    }
}
