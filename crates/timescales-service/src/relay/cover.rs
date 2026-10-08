//! Cover traffic.
//!
//! Cover envelopes seal `Noop` intents to the epoch key. Sealed, they have
//! the size of every other envelope, and only an executor that decrypts them
//! can tell them from orders. The relay pads each batch with them up to a
//! coarse bucket, so the published count says little about real demand.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use rand::Rng;
use rand_chacha::ChaCha20Rng;
use timescales_core::crypto::Signature;
use timescales_core::intent::{IntentBody, MaskedIntent, PrivateIntent, SealedEnvelope};
use timescales_core::{
    CommitmentScheme, Decode, DecodeError, Encode, EpochId, MarketId, MarketParams,
    OrderCommitment, Reader, encoding::put_u8,
};
use timescales_executor::KeyProvider;

/// Source of cover traffic: seals no-op intents to the epoch key.
pub trait CoverSource: Send + Sync {
    /// A fresh cover envelope for (`market`, `epoch`), with a masked no-op
    /// for MPC-capable markets.
    fn cover(
        &self,
        market: MarketId,
        epoch: EpochId,
        rng: &mut ChaCha20Rng,
    ) -> Result<(SealedEnvelope, Option<MaskedIntent>), String>;

    /// A no-op that was cover in the previous epoch, sealed again for `epoch`
    /// under a fresh ephemeral key and with the same commitment, or `None`
    /// when the source keeps none. The relay asks with probability
    /// [`RelayConfig::carry_p`](crate::relay::RelayConfig::carry_p) per cover slot.
    fn carry(
        &self,
        _market: MarketId,
        _epoch: EpochId,
        _rng: &mut ChaCha20Rng,
    ) -> Result<Option<(SealedEnvelope, Option<MaskedIntent>)>, String> {
        Ok(None)
    }

    /// The carried set as `(commitment, record)` pairs for the node's
    /// `cover_carry` table. A record contains its no-op's salt and so tells
    /// carried cover apart from resting orders: the node seals it under its
    /// KEK (AAD `market || C`) before writing it.
    fn export(&self) -> Vec<(OrderCommitment, Vec<u8>)> {
        Vec::new()
    }

    /// Restore a set written by [`CoverSource::export`] after a restart.
    /// Sources that carry nothing ignore it.
    fn import(&self, _carried: Vec<(OrderCommitment, Vec<u8>)>) -> Result<(), String> {
        Ok(())
    }
}

/// Seals fresh `Noop` intents to a published epoch key.
pub struct EpochKeyCover<K> {
    pub keys: Arc<K>,
    pub params: MarketParams,
    /// Also emit masked no-ops (MPC-capable markets).
    pub masked: bool,
}

impl<K> core::fmt::Debug for EpochKeyCover<K> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("EpochKeyCover")
    }
}

impl<K: KeyProvider> CoverSource for EpochKeyCover<K> {
    fn cover(
        &self,
        market: MarketId,
        epoch: EpochId,
        rng: &mut ChaCha20Rng,
    ) -> Result<(SealedEnvelope, Option<MaskedIntent>), String> {
        let (pi, c) =
            PrivateIntent::noop(rng, self.params.commitment_scheme).map_err(|e| e.to_string())?;
        seal_noop(self.keys.as_ref(), self.masked, market, epoch, c, &pi, rng)
    }
}

fn seal_noop<K: KeyProvider>(
    keys: &K,
    masked: bool,
    market: MarketId,
    epoch: EpochId,
    c: OrderCommitment,
    intent: &PrivateIntent,
    rng: &mut ChaCha20Rng,
) -> Result<(SealedEnvelope, Option<MaskedIntent>), String> {
    let pk = keys
        .epoch_public(market, epoch)
        .map_err(|e| e.to_string())?;
    let env =
        SealedEnvelope::seal(rng, market, epoch, &pk, c, intent).map_err(|e| e.to_string())?;
    Ok((env, masked.then(|| MaskedIntent::noop(market, epoch, c))))
}

/// Cover that recurs across epochs.
///
/// A resting order appears under the same commitment in consecutive batches
/// until it fills or expires. If every cover commitment were fresh, any
/// commitment seen in two consecutive batches would be a resting order.
/// `CarryingCover` remembers the no-ops it used as cover and, when the relay
/// asks ([`CoverSource::carry`]), seals one from the previous epoch again
/// under a fresh ephemeral key, so recurring commitments are cover too. A
/// carried no-op recurs in at most `max_order_lifetime + 1` consecutive
/// epochs, the longest run a real order can have.
///
/// Recurrence stays visible: carrying makes it ambiguous, it does not hide
/// it (disclosed).
pub struct CarryingCover<K> {
    keys: Arc<K>,
    params: MarketParams,
    masked: bool,
    state: Mutex<CarryState>,
}

impl<K> core::fmt::Debug for CarryingCover<K> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("CarryingCover")
    }
}

#[derive(Default)]
struct CarryState {
    /// Epoch the candidates were drawn for.
    epoch: Option<EpochId>,
    carried: BTreeMap<OrderCommitment, Carried>,
    /// No-ops of the previous epoch not yet carried into `epoch`.
    candidates: Vec<OrderCommitment>,
}

#[derive(Clone, Copy)]
struct Carried {
    intent: PrivateIntent,
    /// First and latest epoch whose batch held this no-op.
    first: EpochId,
    last: EpochId,
}

/// Version byte of an exported record:
/// `version u8 || first_epoch u64 || last_epoch u64 || PrivateIntent` (114 B).
const CARRY_RECORD_VERSION: u8 = 1;

impl Carried {
    /// Whether a no-op first used in `first` may still appear in `epoch`.
    fn within(first: EpochId, epoch: EpochId, lifetime: u64) -> bool {
        epoch
            .0
            .checked_sub(first.0)
            .is_some_and(|run| run <= lifetime)
    }

    fn to_bytes(self) -> Vec<u8> {
        let mut out = Vec::with_capacity(114);
        put_u8(&mut out, CARRY_RECORD_VERSION);
        self.first.encode(&mut out);
        self.last.encode(&mut out);
        self.intent.encode(&mut out);
        out
    }

    /// Errors never name the commitment: which commitments are carried
    /// cover is what the node's KEK protects, and errors end up in logs.
    fn from_bytes(
        bytes: &[u8],
        scheme: CommitmentScheme,
        commitment: &OrderCommitment,
    ) -> Result<Self, String> {
        let malformed = |e: DecodeError| format!("carried cover record: {e}");
        let mut r = Reader::new(bytes);
        let version = r.u8().map_err(malformed)?;
        if version != CARRY_RECORD_VERSION {
            return Err(format!("carried cover record: unknown version {version}"));
        }
        let first = EpochId::decode(&mut r).map_err(malformed)?;
        let last = EpochId::decode(&mut r).map_err(malformed)?;
        let intent = PrivateIntent::decode(&mut r).map_err(malformed)?;
        r.finish().map_err(malformed)?;
        if intent.body != IntentBody::Noop || intent.signature != Signature([0; 64]) {
            return Err("carried cover record: not a no-op".into());
        }
        if first > last {
            return Err("carried cover record: epochs out of order".into());
        }
        intent
            .verify(scheme, commitment)
            .map_err(|e| format!("carried cover record: {e}"))?;
        Ok(Self {
            intent,
            first,
            last,
        })
    }
}

impl CarryState {
    /// Move to `epoch`: forget what can no longer appear, and offer the
    /// previous epoch's no-ops as candidates.
    fn advance(&mut self, epoch: EpochId, lifetime: u64) {
        if self.epoch == Some(epoch) {
            return;
        }
        self.epoch = Some(epoch);
        self.carried.retain(|_, c| {
            (c.last == epoch || c.last.0.checked_add(1) == Some(epoch.0))
                && Carried::within(c.first, epoch, lifetime)
        });
        self.candidates = self
            .carried
            .iter()
            .filter(|(_, c)| c.last != epoch)
            .map(|(k, _)| *k)
            .collect();
    }
}

impl<K: KeyProvider> CarryingCover<K> {
    pub fn new(keys: Arc<K>, params: MarketParams, masked: bool) -> Self {
        Self {
            keys,
            params,
            masked,
            state: Mutex::new(CarryState::default()),
        }
    }

    /// Every critical section is a single map or list update, so a panic
    /// elsewhere cannot leave the carried set inconsistent, and cover keeps
    /// flowing after a poisoned lock.
    fn state(&self) -> MutexGuard<'_, CarryState> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn lifetime(&self) -> u64 {
        u64::from(self.params.max_order_lifetime)
    }
}

impl<K: KeyProvider> CoverSource for CarryingCover<K> {
    fn cover(
        &self,
        market: MarketId,
        epoch: EpochId,
        rng: &mut ChaCha20Rng,
    ) -> Result<(SealedEnvelope, Option<MaskedIntent>), String> {
        let (intent, c) =
            PrivateIntent::noop(rng, self.params.commitment_scheme).map_err(|e| e.to_string())?;
        let sealed = seal_noop(
            self.keys.as_ref(),
            self.masked,
            market,
            epoch,
            c,
            &intent,
            rng,
        )?;
        let mut st = self.state();
        st.advance(epoch, self.lifetime());
        st.carried.insert(
            c,
            Carried {
                intent,
                first: epoch,
                last: epoch,
            },
        );
        Ok(sealed)
    }

    fn carry(
        &self,
        market: MarketId,
        epoch: EpochId,
        rng: &mut ChaCha20Rng,
    ) -> Result<Option<(SealedEnvelope, Option<MaskedIntent>)>, String> {
        let picked = {
            let mut st = self.state();
            st.advance(epoch, self.lifetime());
            if st.candidates.is_empty() {
                return Ok(None);
            }
            let i = rng.gen_range(0..st.candidates.len());
            let c = st.candidates.swap_remove(i);
            st.carried.get(&c).map(|e| (c, e.intent))
        };
        let Some((c, intent)) = picked else {
            return Ok(None);
        };
        let sealed = seal_noop(
            self.keys.as_ref(),
            self.masked,
            market,
            epoch,
            c,
            &intent,
            rng,
        )?;
        if let Some(e) = self.state().carried.get_mut(&c) {
            e.last = epoch;
        }
        Ok(Some(sealed))
    }

    /// Only what can still be carried into the next epoch.
    fn export(&self) -> Vec<(OrderCommitment, Vec<u8>)> {
        let st = self.state();
        let lifetime = self.lifetime();
        st.carried
            .iter()
            .filter(|(_, c)| match st.epoch {
                Some(epoch) => {
                    c.last == epoch
                        && epoch
                            .0
                            .checked_add(1)
                            .is_some_and(|next| Carried::within(c.first, EpochId(next), lifetime))
                }
                None => true,
            })
            .map(|(k, c)| (*k, c.to_bytes()))
            .collect()
    }

    /// Checks every record (version, a no-op opening its commitment) before
    /// keeping any.
    fn import(&self, carried: Vec<(OrderCommitment, Vec<u8>)>) -> Result<(), String> {
        let scheme = self.params.commitment_scheme;
        let parsed = carried
            .into_iter()
            .map(|(c, bytes)| Carried::from_bytes(&bytes, scheme, &c).map(|r| (c, r)))
            .collect::<Result<Vec<_>, _>>()?;
        let mut st = self.state();
        st.carried.extend(parsed);
        // Candidates are drawn again for the next epoch asked for.
        st.epoch = None;
        st.candidates.clear();
        Ok(())
    }
}
