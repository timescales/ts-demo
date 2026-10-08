//! Where executors get batch decryption keys from.

#[cfg(feature = "simulation")]
use hkdf::Hkdf;
#[cfg(feature = "simulation")]
use sha2::Sha256;
#[cfg(feature = "simulation")]
use timescales_core::crypto::Zeroizing;
use timescales_core::crypto::{EpochSecret, SealSecret};
use timescales_core::{EpochId, MarketId};

use crate::ExecutorError;

/// Source of per-epoch decryption keys.
///
/// The local implementation derives them from a seed. The TEE backend gets
/// them from a threshold key-release committee after attestation, and the
/// MPC backend never needs them at all.
pub trait KeyProvider: Send + Sync {
    fn epoch_public(&self, market: MarketId, epoch: EpochId) -> Result<[u8; 32], ExecutorError>;

    fn epoch_secret(&self, market: MarketId, epoch: EpochId) -> Result<SealSecret, ExecutorError>;

    /// The epoch's secret in the form envelopes are opened with. Providers
    /// of threshold-dealt keys override this.
    fn epoch_key(&self, market: MarketId, epoch: EpochId) -> Result<EpochSecret, ExecutorError> {
        self.epoch_secret(market, epoch).map(EpochSecret::Dev)
    }

    /// Feldman commitments `C_0..= C_{t-1}` (compressed Edwards points) of a
    /// threshold-dealt epoch key, which let an executor check every released
    /// share on its own. Empty when the provider does not know them. An
    /// executor then has to search share subsets for one that reproduces
    /// [`Self::epoch_public`].
    fn epoch_commitments(
        &self,
        _market: MarketId,
        _epoch: EpochId,
    ) -> Result<Vec<[u8; 32]>, ExecutorError> {
        Ok(Vec::new())
    }
}

/// Deterministic key schedule for local development and tests only. Anyone
/// with the seed can decrypt every epoch, so it exists only in builds with
/// the `simulation` feature. The seed and every derived key are wiped when
/// dropped.
#[cfg(feature = "simulation")]
pub struct LocalKeySchedule {
    seed: Zeroizing<[u8; 32]>,
}

#[cfg(feature = "simulation")]
impl core::fmt::Debug for LocalKeySchedule {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("LocalKeySchedule(..)")
    }
}

#[cfg(feature = "simulation")]
impl LocalKeySchedule {
    pub fn new(seed: [u8; 32]) -> Self {
        Self {
            seed: Zeroizing::new(seed),
        }
    }

    fn derive(&self, market: MarketId, epoch: EpochId) -> SealSecret {
        let hk = Hkdf::<Sha256>::new(Some(b"timescales/v1/local-epoch-key"), self.seed.as_ref());
        let mut info = [0u8; 16];
        info[..8].copy_from_slice(&market.0.to_le_bytes());
        info[8..].copy_from_slice(&epoch.0.to_le_bytes());
        let mut okm = Zeroizing::new([0u8; 32]);
        hk.expand(&info, okm.as_mut())
            .unwrap_or_else(|_| unreachable!());
        SealSecret::from_bytes(*okm)
    }
}

#[cfg(feature = "simulation")]
impl KeyProvider for LocalKeySchedule {
    fn epoch_public(&self, market: MarketId, epoch: EpochId) -> Result<[u8; 32], ExecutorError> {
        Ok(self.derive(market, epoch).public())
    }

    fn epoch_secret(&self, market: MarketId, epoch: EpochId) -> Result<SealSecret, ExecutorError> {
        Ok(self.derive(market, epoch))
    }
}
