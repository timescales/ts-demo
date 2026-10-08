//! Epoch keys of one market: verified `EpochKeyBundle`s,
//! lookahead tracking and the replacement rule, and the [`KeyProvider`]
//! the relay's cover traffic seals to.
//!
//! A bundle is accepted only if it verifies against the configured
//! `CommitteeDescription`, whose digest must be the market's current or
//! previous committee digest on chain, with at least `t` member acks. A
//! stored bundle is never replaced once an epoch opened under it, anything
//! is parked for it or it was served in the park window (the store refuses
//! that), so traders never see two keys for one epoch.

use std::collections::BTreeMap;

use parking_lot::RwLock;
use thiserror::Error;
use timescales_core::crypto::SealSecret;
use timescales_core::{Decode, Encode, EpochId, Hash32, MarketId};
use timescales_executor::{ExecutorError, KeyFailure, KeyProvider};
use timescales_service::wire::{CommitteeDescription, EpochKeyBundle, KeyScheme};

use crate::Address;

#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum KeyError {
    #[error("bundle for market {0}, not this one")]
    WrongMarket(String),
    #[error("bundle for epoch {got}, stored as epoch {want}")]
    WrongEpoch { got: u64, want: u64 },
    #[error("bundle does not verify: {0}")]
    Invalid(String),
    #[error("the development key scheme is not accepted")]
    DevScheme,
    #[error("a different bundle is stored for epoch {0}")]
    Conflict(u64),
    #[error("bundle does not decode: {0}")]
    Decode(String),
}

/// One verified bundle and what the node uses of it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedBundle {
    pub epoch: u64,
    pub bundle: EpochKeyBundle,
    /// Canonical bytes, as stored and served.
    pub bytes: Vec<u8>,
    pub epoch_pk: [u8; 32],
    pub key_digest: Hash32,
    pub committee_digest: Hash32,
}

/// Verified bundles of one market.
#[derive(Debug)]
pub struct KeyDirectory {
    market: Address,
    market_id: MarketId,
    committee: CommitteeDescription,
    /// Committee digests the chain recognises: current and previous.
    allowed: RwLock<Vec<Hash32>>,
    bundles: RwLock<BTreeMap<u64, VerifiedBundle>>,
}

impl KeyDirectory {
    pub fn new(market: Address, market_id: MarketId, committee: CommitteeDescription) -> Self {
        let digest = committee.digest();
        Self {
            market,
            market_id,
            committee,
            allowed: RwLock::new(vec![digest]),
            bundles: RwLock::new(BTreeMap::new()),
        }
    }

    pub fn committee(&self) -> &CommitteeDescription {
        &self.committee
    }

    /// The committee digests the chain holds now (`Market.committee_digest`
    /// and the non-zero `prev_committee_digest`).
    pub fn set_allowed(&self, current: Hash32, previous: Hash32) {
        let mut allowed = vec![current];
        if previous != Hash32::ZERO {
            allowed.push(previous);
        }
        *self.allowed.write() = allowed;
    }

    pub fn allowed(&self) -> Vec<Hash32> {
        self.allowed.read().clone()
    }

    /// Checks `bytes` as the bundle of `epoch` without storing it.
    pub fn verify(&self, epoch: u64, bytes: &[u8]) -> Result<VerifiedBundle, KeyError> {
        let bundle =
            EpochKeyBundle::decode_exact(bytes).map_err(|e| KeyError::Decode(e.to_string()))?;
        self.verify_bundle(epoch, bundle)
    }

    pub fn verify_bundle(
        &self,
        epoch: u64,
        bundle: EpochKeyBundle,
    ) -> Result<VerifiedBundle, KeyError> {
        let a = &bundle.announcement;
        if a.market != self.market {
            return Err(KeyError::WrongMarket(bs58::encode(a.market).into_string()));
        }
        if a.epoch.0 != epoch {
            return Err(KeyError::WrongEpoch {
                got: a.epoch.0,
                want: epoch,
            });
        }
        if a.scheme != KeyScheme::FeldmanEd25519 {
            return Err(KeyError::DevScheme);
        }
        let allowed = self.allowed();
        let (epoch_pk, _) = bundle
            .verify(&self.committee, &allowed, false)
            .map_err(|e| KeyError::Invalid(e.to_string()))?;
        Ok(VerifiedBundle {
            epoch,
            key_digest: a.digest(),
            committee_digest: a.committee_digest,
            bytes: bundle.to_bytes(),
            epoch_pk,
            bundle,
        })
    }

    /// Keeps a verified bundle. A different bundle for an epoch already
    /// held is refused. The store applies the stricter rule.
    pub fn insert(&self, v: VerifiedBundle) -> Result<(), KeyError> {
        let mut bundles = self.bundles.write();
        match bundles.get(&v.epoch) {
            Some(held) if held.bytes == v.bytes => Ok(()),
            Some(_) => Err(KeyError::Conflict(v.epoch)),
            None => {
                bundles.insert(v.epoch, v);
                Ok(())
            }
        }
    }

    /// Replaces a held bundle the store accepted as a replacement.
    pub fn replace(&self, v: VerifiedBundle) {
        self.bundles.write().insert(v.epoch, v);
    }

    pub fn get(&self, epoch: u64) -> Option<VerifiedBundle> {
        self.bundles.read().get(&epoch).cloned()
    }

    pub fn contains(&self, epoch: u64) -> bool {
        self.bundles.read().contains_key(&epoch)
    }

    /// Drops bundles of epochs before `epoch` (their epochs are terminal).
    pub fn forget_before(&self, epoch: u64) {
        let mut bundles = self.bundles.write();
        *bundles = bundles.split_off(&epoch);
    }

    /// Drops the bundles whose committee the chain no longer recognises.
    /// Returns their epochs (emergency rotation).
    pub fn drop_unrecognised(&self) -> Vec<u64> {
        let allowed = self.allowed();
        let mut bundles = self.bundles.write();
        let gone: Vec<u64> = bundles
            .iter()
            .filter(|(_, b)| !allowed.contains(&b.committee_digest))
            .map(|(e, _)| *e)
            .collect();
        for e in &gone {
            bundles.remove(e);
        }
        gone
    }

    /// Consecutive verified bundles after `epoch`.
    pub fn ready_ahead(&self, epoch: u64) -> u32 {
        let bundles = self.bundles.read();
        let mut n = 0u32;
        let mut next = epoch.saturating_add(1);
        while bundles.contains_key(&next) {
            n = n.saturating_add(1);
            next = next.saturating_add(1);
        }
        n
    }

    /// Epochs with a verified bundle, ascending.
    pub fn epochs(&self) -> Vec<u64> {
        self.bundles.read().keys().copied().collect()
    }
}

impl KeyProvider for KeyDirectory {
    fn epoch_public(&self, market: MarketId, epoch: EpochId) -> Result<[u8; 32], ExecutorError> {
        if market != self.market_id {
            return Err(ExecutorError::KeyUnavailable(KeyFailure::new(
                "epoch key of another market",
            )));
        }
        self.get(epoch.0).map(|b| b.epoch_pk).ok_or_else(|| {
            ExecutorError::KeyUnavailable(KeyFailure::new("no verified bundle for the epoch"))
        })
    }

    fn epoch_secret(&self, _: MarketId, _: EpochId) -> Result<SealSecret, ExecutorError> {
        Err(ExecutorError::KeyUnavailable(KeyFailure::new(
            "the node never holds epoch secrets",
        )))
    }

    fn epoch_commitments(
        &self,
        _market: MarketId,
        epoch: EpochId,
    ) -> Result<Vec<[u8; 32]>, ExecutorError> {
        Ok(self
            .get(epoch.0)
            .map(|b| b.bundle.announcement.commitments)
            .unwrap_or_default())
    }
}
