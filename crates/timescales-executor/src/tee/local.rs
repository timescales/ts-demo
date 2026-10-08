//! A complete simulated deployment in one process: vendor, platform,
//! verifier, policy, chain, committee, dealer and executor. Simulation only:
//! the dealer holds every epoch secret it deals, and anyone with the vendor
//! seed can forge evidence.

use std::collections::BTreeMap;
use std::sync::{Arc, RwLock};
use std::time::Duration;

use crate::attestation::Platform;
use crate::attestation::simulated::{SimulatedPlatform, SimulatedVendor};
use crate::policy::AttestationPolicy;
use crate::{ExecutorError, KeyFailure, KeyProvider};
use rand::SeedableRng;
use timescales_auction::BatchHeader;
use timescales_core::crypto::{CryptoError, ScalarSealSecret, SealSecret};
use timescales_core::{EpochId, MarketId};

use crate::tee::TeeExecutor;
use crate::tee::committee::{
    ChainView, CommitteeError, DealtEpoch, EpochKeyDealer, InMemoryChain, KeyReleaseMember,
    KeyReleaseService,
};
use crate::tee::enclave::{Enclave, Quoter, program_measurement};

/// An epoch's X25519 public key and, for a Feldman dealing, its
/// commitments.
type PublishedKey = ([u8; 32], Vec<[u8; 32]>);

/// Public epoch keys as published by the committee. Holds no secrets.
#[derive(Debug, Default)]
pub struct PublishedEpochKeys {
    keys: RwLock<BTreeMap<(MarketId, EpochId), PublishedKey>>,
}

impl PublishedEpochKeys {
    /// Publish a key without commitments.
    pub fn publish(&self, market: MarketId, epoch: EpochId, pk: [u8; 32]) {
        self.publish_dealing(market, epoch, pk, Vec::new());
    }

    /// Publish a key and the Feldman commitments it was dealt under.
    pub fn publish_dealing(
        &self,
        market: MarketId,
        epoch: EpochId,
        pk: [u8; 32],
        commitments: Vec<[u8; 32]>,
    ) {
        if let Ok(mut m) = self.keys.write() {
            m.insert((market, epoch), (pk, commitments));
        }
    }

    fn get(&self, market: MarketId, epoch: EpochId) -> Result<PublishedKey, ExecutorError> {
        self.keys
            .read()
            .ok()
            .and_then(|m| m.get(&(market, epoch)).cloned())
            .ok_or_else(|| ExecutorError::KeyUnavailable("epoch key not published".into()))
    }
}

impl KeyProvider for PublishedEpochKeys {
    fn epoch_public(&self, market: MarketId, epoch: EpochId) -> Result<[u8; 32], ExecutorError> {
        self.get(market, epoch).map(|(pk, _)| pk)
    }

    fn epoch_secret(&self, _: MarketId, _: EpochId) -> Result<SealSecret, ExecutorError> {
        Err(ExecutorError::KeyUnavailable(KeyFailure::new(
            "public directory holds no secrets",
        )))
    }

    fn epoch_commitments(
        &self,
        market: MarketId,
        epoch: EpochId,
    ) -> Result<Vec<[u8; 32]>, ExecutorError> {
        self.get(market, epoch).map(|(_, c)| c)
    }
}

pub struct LocalTeeDeployment {
    pub vendor: SimulatedVendor,
    pub chain: Arc<InMemoryChain>,
    pub members: Vec<Arc<KeyReleaseMember>>,
    pub keys: Arc<PublishedEpochKeys>,
    pub dealer: EpochKeyDealer,
    pub executor: TeeExecutor,
    rng: std::sync::Mutex<rand_chacha::ChaCha20Rng>,
}

impl core::fmt::Debug for LocalTeeDeployment {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("LocalTeeDeployment")
            .field("members", &self.members.len())
            .finish_non_exhaustive()
    }
}

impl LocalTeeDeployment {
    /// `n` members, threshold `t`, one platform at the vendor's current
    /// security version running the genuine program.
    ///
    /// # Panics
    ///
    /// If the committee is invalid (`t == 0`, `t > n` or `n > 16`).
    /// [`Self::try_new`] reports that instead.
    pub fn new(n: u8, t: u8, seed: u64) -> Self {
        match Self::try_new(n, t, seed) {
            Ok(dep) => dep,
            Err(e) => panic!("{e}"),
        }
    }

    pub fn try_new(n: u8, t: u8, seed: u64) -> Result<Self, CommitteeError> {
        let mut rng = rand_chacha::ChaCha20Rng::seed_from_u64(seed);
        let vendor = SimulatedVendor::new(&mut rng, 5);
        let platform: Arc<SimulatedPlatform> = Arc::new(vendor.platform(&mut rng, 5));
        Self::with_enclave(n, t, rng, vendor, platform, program_measurement(), false)
    }

    pub fn with_enclave(
        n: u8,
        t: u8,
        rng: rand_chacha::ChaCha20Rng,
        vendor: SimulatedVendor,
        quoter: Arc<dyn Quoter>,
        measurement: crate::attestation::Measurement,
        debug: bool,
    ) -> Result<Self, CommitteeError> {
        let chain = Arc::new(InMemoryChain::new([0x5a; 32]));
        let verifier = Arc::new(vendor.verifier());
        let policy = AttestationPolicy::strict([Platform::Simulated], [program_measurement()]);
        let enclave = Arc::new(Enclave::boot(quoter, measurement, debug));
        let members = (1..=n)
            .map(|i| {
                let m = KeyReleaseMember::new(i, verifier.clone(), policy.clone())?
                    .with_chain(chain.clone() as Arc<dyn ChainView>)
                    .accept_header_v1();
                // A fresh member cannot be poisoned, so registration succeeds.
                let _ = m.register_executor(enclave.executor_id());
                Ok(Arc::new(m))
            })
            .collect::<Result<Vec<_>, CommitteeError>>()?;
        let keys = Arc::new(PublishedEpochKeys::default());
        let committee: Vec<Arc<dyn KeyReleaseService>> = members
            .iter()
            .map(|m| Arc::new(m.serve(enclave.executor_id())) as Arc<dyn KeyReleaseService>)
            .collect();
        let executor =
            TeeExecutor::new(enclave, committee, t, keys.clone(), Duration::from_secs(5))?;
        Ok(Self {
            vendor,
            chain,
            members,
            keys,
            dealer: EpochKeyDealer {
                threshold: t,
                members: n,
            },
            executor,
            rng: rng.into(),
        })
    }

    /// Deal and distribute the key for one epoch and publish its public key
    /// and commitments. An epoch is dealt once: dealing it again returns the
    /// key already published.
    ///
    /// # Panics
    ///
    /// If `dealer` was changed to parameters the committee cannot use.
    pub fn prepare_epoch(&self, market: MarketId, epoch: EpochId) -> [u8; 32] {
        self.distribute(market, epoch, |dealer, rng| dealer.deal(rng))
    }

    /// As [`Self::prepare_epoch`] but also returns the epoch secret, so a
    /// reference executor can run the same batch. Differential testing only:
    /// in a deployment nobody holds the whole secret.
    pub fn prepare_epoch_with_secret(&self, market: MarketId, epoch: EpochId) -> SealSecret {
        let sk = {
            let mut rng = self.rng.lock().unwrap_or_else(|e| e.into_inner());
            SealSecret::generate(&mut *rng)
        };
        self.install_epoch_secret(market, epoch, &sk);
        sk
    }

    /// Split a given epoch secret across the committee (for running batches
    /// that were sealed with a locally held key, e.g. by the CLI). The
    /// members hold Feldman shares of its scalar form, which opens the same
    /// envelopes. Like [`Self::prepare_epoch`], an epoch is dealt once.
    pub fn install_epoch_secret(&self, market: MarketId, epoch: EpochId, sk: &SealSecret) {
        let secret = ScalarSealSecret::from_x25519(sk);
        self.distribute(market, epoch, |dealer, rng| {
            dealer.deal_secret(rng, &secret)
        });
    }

    fn distribute(
        &self,
        market: MarketId,
        epoch: EpochId,
        deal: impl FnOnce(
            &EpochKeyDealer,
            &mut rand_chacha::ChaCha20Rng,
        ) -> Result<DealtEpoch, CryptoError>,
    ) -> [u8; 32] {
        if let Ok(pk) = self.keys.epoch_public(market, epoch) {
            return pk;
        }
        let dealt = {
            let mut rng = self.rng.lock().unwrap_or_else(|e| e.into_inner());
            match deal(&self.dealer, &mut rng) {
                Ok(d) => d,
                Err(e) => panic!("dealing epoch {}: {e}", epoch.0),
            }
        };
        for (m, s) in self.members.iter().zip(dealt.shares) {
            if let Err(e) = m.store_share(market, epoch, s) {
                panic!("member {} refused its share: {e}", m.index());
            }
        }
        self.keys
            .publish_dealing(market, epoch, dealt.public, dealt.commitments);
        dealt.public
    }

    /// Record a pre-built batch on the chain, with the beacon its header
    /// carries.
    pub fn commit(&self, header: &BatchHeader) -> bool {
        self.chain.commit_revealed(
            header.market,
            header.epoch,
            header.batch_root,
            header.envelope_count,
            header.beacon,
        )
    }
}
