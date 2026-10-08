//! A test dealer built from the core crypto and the wire types
//! (Feldman VSS, as the KRC dealer deals): it deals each epoch once,
//! hands every member its share under the announcement it acks, and
//! returns the bundle the node receives. The members are the in-process
//! `KeyReleaseMember`s of the fake enclaves.

use std::sync::Arc;

use parking_lot::Mutex;
use rand::SeedableRng;
use rand::rngs::StdRng;
use timescales_core::crypto::{Keypair, SealSecret, hash};
use timescales_core::{EpochId, Hash32, MarketId};
use timescales_executor::tee::{EpochKeyDealer, HeldAnnouncement, KeyReleaseMember};
use timescales_service::wire::{
    CommitteeDescription, CommitteeMember, EpochKeyAck, EpochKeyAnnouncement, EpochKeyBundle,
    KeyScheme,
};

pub struct Dealer {
    pub market: [u8; 32],
    pub market_id: MarketId,
    pub committee: CommitteeDescription,
    identities: Vec<Keypair>,
    members: Vec<Arc<KeyReleaseMember>>,
    dealt: Mutex<std::collections::BTreeMap<u64, EpochKeyBundle>>,
    rng: Mutex<StdRng>,
}

impl Dealer {
    pub fn new(
        market: [u8; 32],
        market_id: MarketId,
        members: Vec<Arc<KeyReleaseMember>>,
        threshold: u8,
    ) -> Self {
        let identities: Vec<Keypair> = (0..members.len())
            .map(|i| {
                Keypair::from_seed(hash(b"test/member-identity", &[u8::try_from(i).unwrap()]).0)
            })
            .collect();
        let committee = CommitteeDescription {
            version: CommitteeDescription::VERSION,
            market,
            threshold,
            members: identities
                .iter()
                .enumerate()
                .map(|(i, id)| CommitteeMember {
                    index: u8::try_from(i + 1).unwrap(),
                    identity: id.public(),
                    transport: SealSecret::from_bytes(
                        hash(b"test/member-transport", &[u8::try_from(i).unwrap()]).0,
                    )
                    .public(),
                })
                .collect(),
        };
        committee.validate().unwrap();
        Self {
            market,
            market_id,
            committee,
            identities,
            members,
            dealt: Mutex::default(),
            rng: Mutex::new(StdRng::seed_from_u64(7)),
        }
    }

    /// The bundle of `epoch`, dealt on first use.
    pub fn bundle(&self, epoch: u64) -> EpochKeyBundle {
        if let Some(b) = self.dealt.lock().get(&epoch) {
            return b.clone();
        }
        let dealer = EpochKeyDealer {
            threshold: self.committee.threshold,
            members: u8::try_from(self.members.len()).unwrap(),
        };
        let dealt = dealer.deal(&mut *self.rng.lock()).unwrap();
        let announcement = EpochKeyAnnouncement {
            version: EpochKeyAnnouncement::VERSION,
            market: self.market,
            epoch: EpochId(epoch),
            committee_digest: self.committee.digest(),
            scheme: KeyScheme::FeldmanEd25519,
            epoch_pk: dealt.public,
            commitments: dealt.commitments,
        };
        let digest = announcement.digest();
        let held = HeldAnnouncement {
            digest,
            committee_digest: self.committee.digest(),
        };
        let mut acks = Vec::new();
        for ((member, share), identity) in
            self.members.iter().zip(dealt.shares).zip(&self.identities)
        {
            member
                .store_dealt_share(self.market_id, EpochId(epoch), share, held)
                .unwrap();
            let policy = hash(b"test/release-policy", &[member.index()]);
            acks.push(EpochKeyAck::sign(member.index(), &digest, policy, identity));
        }
        let bundle = EpochKeyBundle { announcement, acks };
        self.dealt.lock().insert(epoch, bundle.clone());
        bundle
    }

    pub fn committee_digest(&self) -> Hash32 {
        self.committee.digest()
    }
}
