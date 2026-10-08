//! The trusted dealer: write-ahead dealing, re-sending the same
//! stored ciphertexts, ack collection, bundles to the node, recovery after
//! the loss of `dealer.sqlite` without ever dealing an epoch twice, and the
//! emergency rotation. Members run in process behind `DealerLinks`. The
//! last test runs everything over loopback HTTP.

#![allow(clippy::unwrap_used)]

use super::common;

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use common::*;
use parking_lot::Mutex;
use tempfile::TempDir;
use timescales_chain::Address;
use timescales_core::{Decode, Encode, EpochId, Hash32};
use timescales_krc::config::{DealerConfig, MarketEntry};
use timescales_krc::dealer::{DealError, Dealer, DealerLinks, Delivered, LinkError};
use timescales_krc::member::{Member, ShareRefusal};
use timescales_krc::{BoxFuture, KrcChain};
use timescales_service::store::dealer::DealerRepo;
use timescales_service::store::{Schema, Store, StoreOptions};
use timescales_service::wire::{AnnouncementReply, EpochKeyBundle, ShareDelivery};
use timescales_service::{ClientError, Profile};
use tokio_util::sync::CancellationToken;

const N: u8 = 3;
const T: u8 = 2;
const KEYS: u8 = 1;
/// The last committed epoch. The window is (LC, LC + LOOKAHEAD].
const LC: u64 = 4;
const E: u64 = LC + 1;
const LOOKAHEAD: u64 = 3;

/// Members in process, with faults the tests switch on.
#[derive(Default)]
struct Links {
    members: Mutex<Vec<Arc<Member>>>,
    /// Members that do not answer at all.
    down: Mutex<BTreeSet<u8>>,
    /// Members that answer queries but whose deliveries are lost.
    lose_deliveries: Mutex<BTreeSet<u8>>,
    /// Every delivery that reached a member: (member, bytes).
    sent: Mutex<Vec<(u8, Vec<u8>)>>,
    /// What the node holds, per epoch.
    node: Mutex<BTreeMap<u64, Vec<u8>>>,
    node_down: Mutex<bool>,
}

fn unreachable() -> LinkError {
    LinkError::Client(ClientError::Transport("unreachable".into()))
}

impl Links {
    fn member(&self, i: u8) -> Arc<Member> {
        Arc::clone(&self.members.lock()[usize::from(i - 1)])
    }

    fn sent(&self) -> Vec<(u8, Vec<u8>)> {
        self.sent.lock().clone()
    }
}

impl DealerLinks for Links {
    fn deliver(
        &self,
        _: Address,
        member: u8,
        delivery: Vec<u8>,
    ) -> BoxFuture<'_, Result<Delivered, LinkError>> {
        Box::pin(async move {
            if self.down.lock().contains(&member) || self.lose_deliveries.lock().contains(&member) {
                return Err(unreachable());
            }
            self.sent.lock().push((member, delivery.clone()));
            let d = ShareDelivery::decode_exact(&delivery).unwrap();
            match self
                .member(member)
                .accept_share(dealer_key().public(), d)
                .await
            {
                Ok(ack) => Ok(Delivered::Ack(ack)),
                Err(ShareRefusal::SecondAnnouncement { .. }) => Ok(Delivered::Conflict(None)),
                Err(_) => Err(LinkError::Answer("refused")),
            }
        })
    }

    fn query(
        &self,
        market: Address,
        member: u8,
        epoch: EpochId,
    ) -> BoxFuture<'_, Result<AnnouncementReply, LinkError>> {
        Box::pin(async move {
            if self.down.lock().contains(&member) {
                return Err(unreachable());
            }
            let held = self
                .member(member)
                .announcement(market, epoch)
                .await
                .map_err(|_| LinkError::Answer("query failed"))?;
            Ok(AnnouncementReply(held))
        })
    }

    fn put_bundle(
        &self,
        _: Address,
        epoch: EpochId,
        bundle: Vec<u8>,
    ) -> BoxFuture<'_, Result<(), LinkError>> {
        Box::pin(async move {
            if *self.node_down.lock() {
                return Err(unreachable());
            }
            self.node.lock().insert(epoch.0, bundle);
            Ok(())
        })
    }
}

struct World {
    dir: TempDir,
    chain: Chain,
    committee: Committee,
    committee_file: PathBuf,
    links: Arc<Links>,
    member_dirs: Vec<TempDir>,
}

fn dealer_config(dir: &Path, committee_file: PathBuf, member_urls: Vec<String>) -> DealerConfig {
    DealerConfig {
        profile: Profile::Local,
        data_dir: dir.join("dealer"),
        identity_key: dir.join("dealer.hex"),
        lookahead_epochs: LOOKAHEAD,
        interval_ms: 20,
        ack_timeout_ms: 2_000,
        node_url: "http://127.0.0.1:9".into(),
        node_identity: hex::encode([0x4e; 32]),
        ops_listen: "127.0.0.1:0".into(),
        member_urls,
        tls: None,
        markets: vec![MarketEntry {
            address: b58(&market_address()),
            committee_file,
        }],
        chain: timescales_krc::config::ChainConfig {
            rpc_agree: 1,
            release_commitment: None,
            confirmed_cache_ms: None,
            ..chain_config()
        },
        telemetry: telemetry(),
    }
}

impl World {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let committee = committee(market_address(), N, T, KEYS);
        let committee_file = dir.path().join("committee.bin");
        committee.write(&committee_file);
        let mut market = market_account(committee.digest(), &[[0xee; 32]]);
        market.last_committed = LC;
        market.last_settled = LC;
        let chain = Chain::new(market);
        let member_dirs: Vec<TempDir> = (0..N).map(|_| tempfile::tempdir().unwrap()).collect();
        let links = Arc::new(Links::default());
        let w = Self {
            dir,
            chain,
            committee,
            committee_file,
            links,
            member_dirs,
        };
        w.open_members(&w.committee_file.clone());
        w
    }

    /// (Re)opens every member with `committee_file` as its configuration.
    fn open_members(&self, committee_file: &Path) {
        let members = (1..=N)
            .map(|i| {
                let dir = self.member_dirs[usize::from(i - 1)].path();
                let cfg = member_config(dir, i, committee_file.to_path_buf());
                Arc::new(open_member(
                    dir,
                    cfg,
                    KEYS,
                    Arc::clone(&self.chain.krc()) as Arc<dyn KrcChain>,
                ))
            })
            .collect();
        *self.links.members.lock() = members;
    }

    fn repo(&self, db: &str) -> DealerRepo {
        std::fs::create_dir_all(self.dir.path().join("dealer")).unwrap();
        DealerRepo::new(
            Store::open(
                &self.dir.path().join("dealer").join(db),
                Schema::Dealer,
                StoreOptions::default(),
            )
            .unwrap(),
        )
    }

    /// A dealer process over `db`. A new file is a lost database.
    fn dealer(&self, db: &str) -> Dealer {
        self.dealer_with(db, self.committee_file.clone())
    }

    fn dealer_with(&self, db: &str, committee_file: PathBuf) -> Dealer {
        let urls = (1..=N).map(|i| format!("http://127.0.0.1:{i}")).collect();
        Dealer::with_links(
            dealer_config(self.dir.path(), committee_file, urls),
            Arc::new(dealer_key()),
            self.repo(db),
            Arc::clone(&self.chain.rpc),
            Arc::clone(&self.links) as Arc<dyn DealerLinks>,
        )
        .unwrap()
    }

    async fn held(&self, member: u8, epoch: u64) -> Option<Hash32> {
        self.links
            .member(member)
            .announcement(market_address(), EpochId(epoch))
            .await
            .unwrap()
            .map(|(a, _)| a.digest())
    }

    fn second_announcements(&self) -> u64 {
        self.links
            .members
            .lock()
            .iter()
            .map(|m| m.metrics().second_announcement.get())
            .sum()
    }
}

#[tokio::test]
async fn deals_once_and_delivers_the_bundle_to_the_node() {
    let w = World::new();
    let dealer = w.dealer("dealer.sqlite");
    let bundle = dealer.deal_one(market_address(), EpochId(E)).await.unwrap();
    let (epoch_pk, vouched) = bundle
        .verify(&w.committee.desc, &[w.committee.digest()], false)
        .unwrap();
    assert_eq!(epoch_pk, bundle.announcement.epoch_pk);
    assert_eq!(vouched.len(), 3);
    for (member, policy) in vouched {
        assert_eq!(policy, w.links.member(member).policy().digest());
        assert_eq!(w.held(member, E).await, Some(bundle.announcement.digest()));
    }
    assert_eq!(
        EpochKeyBundle::decode_exact(&w.links.node.lock()[&E]).unwrap(),
        bundle
    );
    // Delivered: the stored ciphertexts are gone.
    let d = w
        .repo("dealer.sqlite")
        .dealing(market_address(), E)
        .await
        .unwrap()
        .unwrap();
    assert!(d.bundle_delivered);
    assert!(d.deliveries.is_empty());

    // Idempotent: the same bundle, nothing sent again.
    let sent = w.links.sent().len();
    assert_eq!(
        dealer.deal_one(market_address(), EpochId(E)).await.unwrap(),
        bundle
    );
    assert_eq!(w.links.sent().len(), sent);
    assert_eq!(dealer.metrics().dealt_count("dealt"), 1);
}

#[tokio::test]
async fn a_crash_between_recording_and_sending_resends_the_same_ciphertexts() {
    let w = World::new();
    w.links.lose_deliveries.lock().extend([1, 2, 3]);
    let dealer = w.dealer("dealer.sqlite");
    assert!(matches!(
        dealer.deal_one(market_address(), EpochId(E)).await,
        Err(DealError::NotEnoughAcks { got: 0, need: 2 })
    ));
    drop(dealer);
    let recorded = w
        .repo("dealer.sqlite")
        .dealing(market_address(), E)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(recorded.deliveries.len(), 3);
    assert!(w.links.sent().is_empty());

    // The restarted dealer sends exactly what it recorded.
    w.links.lose_deliveries.lock().clear();
    let dealer = w.dealer("dealer.sqlite");
    let bundle = dealer.deal_one(market_address(), EpochId(E)).await.unwrap();
    let sent: BTreeSet<(u8, Vec<u8>)> = w.links.sent().into_iter().collect();
    let stored: BTreeSet<(u8, Vec<u8>)> = recorded.deliveries.into_iter().collect();
    assert_eq!(sent, stored);
    assert_eq!(bundle.announcement.to_bytes(), recorded.announcement);
    assert_eq!(dealer.metrics().dealt_count("dealt"), 0);
}

#[tokio::test]
async fn acks_are_collected_from_members_that_have_not_acked_yet() {
    let w = World::new();
    w.links.lose_deliveries.lock().extend([2, 3]);
    let dealer = w.dealer("dealer.sqlite");
    assert!(matches!(
        dealer.deal_one(market_address(), EpochId(E)).await,
        Err(DealError::NotEnoughAcks { got: 1, need: 2 })
    ));
    w.links.lose_deliveries.lock().remove(&2);
    let bundle = dealer.deal_one(market_address(), EpochId(E)).await.unwrap();
    let members: Vec<u8> = bundle.acks.iter().map(|a| a.member).collect();
    assert_eq!(members, [1, 2]);
    // Member 1 acked the first time and was not sent its share again.
    let to_one = w.links.sent().iter().filter(|(m, _)| *m == 1).count();
    assert_eq!(to_one, 1);
}

#[tokio::test]
async fn the_bundle_is_written_ahead_and_sent_again_after_a_node_failure() {
    let w = World::new();
    *w.links.node_down.lock() = true;
    let dealer = w.dealer("dealer.sqlite");
    assert!(matches!(
        dealer.deal_one(market_address(), EpochId(E)).await,
        Err(DealError::Node(_))
    ));
    let d = w
        .repo("dealer.sqlite")
        .dealing(market_address(), E)
        .await
        .unwrap()
        .unwrap();
    let intent = d.bundle.unwrap();
    assert!(!d.bundle_delivered);
    *w.links.node_down.lock() = false;
    let sent = w.links.sent().len();
    let bundle = dealer.deal_one(market_address(), EpochId(E)).await.unwrap();
    assert_eq!(w.links.node.lock()[&E], intent);
    assert_eq!(EpochKeyBundle::decode_exact(&intent).unwrap(), bundle);
    assert_eq!(w.links.sent().len(), sent, "no share is sent twice");
}

#[tokio::test]
async fn recovery_after_database_loss_adopts_and_never_deals_again() {
    let w = World::new();
    let dealer = w.dealer("dealer.sqlite");
    let mut originals = BTreeMap::new();
    for e in E..E + 2 {
        originals.insert(
            e,
            dealer.deal_one(market_address(), EpochId(e)).await.unwrap(),
        );
    }
    drop(dealer);
    w.links.node.lock().clear();
    let sent = w.links.sent().len();

    // dealer.sqlite is gone.
    let dealer = w.dealer("replacement.sqlite");
    let report = dealer.recover(market_address()).await.unwrap();
    assert_eq!(report.adopted, [E, E + 1]);
    assert_eq!(report.rebuilt_bundles, [E, E + 1]);
    assert!(report.undealable.is_empty());
    assert_eq!(dealer.metrics().recoveries.get(), 1);
    for (e, original) in &originals {
        assert_eq!(
            EpochKeyBundle::decode_exact(&w.links.node.lock()[e]).unwrap(),
            *original
        );
        assert_eq!(
            dealer
                .deal_one(market_address(), EpochId(*e))
                .await
                .unwrap(),
            *original
        );
    }
    // Nothing was dealt or sent again. The members hold what they held.
    assert_eq!(w.links.sent().len(), sent);
    assert_eq!(dealer.metrics().dealt_count("dealt"), 0);
    assert_eq!(w.second_announcements(), 0);
    // The rest of the window is dealt as usual.
    let next = dealer
        .deal_one(market_address(), EpochId(E + 2))
        .await
        .unwrap();
    assert!(
        !originals
            .values()
            .any(|b| b.announcement == next.announcement)
    );
}

#[tokio::test]
async fn an_epoch_with_fewer_than_t_acks_stays_undealt_after_database_loss() {
    let w = World::new();
    w.links.lose_deliveries.lock().extend([2, 3]);
    let dealer = w.dealer("dealer.sqlite");
    assert!(dealer.deal_one(market_address(), EpochId(E)).await.is_err());
    let original = w.held(1, E).await.unwrap();
    drop(dealer);
    w.links.lose_deliveries.lock().clear();
    let sent = w.links.sent().len();

    let dealer = w.dealer("replacement.sqlite");
    let report = dealer.recover(market_address()).await.unwrap();
    assert_eq!(report.adopted, [E]);
    assert_eq!(report.undealable, [E]);
    assert!(matches!(
        dealer.deal_one(market_address(), EpochId(E)).await,
        Err(DealError::Undealable(e)) if e == E
    ));
    assert_eq!(w.links.sent().len(), sent);
    assert_eq!(w.held(1, E).await, Some(original));
    assert_eq!(w.held(2, E).await, None);
    assert!(!w.links.node.lock().contains_key(&E));
}

#[tokio::test]
async fn recovery_waits_until_enough_members_answer() {
    let w = World::new();
    w.links.down.lock().extend([2, 3]);
    let dealer = w.dealer("dealer.sqlite");
    assert!(matches!(
        dealer.deal_one(market_address(), EpochId(E)).await,
        Err(DealError::Unconfirmed(e)) if e == E
    ));
    assert!(
        w.repo("dealer.sqlite")
            .dealing(market_address(), E)
            .await
            .unwrap()
            .is_none()
    );
    // n - t + 1 = 2 answers suffice.
    w.links.down.lock().remove(&2);
    w.links.lose_deliveries.lock().insert(3);
    dealer.deal_one(market_address(), EpochId(E)).await.unwrap();
}

#[tokio::test]
async fn deals_only_within_the_lookahead_and_for_the_committee_on_chain() {
    let w = World::new();
    let dealer = w.dealer("dealer.sqlite");
    assert!(matches!(
        dealer
            .deal_one(market_address(), EpochId(LC + LOOKAHEAD + 1))
            .await,
        Err(DealError::TooFarAhead { .. })
    ));
    assert!(matches!(
        dealer.deal_one(market_address(), EpochId(LC)).await,
        Err(DealError::Undealable(_))
    ));
    w.chain
        .update_market(|m| m.committee_digest = Hash32([0xcc; 32]));
    assert!(matches!(
        dealer.deal_one(market_address(), EpochId(E)).await,
        Err(DealError::CommitteeMismatch)
    ));
    assert_eq!(dealer.metrics().committee_mismatch.get(), 1);
    assert!(w.links.sent().is_empty());
}

#[tokio::test]
async fn run_keeps_the_window_dealt() {
    let w = World::new();
    let dealer = w.dealer("dealer.sqlite");
    let metrics = dealer.metrics().clone();
    let stop = CancellationToken::new();
    let task = tokio::spawn(dealer.run(stop.clone()));
    let window: Vec<u64> = (LC + 1..=LC + LOOKAHEAD).collect();
    for _ in 0..500 {
        if window.iter().all(|e| w.links.node.lock().contains_key(e)) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    stop.cancel();
    task.await.unwrap().unwrap();
    for e in &window {
        assert!(
            w.links.node.lock().contains_key(e),
            "epoch {e} has no bundle"
        );
    }
    assert_eq!(
        metrics.lookahead_epochs.get(),
        i64::try_from(LOOKAHEAD).unwrap()
    );
    assert_eq!(metrics.pending_deliveries.get(), 0);
}

#[tokio::test]
async fn an_emergency_rotation_supersedes_and_deals_again_under_the_new_committee() {
    let w = World::new();
    let dealer = w.dealer("dealer.sqlite");
    let old = dealer.deal_one(market_address(), EpochId(E)).await.unwrap();
    drop(dealer);

    // SetCommitteeDigest applied. Members and dealer move to committee B.
    let new_committee = committee(market_address(), N, 3, KEYS);
    let file = w.dir.path().join("committee-b.bin");
    new_committee.write(&file);
    w.chain.update_market(|m| {
        m.prev_committee_digest = w.committee.digest();
        m.committee_digest = new_committee.digest();
    });
    w.open_members(&file);
    let dealer = w.dealer_with("dealer.sqlite", file);
    // Before superseding, the old committee's bundle stands.
    assert_eq!(
        dealer.deal_one(market_address(), EpochId(E)).await.unwrap(),
        old
    );

    assert_eq!(
        dealer
            .supersede(market_address(), EpochId(E))
            .await
            .unwrap(),
        1
    );
    let new = dealer.deal_one(market_address(), EpochId(E)).await.unwrap();
    assert_ne!(new.announcement, old.announcement);
    new.verify(&new_committee.desc, &[new_committee.digest()], false)
        .unwrap();
    for i in 1..=N {
        assert_eq!(w.held(i, E).await, Some(new.announcement.digest()));
    }
    assert_eq!(w.second_announcements(), 0);
}
