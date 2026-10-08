//! The dealer and three members over loopback HTTP, with a stand-in node
//! that accepts `KeyBundlePut` envelopes: `Dealer::new` builds its own
//! `SignedClient`s, and a member holding another announcement answers the
//! dealer with a signed 409.

#![allow(clippy::unwrap_used)]

use super::common;

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use axum::extract::{FromRef, Path, State};
use axum::response::Response;
use axum::routing::post;
use common::*;
use parking_lot::Mutex;
use timescales_core::crypto::Keypair;
use timescales_core::{Decode, EpochId};
use timescales_krc::config::{ChainConfig, DealerConfig, MarketEntry};
use timescales_krc::dealer::Dealer;
use timescales_krc::member::router;
use timescales_service::store::dealer::DealerRepo;
use timescales_service::store::{Schema, Store, StoreOptions};
use timescales_service::wire::{EpochKeyBundle, MessageKind, ReplayGuard};
use timescales_service::{EnvelopeAuth, HttpLimits, Profile, VerifiedEnvelope, sealed_response};

const LC: u64 = 4;
const E: u64 = LC + 1;

fn node_key() -> Keypair {
    Keypair::from_seed([0x4e; 32])
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis()
        .try_into()
        .unwrap()
}

/// Bundles the stand-in node received, by (market, epoch).
type Bundles = Arc<Mutex<BTreeMap<(String, u64), Vec<u8>>>>;

#[derive(Clone)]
struct Node {
    auth: EnvelopeAuth,
    bundles: Bundles,
}

impl FromRef<Node> for EnvelopeAuth {
    fn from_ref(n: &Node) -> Self {
        n.auth.clone()
    }
}

async fn put_key(
    State(node): State<Node>,
    Path((market, epoch)): Path<(String, u64)>,
    env: VerifiedEnvelope,
) -> Response {
    assert_eq!(env.kind, MessageKind::KeyBundlePut);
    node.bundles.lock().insert((market, epoch), env.body);
    sealed_response(
        MessageKind::Empty,
        &node_key(),
        env.sender,
        now_ms(),
        Vec::new(),
    )
}

async fn listen(app: axum::Router) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    format!("http://{addr}")
}

#[tokio::test]
async fn deals_over_http_and_reads_a_members_conflict() {
    let dir = tempfile::tempdir().unwrap();
    let committee = committee(market_address(), 3, 2, 1);
    let file = dir.path().join("committee.bin");
    committee.write(&file);
    let mut market = market_account(committee.digest(), &[[0xee; 32]]);
    market.last_committed = LC;
    market.last_settled = LC;
    let chain = Chain::new(market);

    let limits = HttpLimits {
        max_body_bytes: MessageKind::ReleaseRequest.max_envelope_len(),
        request_timeout: Duration::from_secs(10),
        max_concurrency: 16,
        per_caller_rps: 100,
        per_caller_burst: 100,
    };
    let mut member_dirs = Vec::new();
    let mut members = Vec::new();
    let mut urls = Vec::new();
    for i in 1..=3u8 {
        let d = tempfile::tempdir().unwrap();
        let cfg = member_config(d.path(), i, file.clone());
        let m = Arc::new(open_member(d.path(), cfg, 1, chain.krc()));
        urls.push(listen(router(Arc::clone(&m), limits)).await);
        members.push(m);
        member_dirs.push(d);
    }
    let dealer_pub = dealer_key().public();
    let node = Node {
        auth: EnvelopeAuth {
            me: node_key().public(),
            allowed: Arc::new(move |s: &[u8; 32], k| {
                *s == dealer_pub && k == MessageKind::KeyBundlePut
            }),
            replay: Arc::new(ReplayGuard::new(1024, 60_000)),
            skew_ms: 30_000,
            now_ms: Arc::new(now_ms),
        },
        bundles: Arc::default(),
    };
    let node_url = listen(
        axum::Router::new()
            .route(
                "/internal/v1/markets/{market}/epochs/{epoch}/key",
                post(put_key),
            )
            .with_state(node.clone()),
    )
    .await;

    let cfg = DealerConfig {
        profile: Profile::Local,
        data_dir: dir.path().join("dealer"),
        identity_key: dir.path().join("dealer.hex"),
        lookahead_epochs: 3,
        interval_ms: 1000,
        ack_timeout_ms: 5000,
        node_url,
        node_identity: hex::encode(node_key().public()),
        ops_listen: "127.0.0.1:0".into(),
        member_urls: urls,
        tls: None,
        markets: vec![MarketEntry {
            address: b58(&market_address()),
            committee_file: file,
        }],
        chain: ChainConfig {
            rpc_agree: 1,
            release_commitment: None,
            confirmed_cache_ms: None,
            ..chain_config()
        },
        telemetry: telemetry(),
    };
    std::fs::create_dir_all(&cfg.data_dir).unwrap();
    let repo = DealerRepo::new(
        Store::open(
            &cfg.data_dir.join("dealer.sqlite"),
            Schema::Dealer,
            StoreOptions::default(),
        )
        .unwrap(),
    );
    let dealer = Dealer::new(cfg, dealer_key(), repo, Arc::clone(&chain.rpc)).unwrap();
    // The members hold nothing yet (the recovery queries go over HTTP too).
    let report = dealer.recover(market_address()).await.unwrap();
    assert!(report.adopted.is_empty());

    // Then member 1 is handed another announcement for E, as a second
    // dealer holding the dealer key could.
    let rogue = deal(&committee, E);
    members[0]
        .accept_share(dealer_key().public(), rogue.deliveries[0].clone())
        .await
        .unwrap();

    let bundle = dealer.deal_one(market_address(), EpochId(E)).await.unwrap();
    // Member 1 refused with 409. Members 2 and 3 vouch.
    let acked: Vec<u8> = bundle.acks.iter().map(|a| a.member).collect();
    assert_eq!(acked, [2, 3]);
    assert_ne!(bundle.announcement, rogue.announcement);
    bundle
        .verify(&committee.desc, &[committee.digest()], false)
        .unwrap();
    assert_eq!(members[0].metrics().second_announcement.get(), 1);
    let stored = node.bundles.lock()[&(b58(&market_address()), E)].clone();
    assert_eq!(EpochKeyBundle::decode_exact(&stored).unwrap(), bundle);
}
