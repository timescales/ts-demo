//! `no_secrets_in_logs`: a full LiteSVM epoch under a capturing
//! subscriber that sees every thread. The output must not contain any key,
//! salt, grant text, envelope or submission, nor a raw wallet address at
//! `info` or above.

use std::collections::BTreeSet;

use timescales_core::intent::{PrivateIntent, SealedEnvelope};
use timescales_core::{
    CommitmentScheme, EpochId, Lots, MarketId, Order, OrderKind, Role, Side, Tick, TraderId,
};
use timescales_node::NodeApi;
use timescales_service::store::node::Phase;

use crate::support::logs::capture_all;
use crate::support::svm::seed;
use crate::support::world::{Options, World};

#[tokio::test(start_paused = true)]
async fn no_secrets_in_logs() {
    let captured = capture_all().expect("no other global subscriber");

    let mut w = World::new(Options::default()).await;
    w.start_node().await.unwrap();
    w.deal(1..=4).await;
    let maker = w.trader(10_000, 0).await;
    let taker = w.trader(0, 1_000_000).await;
    let e = w.fresh_epoch().await;
    let pk = w.epoch_pk(e);
    let mid = MarketId(w.market_id);
    let mut forbidden: BTreeSet<String> = BTreeSet::new();
    let mut salts = Vec::new();
    for (t, side, role) in [
        (&maker, Side::Sell, Role::Maker),
        (&taker, Side::Buy, Role::Taker),
    ] {
        let order = Order {
            market: mid,
            trader: TraderId(t.id()),
            nonce: 1,
            side,
            role,
            kind: OrderKind::Limit,
            limit: Tick(100),
            quantity: Lots(5),
            valid_from: EpochId(e),
            expires_at: EpochId(e),
        };
        let mut rng = rand::thread_rng();
        let (intent, c) =
            PrivateIntent::place(&mut rng, &t.key, CommitmentScheme::Sha256, order).unwrap();
        salts.push(hex::encode(intent.salt.0));
        let env = SealedEnvelope::seal(&mut rng, mid, EpochId(e), &pk, c, &intent).unwrap();
        forbidden.insert(hex::encode(&env.ciphertext[..32]));
        let sub = t.submission(&w.relay_cfg, env);
        forbidden.insert(hex::encode(&sub.raw[100..140]));
        let r = w
            .node()
            .submit(w.market, vec![sub], t.session.unwrap())
            .await;
        assert!(r[0].is_ok());
    }
    w.to_cutoff().await;
    w.phase(e, &[Phase::Settled]).await;
    w.crash().await;

    // Secrets: every key seed of the node, the wallets and the sessions,
    // and the salts of the intents.
    for label in ["relay", "cranker", "trader", "session"] {
        for n in 0..4 {
            forbidden.insert(hex::encode(seed(label, n)));
        }
    }
    forbidden.insert(hex::encode([0x4b; 32]));
    forbidden.insert(hex::encode([0x4e; 32]));
    forbidden.extend(salts);
    // Grant texts.
    forbidden.insert("wants you to sign in with your Solana account".to_owned());
    let text = captured.text();
    assert!(
        text.len() > 1_000,
        "the run logged something ({} bytes)",
        text.len()
    );
    for f in &forbidden {
        assert!(!text.contains(f.as_str()), "a secret reached the logs: {f}");
    }
    // Wallets: only `wallet_tag` at info and above.
    let wallets: Vec<String> = [maker.id(), taker.id()]
        .iter()
        .flat_map(|w| [hex::encode(w), bs58::encode(w).into_string()])
        .collect();
    for line in text
        .lines()
        .filter(|l| l.starts_with("INFO") || l.starts_with("WARN") || l.starts_with("ERROR"))
    {
        for wallet in &wallets {
            assert!(
                !line.contains(wallet.as_str()),
                "a raw wallet at info: {line}"
            );
        }
    }
    assert!(text.contains("wallet_tag"), "sessions log the wallet tag");
}
