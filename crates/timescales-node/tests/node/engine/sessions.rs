//! Sessions: SIWS grants checked in order, nonces consumed only
//! after eligibility, identical grants idempotent, oldest-session eviction,
//! `TimescalesSession` request authentication. And the ban of a wallet
//! whose session submitted another wallet's intent (E19).

use std::time::Duration;

use timescales_core::crypto::Keypair;
use timescales_core::intent::{PrivateIntent, SealedEnvelope};
use timescales_core::{
    CommitmentScheme, EpochId, Lots, MarketId, Order, OrderKind, Role, Side, Tick, TraderId,
};
use timescales_node::{NodeApi, SessionError};
use timescales_service::api::{ErrorCode, GrantMethodJson, WalletNotEligibleDetails};
use timescales_service::store::node::Phase;
use timescales_service::wire::SessionAuthorization;

use crate::support::world::{Options, World};

fn code(r: Result<timescales_service::api::Session, SessionError>) -> ErrorCode {
    match r {
        Err(SessionError::Refused { code, .. }) => code,
        other => panic!("expected a refusal, got {other:?}"),
    }
}

#[tokio::test(start_paused = true)]
async fn grants_nonces_and_eviction() {
    let mut w = World::new(Options::default()).await;
    w.start_node().await.unwrap();
    let node = w.node();
    let t = w.new_trader();

    // Not eligible yet: refused, and the nonce stays usable.
    let nonce: [u8; 16] = node
        .session_nonce()
        .await
        .unwrap()
        .nonce
        .0
        .try_into()
        .unwrap();
    let text = t.grant_text(nonce, w.clock_now(), w.market, w.program);
    let req = t.grant(&text);
    assert_eq!(
        code(node.create_session(req.clone(), None).await),
        ErrorCode::WalletNotEligible
    );
    w.fund(&t, 0, 50_000).await;
    // The client names the slot of its deposit, past the node's cached
    // "no account" answer.
    let deposit_slot = w
        .chain
        .slot(timescales_chain::Level::Confirmed)
        .await
        .unwrap();
    let (s, created) = w
        .node()
        .create_session_status(req.clone(), Some(deposit_slot))
        .await
        .unwrap();
    assert!(created);
    assert_eq!(s.session_key.0, t.session_key.id().0);
    // The identical grant again returns the same session (a client retry).
    let (again, created) = w
        .node()
        .create_session_status(req.clone(), None)
        .await
        .unwrap();
    assert!(!created);
    assert_eq!(again.session_key, s.session_key);

    let node = w.node();
    // A signature that is not the wallet's over this exact text.
    let mut other = req.clone();
    other.signature_b64 = timescales_service::api::B64(t.wallet.sign(b"not the text").to_vec());
    assert_eq!(
        code(node.create_session(other, None).await),
        ErrorCode::BadSignature
    );

    // Method, domain, nonce and template refusals.
    let n = fresh(node).await;
    let mut sm = t.grant(&t.grant_text(n, w.clock_now(), w.market, w.program));
    sm.method = GrantMethodJson::SignMessage;
    assert_eq!(
        code(node.create_session(sm, None).await),
        ErrorCode::SessionMethodRefused
    );
    let n = fresh(node).await;
    let wrong_domain = t
        .grant_text(n, w.clock_now(), w.market, w.program)
        .replacen("localhost:4173", "evil.example", 1);
    assert_eq!(
        code(node.create_session(t.grant(&wrong_domain), None).await),
        ErrorCode::SessionDomainMismatch
    );
    let forged = t.grant_text([7; 16], w.clock_now(), w.market, w.program);
    assert_eq!(
        code(node.create_session(t.grant(&forged), None).await),
        ErrorCode::SessionNonceInvalid
    );
    assert_eq!(
        code(node.create_session(t.grant("not a grant"), None).await),
        ErrorCode::SessionTemplateInvalid
    );

    // max_per_wallet = 2: a third session evicts the oldest.
    let mut sessions = vec![s.session_key.0];
    for i in 0..2u8 {
        let mut t2 = crate::support::trader::Trader::new(
            t.wallet.clone(),
            crate::support::svm::seed("trader", t.index),
            [0x70 + i; 32],
            t.index,
        );
        let s2 = t2.login(node, w.clock_now(), w.market, w.program).await;
        sessions.push(s2.session_key.0);
        if i == 1 {
            assert_eq!(s2.evicted, Some(1));
        }
    }
    let first = w
        .node()
        .store()
        .session(sessions[0])
        .await
        .unwrap()
        .unwrap();
    assert!(first.revoked, "the oldest session is evicted");

    // TimescalesSession: valid, replayed, skewed.
    let key = Keypair::from_seed([0x71; 32]);
    let now = w.clock_now();
    let auth = SessionAuthorization::sign(&key, "GET", "/v1/sessions/current", now, b"");
    let r = w
        .node()
        .authenticate(&auth.render(), "GET", "/v1/sessions/current", b"")
        .await
        .unwrap();
    assert_eq!(r.wallet, t.id());
    let replay = w
        .node()
        .authenticate(&auth.render(), "GET", "/v1/sessions/current", b"")
        .await;
    assert!(matches!(
        replay,
        Err(SessionError::Refused {
            code: ErrorCode::BadSignature,
            ..
        })
    ));
    let old = SessionAuthorization::sign(&key, "GET", "/v1/sessions/current", now - 60_000, b"");
    let skew = w
        .node()
        .authenticate(&old.render(), "GET", "/v1/sessions/current", b"")
        .await;
    assert!(matches!(
        skew,
        Err(SessionError::Refused {
            code: ErrorCode::Skew,
            ..
        })
    ));

    // Revocation.
    w.node().revoke_session(sessions[2]).await.unwrap();
    let row = w
        .node()
        .store()
        .session(sessions[2])
        .await
        .unwrap()
        .unwrap();
    assert!(row.revoked);
    tokio::time::sleep(Duration::from_millis(10)).await;
}

#[tokio::test(start_paused = true)]
async fn a_wallet_that_submits_another_wallets_intent_is_banned() {
    let mut w = World::new(Options::default()).await;
    w.start_node().await.unwrap();
    w.deal(1..=4).await;
    let victim = w.trader(0, 100_000).await;
    let attacker = w.trader(0, 100_000).await;
    let e = w.fresh_epoch().await;
    let mid = MarketId(w.market_id);
    let pk = w.epoch_pk(e);
    // An intent the victim signed, sealed and submitted by the attacker's
    // session.
    let order = Order {
        market: mid,
        trader: TraderId(victim.id()),
        nonce: 1,
        side: Side::Buy,
        role: Role::Taker,
        kind: OrderKind::Limit,
        limit: Tick(100),
        quantity: Lots(1),
        valid_from: EpochId(e),
        expires_at: EpochId(e),
    };
    let mut rng = rand::thread_rng();
    let (intent, c) =
        PrivateIntent::place(&mut rng, &victim.key, CommitmentScheme::Sha256, order).unwrap();
    let env = SealedEnvelope::seal(&mut rng, mid, EpochId(e), &pk, c, &intent).unwrap();
    let phished = attacker.submission(&w.relay_cfg, env);
    let r = w
        .node()
        .submit(w.market, vec![phished], attacker.session.unwrap())
        .await;
    assert!(r[0].is_ok(), "accepted: the relay cannot read it");
    w.to_cutoff().await;
    w.phase(e, &[Phase::Settled]).await;
    let until = e + 64;
    assert!(
        w.node()
            .store()
            .banned(w.market, attacker.id(), e + 1)
            .await
            .unwrap()
    );
    assert!(
        !w.node()
            .store()
            .banned(w.market, victim.id(), e + 1)
            .await
            .unwrap()
    );
    // The attacker is refused from now on. The victim is not.
    let next = w.fresh_epoch().await;
    let pk = w.epoch_pk(next);
    let (o, _) = attacker.order(&w.relay_cfg, mid, next, &pk, Side::Buy, Role::Taker, 100, 1);
    let r = w
        .node()
        .submit(w.market, vec![o], attacker.session.unwrap())
        .await;
    let err = r[0].clone().unwrap_err();
    assert_eq!(err.code, ErrorCode::WalletNotEligible);
    let details: WalletNotEligibleDetails = serde_json::from_value(err.details).unwrap();
    assert_eq!(
        details,
        WalletNotEligibleDetails::Banned {
            until_epoch: timescales_service::api::U64(until)
        }
    );
    let (o, _) = victim.order(&w.relay_cfg, mid, next, &pk, Side::Buy, Role::Taker, 100, 1);
    assert!(
        w.node()
            .submit(w.market, vec![o], victim.session.unwrap())
            .await[0]
            .is_ok()
    );
}

async fn fresh(node: &timescales_node::NodeHandle) -> [u8; 16] {
    node.session_nonce()
        .await
        .unwrap()
        .nonce
        .0
        .try_into()
        .unwrap()
}
