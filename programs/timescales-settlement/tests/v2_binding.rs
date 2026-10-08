//! PostReceipt binding: each field of header v2 and receipt v1 that
//! ties the receipt to the market and batch is rejected with its own code.
//! Also cross-checks the hand-built bytes against the off-chain decoders.

mod common;

use common::*;
use timescales_auction::BatchHeader;
use timescales_auction::receipts::ExecutionReceipt;
use timescales_core::Decode;

fn revealed(cfg: Cfg) -> (Env, Settlement) {
    let mut env = Env::new(cfg);
    let a = env.trader(100, 100);
    let b = env.trader(100, 100);
    let s = Settlement::new(&[(a.owner(), 1, -1), (b.owner(), -1, 1)], 0);
    ok(env.commit_for(1, &s));
    ok(env.reveal(1));
    (env, s)
}

/// Posts after `mutate`. The receipt is re-bound to the header unless the
/// mutation targets the binding itself.
fn post_with(env: &mut Env, s: &Settlement, rebind: bool, mutate: impl Fn(&mut Post)) -> TxResult {
    let mut post = env.prepare(1, s);
    mutate(&mut post);
    if rebind {
        post.rebind();
    }
    env.post(1, &post)
}

#[test]
fn hand_built_bytes_match_the_off_chain_decoders() {
    let (mut env, s) = revealed(Cfg::default());
    let post = env.prepare(1, &s);
    let header = BatchHeader::decode_exact(&post.header).expect("header v2");
    assert_eq!(header.version, 2);
    assert_eq!(header.digest().0, post.header_digest());
    let receipt = ExecutionReceipt::decode_exact(&env.signed_receipt(&post)).expect("receipt v1");
    assert!(receipt.verify_signature().is_ok());
    assert_eq!(receipt.digest().0, post.digest());
    assert_eq!(receipt.outcome.digest().0, post.outcome_digest());
    ok(env.post(1, &post));
    let b = env.batch_view(1);
    assert_eq!(b.header_digest, header.digest().0);
    assert_eq!(b.receipt, receipt.digest().0);
    assert_eq!(b.outcome_digest, receipt.outcome.digest().0);
    assert_eq!(b.settlement_count, 2);
    assert_eq!(b.receipt_slot, env.slot());
}

#[test]
fn each_binding_has_its_own_error() {
    type Mutation = Box<dyn Fn(&mut Post)>;
    let cases: Vec<(&str, bool, Mutation, E)> = vec![
        (
            "header version 1",
            true,
            Box::new(|p| p.header[0] = 1),
            E::UnsupportedVersion,
        ),
        (
            "short header",
            true,
            Box::new(|p| {
                p.header.pop();
            }),
            E::UnsupportedVersion,
        ),
        (
            "receipt version 2",
            true,
            Box::new(|p| p.body[0] = 2),
            E::UnsupportedVersion,
        ),
        (
            "header market",
            true,
            Box::new(|p| p.header[1] ^= 1),
            E::HeaderMismatch,
        ),
        (
            "header epoch",
            true,
            Box::new(|p| p.header[9] = 2),
            E::HeaderMismatch,
        ),
        (
            "params",
            true,
            Box::new(|p| p.header[30] ^= 1),
            E::ParamsMismatch,
        ),
        (
            "band",
            true,
            Box::new(|p| p.header[63] ^= 1),
            E::TermsMismatch,
        ),
        (
            "epoch binding",
            true,
            Box::new(|p| p.header[100] ^= 1),
            E::TermsMismatch,
        ),
        (
            "count",
            true,
            Box::new(|p| p.header[119] ^= 1),
            E::HeaderMismatch,
        ),
        (
            "batch root",
            true,
            Box::new(|p| p.header[123] ^= 1),
            E::HeaderMismatch,
        ),
        (
            "beacon",
            true,
            Box::new(|p| p.header[155] ^= 1),
            E::HeaderMismatch,
        ),
        (
            "prior state root",
            true,
            Box::new(|p| p.header[187] ^= 1),
            E::StateRootMismatch,
        ),
        (
            "prev receipt",
            true,
            Box::new(|p| p.header[251] ^= 1),
            E::HeaderMismatch,
        ),
        (
            "receipt market",
            true,
            Box::new(|p| p.body[1] ^= 1),
            E::ReceiptMismatch,
        ),
        (
            "receipt epoch",
            true,
            Box::new(|p| p.body[9] = 2),
            E::ReceiptMismatch,
        ),
        (
            "receipt header digest",
            false,
            Box::new(|p| p.body[17] ^= 1),
            E::ReceiptMismatch,
        ),
        (
            "three clearing prices",
            true,
            Box::new(|p| {
                p.body[49] = 3;
                let tail = p.body.split_off(53);
                p.body.extend_from_slice(&[0; 51]);
                p.body.extend_from_slice(&tail);
            }),
            E::ReceiptMismatch,
        ),
        (
            "clearing count without bytes",
            true,
            Box::new(|p| p.body[49] = 1),
            E::ReceiptMismatch,
        ),
        (
            "more deltas than envelopes",
            true,
            Box::new(|p| {
                let at = p.off(153);
                p.body[at..at + 4].copy_from_slice(&3u32.to_le_bytes());
            }),
            E::TooManyDeltas,
        ),
        (
            "reference backend",
            true,
            Box::new(|p| {
                let at = p.off(197);
                p.body[at] = 0;
            }),
            E::BackendNotAllowed,
        ),
        (
            "mpc backend",
            true,
            Box::new(|p| {
                let at = p.off(197);
                p.body[at] = 2;
            }),
            E::BackendNotAllowed,
        ),
    ];
    let (env, s) = revealed(Cfg::default());
    for (name, rebind, mutate, err) in cases {
        let mut fork = env.fork();
        let r = post_with(&mut fork, &s, rebind, mutate);
        assert!(r.is_err(), "{name} was accepted");
        let f = r.unwrap_err();
        assert_eq!(
            f.code,
            Some(err.code()),
            "{name}: {} {:?}",
            f.err,
            f.code.and_then(E::from_code)
        );
    }
}

#[test]
fn unknown_executor_and_bad_signatures() {
    let (env, s) = revealed(Cfg::default());

    let mut fork = env.fork();
    let mut post = fork.prepare(1, &s);
    fork.set_poster(&mut post, 5);
    fails(fork.post(1, &post), E::UnknownExecutor);

    // The precompile verified a different message.
    let mut fork = env.fork();
    let post = fork.prepare(1, &s);
    let mut ixs = fork.post_ixs(1, &post);
    let key = executor_key(0);
    let other = [9u8; 32];
    ixs[0] = ed25519_ix(&executor_id(&key), &other, &sign(&key, &other));
    fails(fork.crank(&ixs), E::BadSignature);

    // No precompile instruction at all.
    let mut fork = env.fork();
    let post = fork.prepare(1, &s);
    let ixs = fork.post_ixs(1, &post);
    fails(fork.crank(&ixs[1..]), E::BadSignature);

    // The precompile checked another key's signature over the right digest.
    let mut fork = env.fork();
    let post = fork.prepare(1, &s);
    let mut ixs = fork.post_ixs(1, &post);
    let stranger = executor_key(7);
    ixs[0] = ed25519_ix(
        &executor_id(&stranger),
        &post.digest(),
        &sign(&stranger, &post.digest()),
    );
    fails(fork.crank(&ixs), E::BadSignature);
}

#[test]
fn post_needs_a_revealed_batch_of_the_next_epoch() {
    let mut env = Env::new(Cfg::default());
    let s = Settlement::default();
    ok(env.commit_for(1, &s));
    // A header for a committed but unrevealed batch.
    let post = env.prepare(1, &s);
    fails(env.post(1, &post), E::WrongStatus);
    ok(env.reveal(1));
    let post = env.prepare(1, &s);
    ok(env.post(1, &post));
    fails(env.post(1, &post), E::WrongStatus);
}

#[test]
fn receipts_with_clearing_prices_are_accepted() {
    for k in [1usize, 2] {
        let (mut env, s) = revealed(Cfg::default());
        let mut post = env.prepare(1, &s);
        post.body[49..53].copy_from_slice(&(k as u32).to_le_bytes());
        let tail = post.body.split_off(53);
        for i in 0..k {
            // book u8 || tick u64 || volume u64
            post.body.push(i as u8);
            post.body.extend_from_slice(&100u64.to_le_bytes());
            post.body.extend_from_slice(&7u64.to_le_bytes());
        }
        post.body.extend_from_slice(&tail);
        assert_eq!(post.body.len() + 64, 390 + 17 * k);
        let receipt = ExecutionReceipt::decode_exact(&env.signed_receipt(&post)).expect("decodes");
        assert_eq!(receipt.outcome.clearing.len(), k);
        ok(env.post(1, &post));
        let b = env.batch_view(1);
        assert_eq!(b.outcome_digest, receipt.outcome.digest().0);
        assert_eq!(b.next_state_root, next_state_root(1));
        assert_eq!(b.settlement_count, 2);
    }
}
