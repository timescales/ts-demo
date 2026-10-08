//! Compute units and transaction sizes, measured in LiteSVM on the
//! program artifact and recorded in `target/settlement-v2.jsonl` with the
//! environment. Ceilings: RevealBeacon <= 30k, CoSignReceipt <=
//! 15k, InitMarket <= 60k, ClaimFees <= 20k, every instruction < 200k, and
//! every worst-case transaction <= 1232 bytes, with two compute-budget
//! instructions where the client adds them.

mod common;

use std::path::Path;

use common::*;
use sha2::{Digest, Sha256};
use solana_address::Address;
use solana_instruction::Instruction;
use solana_keypair::Keypair;
use solana_signer::Signer;

const MAX_TX: usize = 1232;

struct Record {
    instruction: &'static str,
    variant: String,
    cu: u64,
    tx_bytes: usize,
    tx_bytes_with_compute_budget: usize,
}

fn compute_budget() -> [Instruction; 2] {
    let program: Address = "ComputeBudget111111111111111111111111111111"
        .parse()
        .expect("compute budget id");
    let mut limit = vec![2u8];
    limit.extend_from_slice(&400_000u32.to_le_bytes());
    let mut price = vec![3u8];
    price.extend_from_slice(&1_000u64.to_le_bytes());
    [
        Instruction {
            program_id: program,
            accounts: vec![],
            data: limit,
        },
        Instruction {
            program_id: program,
            accounts: vec![],
            data: price,
        },
    ]
}

struct Bench {
    records: Vec<Record>,
}

impl Bench {
    /// Sends `ixs` (fee payer = `signers[0]`) and records its compute units
    /// and its size with and without the two compute-budget instructions.
    fn measure(
        &mut self,
        env: &mut Env,
        instruction: &'static str,
        variant: &str,
        ixs: &[Instruction],
        signers: &[&Keypair],
    ) -> u64 {
        let payer = signers[0].pubkey();
        let tx_bytes = legacy_tx_size(ixs, &payer, signers.len());
        let mut with_cb = compute_budget().to_vec();
        with_cb.extend_from_slice(ixs);
        let tx_bytes_with_compute_budget = legacy_tx_size(&with_cb, &payer, signers.len());
        let cu = ok(env.send(ixs, signers));
        assert!(cu < 200_000, "{instruction} {variant}: {cu} CU");
        self.records.push(Record {
            instruction,
            variant: variant.to_owned(),
            cu,
            tx_bytes,
            tx_bytes_with_compute_budget,
        });
        cu
    }

    fn crank(
        &mut self,
        env: &mut Env,
        instruction: &'static str,
        variant: &str,
        ixs: &[Instruction],
    ) -> u64 {
        let c = env.cranker.insecure_clone();
        self.measure(env, instruction, variant, ixs, &[&c])
    }

    fn get(&self, instruction: &str, variant: &str) -> &Record {
        self.records
            .iter()
            .find(|r| r.instruction == instruction && r.variant == variant)
            .unwrap_or_else(|| panic!("no record for {instruction} {variant}"))
    }
}

/// A batch whose settlement tree has `n` leaves, all for existing traders
/// with zero deltas, posted and co-signed.
fn batch_with_leaves(n: usize) -> (Env, Settlement) {
    let mut env = Env::new(Cfg::default());
    let owners: Vec<Address> = (0..n)
        .map(|_| {
            let t = env.wallet(0, 0);
            let open = env.open_trader_ix(&t.owner());
            ok(env.send(&[open], &[&t.kp]));
            t.owner()
        })
        .collect();
    let deltas: Vec<_> = owners.iter().map(|o| (*o, 0i64, 0i64)).collect();
    let s = Settlement::new(&deltas, 0);
    ok(env.commit(1, &[0x33; 32], n as u32));
    ok(env.reveal(1));
    let post = env.prepare(1, &s);
    ok(env.post(1, &post));
    (env, s)
}

fn path_len(s: &Settlement, i: usize) -> usize {
    s.tree().proof(i).expect("proof").path.len()
}

/// Verify and apply chunks of `per_tx` leaves whose paths have `p` hashes.
fn delta_chunks(bench: &mut Bench, n: usize, per_tx: usize, p: usize) {
    let (mut env, s) = batch_with_leaves(n);
    assert!((0..per_tx).all(|i| path_len(&s, i) == p));
    let variant = format!("{per_tx} leaves, path {p}");
    let first: Vec<usize> = (0..per_tx).collect();
    let v = env.verify_ix(1, &s, &first);
    bench.crank(&mut env, "VerifyDeltas", &variant, &[v]);
    let rest: Vec<usize> = (per_tx..n).collect();
    for chunk in rest.chunks(per_tx) {
        ok(env.verify(1, &s, chunk));
    }
    let f = env.finalize_ix(1);
    bench.crank(
        &mut env,
        "FinalizeVerification",
        &format!("{n} leaves"),
        &[f],
    );
    let a = env.apply_ix(1, &s, &first);
    bench.crank(&mut env, "ApplyDeltas", &variant, &[a]);
    for chunk in rest.chunks(per_tx) {
        ok(env.apply(1, &s, chunk));
    }
    let c = env.close_batch_ix(1);
    bench.crank(&mut env, "CloseBatch", &format!("{n} leaves"), &[c]);
}

fn post_with_clearing(bench: &mut Bench, k: usize) {
    let mut env = Env::new(Cfg {
        executors: 2,
        quorum: 2,
        ..Cfg::default()
    });
    let s = Settlement::default();
    ok(env.commit_for(1, &s));
    ok(env.reveal(1));
    let mut post = env.prepare(1, &s);
    post.body[49..53].copy_from_slice(&(k as u32).to_le_bytes());
    let tail = post.body.split_off(53);
    for i in 0..k {
        post.body.push(i as u8);
        post.body.extend_from_slice(&100u64.to_le_bytes());
        post.body.extend_from_slice(&7u64.to_le_bytes());
    }
    post.body.extend_from_slice(&tail);
    let ixs = env.post_ixs(1, &post);
    assert_eq!(ixs[1].data.len(), 678 + 17 * k);
    bench.crank(
        &mut env,
        "PostReceipt",
        &format!("{k} clearing prices"),
        &ixs,
    );
    if k == 0 {
        let digest = env.cosign_digest(1);
        let ixs = env.cosign_ixs(1, &executor_key(1), &digest);
        bench.crank(&mut env, "CoSignReceipt", "", &ixs);
    }
}

fn environment() -> String {
    let so = program_so();
    let bytes = std::fs::read(&so).expect("program");
    let sha = Sha256::digest(&bytes);
    let sha: String = sha.iter().map(|b| format!("{b:02x}")).collect();
    let rel = std::env::var("TIMESCALES_PROGRAM_SO")
        .unwrap_or_else(|_| "target/sbf/timescales_settlement_program.so".to_owned());
    format!(
        "{{\"os\":\"{}\",\"arch\":\"{}\",\"vm\":\"litesvm 0.17\",\"program\":\"{}\",\"program_sha256\":\"{}\",\"program_bytes\":{}}}",
        std::env::consts::OS,
        std::env::consts::ARCH,
        rel,
        sha,
        bytes.len()
    )
}

fn write_results(records: &[Record]) {
    let env = environment();
    let mut out = String::new();
    for r in records {
        out.push_str(&format!(
            "{{\"experiment\":\"settlement-v2\",\"instruction\":\"{}\",\"variant\":\"{}\",\"cu\":{},\"tx_bytes\":{},\"tx_bytes_with_compute_budget\":{},\"environment\":{}}}\n",
            r.instruction, r.variant, r.cu, r.tx_bytes, r.tx_bytes_with_compute_budget, env
        ));
    }
    let path =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("target/settlement-v2.jsonl");
    if std::fs::read_to_string(&path).ok().as_deref() != Some(out.as_str()) {
        std::fs::write(&path, out).expect("write settlement-v2.jsonl");
    }
}

#[test]
fn ceilings_and_sizes() {
    let mut bench = Bench {
        records: Vec::new(),
    };

    // Market setup and the trader instructions.
    let mut env = Env::bare(Cfg {
        executors: 8,
        quorum: 2,
        ..Cfg::default()
    });
    let args = env.init_args();
    let init = env.init_market_ix(&args, &env.creator.pubkey());
    assert_eq!(init.data.len(), 211 + 32 * 8);
    let creator = env.creator.insecure_clone();
    bench.measure(&mut env, "InitMarket", "8 executors", &[init], &[&creator]);

    let t = env.wallet(1_000, 1_000);
    let open = env.open_trader_ix(&t.owner());
    bench.measure(&mut env, "OpenTrader", "", &[open], &[&t.kp]);
    let d = env.deposit_ix(&t, true, 1_000);
    bench.measure(&mut env, "Deposit", "", &[d], &[&t.kp]);
    let r = env.request_withdraw_ix(&t, 0, 400);
    bench.measure(&mut env, "RequestWithdraw", "", &[r], &[&t.kp]);
    let c = env.cancel_request_ix(&t);
    bench.measure(&mut env, "CancelWithdrawRequest", "", &[c], &[&t.kp]);
    let r = env.request_withdraw_ix(&t, 0, 1_000);
    ok(env.send(&[r], &[&t.kp]));
    let w = env.withdraw_ix(&t, true);
    bench.measure(&mut env, "Withdraw", "", &[w], &[&t.kp]);
    let c = env.close_trader_ix(&t);
    bench.measure(&mut env, "CloseTrader", "", &[c], &[&t.kp]);

    // The batch path on an 8-executor market.
    let commit = env.commit_ix(1, &[0x44; 32], 1, &terms());
    let relay = env.relay.insecure_clone();
    bench.measure(&mut env, "CommitBatch", "", &[commit], &[&relay]);
    let at = env.batch_view(1).commit_slot + 2 * u64::from(env.cfg.beacon_delay) + 1;
    env.warp(at);
    env.fill_slot_hashes();
    let reveal = env.reveal_ix(1);
    bench.crank(
        &mut env,
        "RevealBeacon",
        "512 SlotHashes entries",
        &[reveal],
    );
    let s = Settlement::default();
    let post = env.prepare(1, &s);
    let ixs = env.post_ixs(1, &post);
    bench.crank(&mut env, "PostReceipt", "8 executors", &ixs);
    let digest = env.cosign_digest(1);
    let last = env.executors[7].clone();
    let ixs = env.cosign_ixs(1, &last, &digest);
    bench.crank(&mut env, "CoSignReceipt", "8 executors, last slot", &ixs);
    let admin = env.admin.insecure_clone();
    let cranker = env.cranker.insecure_clone();
    let abort = env.abort_ix(1, &admin.pubkey(), 1);
    bench.measure(
        &mut env,
        "AbortBatch",
        "admin",
        &[abort],
        &[&cranker, &admin],
    );

    // Governance.
    let keys: Vec<[u8; 32]> = (0..8).map(|i| [0x60 + i; 32]).collect();
    let mut payload = vec![8u8];
    for k in &keys {
        payload.extend_from_slice(k);
    }
    payload.push(8);
    let p = env.propose_ix(&admin.pubkey(), 2, &payload);
    bench.measure(
        &mut env,
        "ProposeChange",
        "SetExecutors, 8 keys",
        &[p],
        &[&admin],
    );
    env.advance(20);
    let a = env.apply_change_ix(&cranker.pubkey());
    bench.crank(&mut env, "ApplyChange", "SetExecutors, 8 keys", &[a]);
    let p = env.propose_ix(&admin.pubkey(), 1, &[9; 32]);
    ok(env.send(&[p], &[&admin]));
    let c = env.cancel_change_ix(&admin.pubkey());
    bench.measure(&mut env, "CancelChange", "", &[c], &[&admin]);
    let next = env.funded();
    let p = env.propose_ix(&admin.pubkey(), 4, &next.pubkey().to_bytes());
    ok(env.send(&[p], &[&admin]));
    env.advance(20);
    let a = env.apply_change_ix(&cranker.pubkey());
    ok(env.crank(&[a]));
    let a = env.accept_admin_ix(&next.pubkey());
    bench.measure(&mut env, "AcceptAdmin", "", &[a], &[&next]);
    let h = env.set_halted_ix(&next.pubkey(), true);
    bench.measure(&mut env, "SetHalted", "", &[h], &[&next]);
    let r = env.remove_executor_ix(&next.pubkey(), &keys[7]);
    bench.measure(&mut env, "RemoveExecutor", "last slot", &[r], &[&next]);

    // Fees and reclaim on a market with settled epochs.
    let mut env = Env::new(Cfg::default());
    let a = env.trader(0, 1_000);
    let b = env.trader(100, 0);
    let s = Settlement::new(&[(a.owner(), 10, -110), (b.owner(), -10, 100)], 10);
    env.run_epoch(1, &s);
    let dest = env.wallet(0, 0);
    let claim = env.claim_fees_ix(&env.admin.pubkey(), &dest.quote_ata, 10);
    let admin = env.admin.insecure_clone();
    bench.measure(&mut env, "ClaimFees", "", &[claim], &[&admin]);
    for e in 2..=1025 {
        env.skip_epoch(e);
    }
    let r = env.reclaim_ix(1, &env.relay.pubkey());
    bench.crank(&mut env, "ReclaimBatch", "", &[r]);

    // Receipts with 0, 1 and 2 clearing prices.
    for k in 0..=2 {
        post_with_clearing(&mut bench, k);
    }

    // Verify / apply chunking by path length (plan_delta_chunks): 4 / 3 / 2
    // leaves for paths of at most 4 / 7 / 10 hashes.
    // The smallest trees whose first leaves have those path lengths.
    delta_chunks(&mut bench, 9, 4, 4);
    delta_chunks(&mut bench, 65, 3, 7);
    delta_chunks(&mut bench, 513, 2, 10);

    // Compute ceilings and transaction sizes.
    assert!(bench.get("RevealBeacon", "512 SlotHashes entries").cu <= 30_000);
    assert!(bench.get("CoSignReceipt", "8 executors, last slot").cu <= 15_000);
    assert!(bench.get("CoSignReceipt", "").cu <= 15_000);
    assert!(bench.get("InitMarket", "8 executors").cu <= 60_000);
    assert!(bench.get("ClaimFees", "").cu <= 20_000);
    for (k, plain, budgeted) in [(0, 1128, 1180), (1, 1145, 1197), (2, 1162, 1214)] {
        let r = bench.get("PostReceipt", &format!("{k} clearing prices"));
        assert_eq!(
            (r.tx_bytes, r.tx_bytes_with_compute_budget),
            (plain, budgeted),
            "PostReceipt k={k}"
        );
    }
    assert!(bench.get("CommitBatch", "").tx_bytes <= 350);
    for r in &bench.records {
        assert!(
            r.tx_bytes_with_compute_budget <= MAX_TX,
            "{} {}: {} bytes",
            r.instruction,
            r.variant,
            r.tx_bytes_with_compute_budget
        );
    }
    write_results(&bench.records);
}
