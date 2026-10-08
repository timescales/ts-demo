//! Every builder against the table, written out byte by byte: data
//! layout, account order, signer and writable flags. The program side of
//! the same layouts is checked by `v13_conformance` in the program crate.

#![allow(clippy::unwrap_used)]

use super::common;

use std::collections::BTreeSet;

use common::{Rng, params, settlement};
use timescales_chain::program::{
    ASSOCIATED_TOKEN_PROGRAM, AbortReason, COMPUTE_BUDGET_PROGRAM, ClientError, ED25519_PROGRAM,
    GovernanceChange, INSTRUCTIONS_SYSVAR, InitMarketArgs, Ix, Key, Leaf, Meta, SLOT_HASHES_SYSVAR,
    SYSTEM_PROGRAM, Side, TOKEN_PROGRAM, abort_batch, accept_admin, apply_change, apply_deltas,
    associated_token_address, batch_pda, cancel_change, cancel_withdraw_request, claim_fees,
    close_batch, close_trader, commit_batch, compute_budget, cosign_receipt, deposit,
    derive_market_id, ed25519_verify, finalize, init_market, leaves, market_pda, open_trader,
    post_receipt, propose_change, reclaim_batch, remove_executor, request_withdraw, reveal_beacon,
    set_halted, spl, system, trader_pda, verify_deltas, withdraw,
};
use timescales_core::{Encode, Hash32};

const PROGRAM: Key = [0x50; 32];
const CREATOR: Key = [0x01; 32];
const OWNER: Key = [0x02; 32];
const RELAY: Key = [0x03; 32];
const CRANKER: Key = [0x04; 32];
const ADMIN: Key = [0x05; 32];
const BASE_MINT: Key = [0x11; 32];
const QUOTE_MINT: Key = [0x12; 32];
const BASE_VAULT: Key = [0x13; 32];
const QUOTE_VAULT: Key = [0x14; 32];
const SOURCE: Key = [0x15; 32];
const DEST: Key = [0x16; 32];
const EPOCH: u64 = 0x0102_0304_0506_0708;

fn cat(parts: &[&[u8]]) -> Vec<u8> {
    parts.concat()
}

fn s(key: Key) -> (Key, bool, bool) {
    (key, true, false)
}

fn sw(key: Key) -> (Key, bool, bool) {
    (key, true, true)
}

fn r(key: Key) -> (Key, bool, bool) {
    (key, false, false)
}

fn w(key: Key) -> (Key, bool, bool) {
    (key, false, true)
}

#[track_caller]
fn check(ix: &Ix, program: Key, data: &[u8], metas: &[(Key, bool, bool)]) {
    assert_eq!(ix.program, program, "program");
    assert_eq!(ix.data, data, "data");
    let got: Vec<(Key, bool, bool)> = ix
        .accounts
        .iter()
        .map(|m| (m.key, m.signer, m.writable))
        .collect();
    assert_eq!(got, metas, "accounts");
}

fn market() -> Key {
    market_pda(&PROGRAM, derive_market_id(&PROGRAM, &CREATOR, &[0x5a; 32]))
        .unwrap()
        .0
}

fn trader() -> Key {
    trader_pda(&PROGRAM, &market(), &OWNER).unwrap().0
}

fn batch() -> Key {
    batch_pda(&PROGRAM, &market(), EPOCH).unwrap().0
}

fn init_args(executors: u8) -> InitMarketArgs {
    let id = derive_market_id(&PROGRAM, &CREATOR, &[0x5a; 32]);
    InitMarketArgs {
        salt: [0x5a; 32],
        admin: ADMIN,
        relay: RELAY,
        params: params(id),
        committee_digest: Hash32([0xc0; 32]),
        beacon_delay_slots: 0x0a0b,
        timelock_slots: 0x1112_1314_1516_1718,
        exec_timeout_slots: 0x2122_2324_2526_2728,
        settle_timeout_slots: 0x3132_3334_3536_3738,
        receipt_quorum: 2,
        executors: (0..executors).map(|i| [0x40 + i; 32]).collect(),
    }
}

#[test]
fn init_market_is_211_plus_32n_bytes() {
    for n in [1u8, 3, 8] {
        let a = init_args(n);
        let ix = init_market(
            &PROGRAM,
            &CREATOR,
            &BASE_MINT,
            &QUOTE_MINT,
            &BASE_VAULT,
            &QUOTE_VAULT,
            &a,
        )
        .unwrap();
        let id = derive_market_id(&PROGRAM, &CREATOR, &a.salt);
        let executors: Vec<u8> = a.executors.concat();
        let data = cat(&[
            &[0],
            &id.to_le_bytes(),
            &a.salt,
            &ADMIN,
            &RELAY,
            &a.params.to_bytes(),
            &[0xc0; 32],
            &[0x0b, 0x0a],
            &[0x18, 0x17, 0x16, 0x15, 0x14, 0x13, 0x12, 0x11],
            &[0x28, 0x27, 0x26, 0x25, 0x24, 0x23, 0x22, 0x21],
            &[0x38, 0x37, 0x36, 0x35, 0x34, 0x33, 0x32, 0x31],
            &[2, n],
            &executors,
        ]);
        assert_eq!(data.len(), 211 + 32 * usize::from(n));
        assert_eq!(a.params.to_bytes().len(), 46);
        check(
            &ix,
            PROGRAM,
            &data,
            &[
                sw(CREATOR),
                w(market_pda(&PROGRAM, id).unwrap().0),
                r(BASE_MINT),
                r(QUOTE_MINT),
                r(BASE_VAULT),
                r(QUOTE_VAULT),
                r(SYSTEM_PROGRAM),
            ],
        );
    }
}

#[test]
fn init_market_refuses_more_than_eight_executors() {
    let r = init_market(
        &PROGRAM,
        &CREATOR,
        &BASE_MINT,
        &QUOTE_MINT,
        &BASE_VAULT,
        &QUOTE_VAULT,
        &init_args(9),
    );
    assert_eq!(r, Err(ClientError::TooManyExecutors));
}

#[test]
fn trader_instructions() {
    let (m, t) = (market(), trader());
    check(
        &open_trader(&PROGRAM, &OWNER, &m).unwrap(),
        PROGRAM,
        &[1],
        &[sw(OWNER), r(m), w(t), r(SYSTEM_PROGRAM)],
    );
    for (side, byte) in [(Side::Base, 0u8), (Side::Quote, 1)] {
        let amount = 0x0807_0605_0403_0201u64;
        check(
            &deposit(&PROGRAM, &OWNER, &m, &SOURCE, &QUOTE_VAULT, side, amount).unwrap(),
            PROGRAM,
            &[2, byte, 1, 2, 3, 4, 5, 6, 7, 8],
            &[
                s(OWNER),
                r(m),
                w(t),
                w(SOURCE),
                w(QUOTE_VAULT),
                r(TOKEN_PROGRAM),
            ],
        );
        check(
            &withdraw(&PROGRAM, &OWNER, &m, &BASE_VAULT, &DEST, side).unwrap(),
            PROGRAM,
            &[4, byte],
            &[
                s(OWNER),
                r(m),
                w(t),
                w(BASE_VAULT),
                w(DEST),
                r(TOKEN_PROGRAM),
            ],
        );
    }
    check(
        &request_withdraw(&PROGRAM, &OWNER, &m, 0x0102, u64::MAX).unwrap(),
        PROGRAM,
        &cat(&[&[3, 2, 1, 0, 0, 0, 0, 0, 0], &[0xff; 8]]),
        &[s(OWNER), r(m), w(t)],
    );
    check(
        &cancel_withdraw_request(&PROGRAM, &OWNER, &m).unwrap(),
        PROGRAM,
        &[14],
        &[s(OWNER), r(m), w(t)],
    );
    check(
        &close_trader(&PROGRAM, &OWNER, &m).unwrap(),
        PROGRAM,
        &[23],
        &[sw(OWNER), r(m), w(t)],
    );
}

#[test]
fn batch_path_instructions() {
    let (m, b) = (market(), batch());
    let commit = commit_batch(
        &PROGRAM,
        &RELAY,
        &m,
        EPOCH,
        &Hash32([0xa1; 32]),
        0x0403_0201,
        &Hash32([0xa2; 32]),
    )
    .unwrap();
    let data = cat(&[
        &[5],
        &[8, 7, 6, 5, 4, 3, 2, 1],
        &[0xa1; 32],
        &[1, 2, 3, 4],
        &[0xa2; 32],
    ]);
    assert_eq!(data.len(), 77);
    check(
        &commit,
        PROGRAM,
        &data,
        &[sw(RELAY), w(m), w(b), r(SYSTEM_PROGRAM)],
    );

    check(
        &reveal_beacon(&PROGRAM, &CRANKER, &m, EPOCH).unwrap(),
        PROGRAM,
        &[12],
        &[s(CRANKER), r(m), w(b), r(SLOT_HASHES_SYSVAR)],
    );

    let header = [0x48u8; 283];
    for k in 0..=2usize {
        let receipt = vec![0x52u8; 390 + 17 * k];
        let ix = post_receipt(&PROGRAM, &CRANKER, &m, EPOCH, &header, &receipt).unwrap();
        let rl = u16::try_from(receipt.len()).unwrap().to_le_bytes();
        let data = cat(&[&[6], &[0x1b, 0x01], &header, &rl, &receipt]);
        assert_eq!(data.len(), 678 + 17 * k);
        check(
            &ix,
            PROGRAM,
            &data,
            &[s(CRANKER), r(m), w(b), r(INSTRUCTIONS_SYSVAR)],
        );
    }
    check(
        &cosign_receipt(&PROGRAM, &CRANKER, &m, EPOCH).unwrap(),
        PROGRAM,
        &[13],
        &[s(CRANKER), r(m), w(b), r(INSTRUCTIONS_SYSVAR)],
    );
    check(
        &finalize(&PROGRAM, &CRANKER, &m, &b),
        PROGRAM,
        &[8],
        &[s(CRANKER), r(m), w(b)],
    );
    check(
        &close_batch(&PROGRAM, &CRANKER, &m, &b),
        PROGRAM,
        &[10],
        &[s(CRANKER), w(m), w(b)],
    );
    for (reason, byte) in [
        (AbortReason::Admin, 1u8),
        (AbortReason::Relay, 2),
        (AbortReason::BeaconExpired, 3),
        (AbortReason::ExecTimeout, 4),
        (AbortReason::SettleTimeout, 5),
        (AbortReason::QuorumTimeout, 6),
    ] {
        check(
            &abort_batch(&PROGRAM, &m, &b, &ADMIN, reason),
            PROGRAM,
            &[11, byte],
            &[s(ADMIN), w(m), w(b)],
        );
    }
    check(
        &reclaim_batch(&PROGRAM, &CRANKER, &m, &b, &RELAY),
        PROGRAM,
        &[22],
        &[s(CRANKER), r(m), w(b), w(RELAY)],
    );
}

#[test]
fn delta_instructions_encode_leaves_and_list_trader_pdas() {
    let (m, b) = (market(), batch());
    let batch = settlement(&mut Rng::new(1), 7);
    let all = leaves(&batch).unwrap();
    let chunk = &all[2..5];
    let mut data = vec![0u8, 3];
    let mut metas = vec![s(CRANKER), r(m), w(b)];
    for leaf in chunk {
        let path: Vec<u8> = leaf.path.iter().flat_map(|h| h.0).collect();
        data.extend_from_slice(&cat(&[
            &leaf.index.to_le_bytes(),
            &leaf.delta.trader.0,
            &leaf.delta.base.to_le_bytes(),
            &leaf.delta.quote.to_le_bytes(),
            &[u8::try_from(leaf.path.len()).unwrap()],
            &path,
        ]));
        metas.push(w(trader_pda(&PROGRAM, &m, &leaf.delta.trader.0).unwrap().0));
    }
    data[0] = 7;
    check(
        &verify_deltas(&PROGRAM, &CRANKER, &m, EPOCH, chunk).unwrap(),
        PROGRAM,
        &data,
        &metas,
    );
    data[0] = 9;
    check(
        &apply_deltas(&PROGRAM, &CRANKER, &m, EPOCH, chunk).unwrap(),
        PROGRAM,
        &data,
        &metas,
    );
}

#[test]
fn delta_instruction_limits() {
    let m = market();
    let leaf = leaves(&settlement(&mut Rng::new(2), 1)).unwrap().remove(0);
    let many = vec![leaf.clone(); 256];
    assert_eq!(
        verify_deltas(&PROGRAM, &CRANKER, &m, EPOCH, &many),
        Err(ClientError::TooManyLeaves)
    );
    assert!(verify_deltas(&PROGRAM, &CRANKER, &m, EPOCH, &many[..255]).is_ok());
    let long = Leaf {
        path: vec![Hash32::ZERO; 256],
        ..leaf
    };
    assert!(matches!(
        apply_deltas(&PROGRAM, &CRANKER, &m, EPOCH, &[long]),
        Err(ClientError::InvalidArgument(_))
    ));
    let header = vec![0u8; usize::from(u16::MAX) + 1];
    assert!(matches!(
        post_receipt(&PROGRAM, &CRANKER, &m, EPOCH, &header, &[1]),
        Err(ClientError::InvalidArgument(_))
    ));
}

#[test]
fn governance_instructions() {
    let m = market();
    check(
        &set_halted(&PROGRAM, &ADMIN, &m, true),
        PROGRAM,
        &[15, 1],
        &[s(ADMIN), w(m)],
    );
    check(
        &set_halted(&PROGRAM, &ADMIN, &m, false),
        PROGRAM,
        &[15, 0],
        &[s(ADMIN), w(m)],
    );
    let keys: Vec<Key> = (1..=3u8).map(|i| [i; 32]).collect();
    let cases: Vec<(GovernanceChange, Vec<u8>)> = vec![
        (
            GovernanceChange::SetRelay([9; 32]),
            cat(&[&[1, 32, 0], &[9; 32]]),
        ),
        (
            GovernanceChange::SetExecutors {
                keys: keys.clone(),
                quorum: 2,
            },
            cat(&[&[2, 98, 0, 3], &keys.concat(), &[2]]),
        ),
        (
            GovernanceChange::SetCommitteeDigest(Hash32([7; 32])),
            cat(&[&[3, 32, 0], &[7; 32]]),
        ),
        (
            GovernanceChange::SetAdmin([8; 32]),
            cat(&[&[4, 32, 0], &[8; 32]]),
        ),
        (
            GovernanceChange::SetTimings {
                beacon_delay_slots: 8,
                exec_timeout_slots: 750,
                settle_timeout_slots: 9_000,
            },
            cat(&[
                &[5, 18, 0],
                &8u16.to_le_bytes(),
                &750u64.to_le_bytes(),
                &9_000u64.to_le_bytes(),
            ]),
        ),
        (
            GovernanceChange::SetTimelock(216_000),
            cat(&[&[6, 8, 0], &216_000u64.to_le_bytes()]),
        ),
    ];
    for (change, body) in cases {
        check(
            &propose_change(&PROGRAM, &ADMIN, &m, &change).unwrap(),
            PROGRAM,
            &cat(&[&[16], &body]),
            &[s(ADMIN), w(m)],
        );
    }
    let nine = GovernanceChange::SetExecutors {
        keys: vec![[1; 32]; 9],
        quorum: 1,
    };
    assert_eq!(
        propose_change(&PROGRAM, &ADMIN, &m, &nine),
        Err(ClientError::TooManyExecutors)
    );
    check(
        &apply_change(&PROGRAM, &CRANKER, &m),
        PROGRAM,
        &[17],
        &[s(CRANKER), w(m)],
    );
    check(
        &cancel_change(&PROGRAM, &ADMIN, &m),
        PROGRAM,
        &[18],
        &[s(ADMIN), w(m)],
    );
    check(
        &accept_admin(&PROGRAM, &OWNER, &m),
        PROGRAM,
        &[19],
        &[s(OWNER), w(m)],
    );
    check(
        &remove_executor(&PROGRAM, &ADMIN, &m, &[0x77; 32]),
        PROGRAM,
        &cat(&[&[20], &[0x77; 32]]),
        &[s(ADMIN), w(m)],
    );
    check(
        &claim_fees(&PROGRAM, &ADMIN, &m, &QUOTE_VAULT, &DEST, 0x0201),
        PROGRAM,
        &[21, 1, 2, 0, 0, 0, 0, 0, 0],
        &[s(ADMIN), w(m), w(QUOTE_VAULT), w(DEST), r(TOKEN_PROGRAM)],
    );
}

/// The 24 builders together use each tag 0..=23 once.
#[test]
fn every_tag_has_one_builder() {
    let (m, b) = (market(), batch());
    let leaf = leaves(&settlement(&mut Rng::new(3), 2)).unwrap();
    let root = Hash32([1; 32]);
    let ixs: Vec<Ix> = vec![
        init_market(
            &PROGRAM,
            &CREATOR,
            &BASE_MINT,
            &QUOTE_MINT,
            &BASE_VAULT,
            &QUOTE_VAULT,
            &init_args(1),
        )
        .unwrap(),
        open_trader(&PROGRAM, &OWNER, &m).unwrap(),
        deposit(&PROGRAM, &OWNER, &m, &SOURCE, &BASE_VAULT, Side::Base, 1).unwrap(),
        request_withdraw(&PROGRAM, &OWNER, &m, 1, 0).unwrap(),
        withdraw(&PROGRAM, &OWNER, &m, &BASE_VAULT, &DEST, Side::Base).unwrap(),
        commit_batch(&PROGRAM, &RELAY, &m, 1, &root, 1, &root).unwrap(),
        post_receipt(&PROGRAM, &CRANKER, &m, 1, &[2; 283], &[1; 390]).unwrap(),
        verify_deltas(&PROGRAM, &CRANKER, &m, 1, &leaf).unwrap(),
        finalize(&PROGRAM, &CRANKER, &m, &b),
        apply_deltas(&PROGRAM, &CRANKER, &m, 1, &leaf).unwrap(),
        close_batch(&PROGRAM, &CRANKER, &m, &b),
        abort_batch(&PROGRAM, &m, &b, &ADMIN, AbortReason::Admin),
        reveal_beacon(&PROGRAM, &CRANKER, &m, 1).unwrap(),
        cosign_receipt(&PROGRAM, &CRANKER, &m, 1).unwrap(),
        cancel_withdraw_request(&PROGRAM, &OWNER, &m).unwrap(),
        set_halted(&PROGRAM, &ADMIN, &m, true),
        propose_change(&PROGRAM, &ADMIN, &m, &GovernanceChange::SetTimelock(1)).unwrap(),
        apply_change(&PROGRAM, &CRANKER, &m),
        cancel_change(&PROGRAM, &ADMIN, &m),
        accept_admin(&PROGRAM, &OWNER, &m),
        remove_executor(&PROGRAM, &ADMIN, &m, &[1; 32]),
        claim_fees(&PROGRAM, &ADMIN, &m, &QUOTE_VAULT, &DEST, 1),
        reclaim_batch(&PROGRAM, &CRANKER, &m, &b, &RELAY),
        close_trader(&PROGRAM, &OWNER, &m).unwrap(),
    ];
    let tags: Vec<u8> = ixs.iter().map(|ix| ix.data[0]).collect();
    assert_eq!(tags, (0..=23).collect::<Vec<u8>>());
    assert!(ixs.iter().all(|ix| ix.program == PROGRAM));
    // Every instruction names its signer first.
    assert!(ixs.iter().all(|ix| ix.accounts[0].signer));
    let distinct: BTreeSet<u8> = tags.into_iter().collect();
    assert_eq!(distinct.len(), 24);
}

#[test]
fn ed25519_instruction_layout() {
    let ix = ed25519_verify(&[0xe1; 32], &Hash32([0xe3; 32]), &[0xe2; 64]);
    let offsets: Vec<u8> = [48u16, 0xffff, 16, 0xffff, 112, 32, 0xffff]
        .iter()
        .flat_map(|v| v.to_le_bytes())
        .collect();
    let data = cat(&[&[1, 0], &offsets, &[0xe1; 32], &[0xe2; 64], &[0xe3; 32]]);
    check(&ix, ED25519_PROGRAM, &data, &[]);
}

#[test]
fn compute_budget_instructions() {
    check(
        &compute_budget::set_limit(0x0403_0201),
        COMPUTE_BUDGET_PROGRAM,
        &[2, 1, 2, 3, 4],
        &[],
    );
    check(
        &compute_budget::set_price(0x0807_0605_0403_0201),
        COMPUTE_BUDGET_PROGRAM,
        &[3, 1, 2, 3, 4, 5, 6, 7, 8],
        &[],
    );
}

#[test]
fn spl_and_system_instructions() {
    let ata = associated_token_address(&OWNER, &BASE_MINT);
    check(
        &spl::create_ata_idempotent(&CREATOR, &OWNER, &BASE_MINT),
        ASSOCIATED_TOKEN_PROGRAM,
        &[1],
        &[
            sw(CREATOR),
            w(ata),
            r(OWNER),
            r(BASE_MINT),
            r(SYSTEM_PROGRAM),
            r(TOKEN_PROGRAM),
        ],
    );
    check(
        &spl::initialize_mint2(&BASE_MINT, &ADMIN, None, 6),
        TOKEN_PROGRAM,
        &cat(&[&[20, 6], &ADMIN, &[0]]),
        &[w(BASE_MINT)],
    );
    check(
        &spl::initialize_mint2(&BASE_MINT, &ADMIN, Some(&RELAY), 9),
        TOKEN_PROGRAM,
        &cat(&[&[20, 9], &ADMIN, &[1], &RELAY]),
        &[w(BASE_MINT)],
    );
    check(
        &spl::initialize_account3(&SOURCE, &BASE_MINT, &OWNER),
        TOKEN_PROGRAM,
        &cat(&[&[18], &OWNER]),
        &[w(SOURCE), r(BASE_MINT)],
    );
    check(
        &spl::mint_to(&BASE_MINT, &SOURCE, &ADMIN, 0x0201),
        TOKEN_PROGRAM,
        &[7, 1, 2, 0, 0, 0, 0, 0, 0],
        &[w(BASE_MINT), w(SOURCE), s(ADMIN)],
    );
    check(
        &system::create_account(&CREATOR, &BASE_MINT, 0x0102, 82, &TOKEN_PROGRAM),
        SYSTEM_PROGRAM,
        &cat(&[
            &[0, 0, 0, 0],
            &0x0102u64.to_le_bytes(),
            &82u64.to_le_bytes(),
            &TOKEN_PROGRAM,
        ]),
        &[sw(CREATOR), sw(BASE_MINT)],
    );
    check(
        &system::transfer(&CREATOR, &OWNER, 5),
        SYSTEM_PROGRAM,
        &[2, 0, 0, 0, 5, 0, 0, 0, 0, 0, 0, 0],
        &[sw(CREATOR), w(OWNER)],
    );
}

#[test]
fn meta_helpers() {
    assert_eq!(
        Meta::w([1; 32], true),
        Meta {
            key: [1; 32],
            signer: true,
            writable: true
        }
    );
    assert_eq!(
        Meta::r([1; 32], false),
        Meta {
            key: [1; 32],
            signer: false,
            writable: false
        }
    );
}
