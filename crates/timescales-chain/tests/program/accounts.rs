//! Account decoders against the account offset tables: every field is written
//! at its documented offset here (independently of the decoders' sequential
//! reading), decoded, and compared. Lengths, tags, layout versions and
//! closed value sets are refused exactly. Arbitrary bytes never panic.

#![allow(clippy::unwrap_used)]

use super::common;

use common::{Rng, params};
use timescales_chain::program::{
    AbortReason, BATCH_LEN, BatchStatus, ClientError, GovernanceChange, Key, MARKET_LEN,
    PendingChange, Side, TRADER_LEN, TraderAccount, available, decode_batch, decode_market,
    decode_trader,
};
use timescales_core::{Encode, Hash32, MarketParams};

fn put(d: &mut [u8], off: usize, b: &[u8]) {
    d[off..off + b.len()].copy_from_slice(b);
}

struct MarketSample {
    bump: u8,
    flags: u8,
    market_id: u64,
    keys: [Key; 8],
    params: MarketParams,
    digests: [Key; 2],
    executor_count: u8,
    quorum: u8,
    executors: [Key; 8],
    beacon_delay: u16,
    words: [u64; 8],
    roots: [Key; 2],
    pending_kind: u8,
    pending_eta: u64,
    pending_payload: Vec<u8>,
    salt: Key,
    prev_committee: Key,
}

impl MarketSample {
    fn random(rng: &mut Rng) -> Self {
        let pending = match rng.below(7) {
            0 => None,
            1 => Some(GovernanceChange::SetRelay(rng.key())),
            2 => Some(GovernanceChange::SetExecutors {
                keys: (0..rng.below(9)).map(|_| rng.key()).collect(),
                quorum: rng.byte(),
            }),
            3 => Some(GovernanceChange::SetCommitteeDigest(Hash32(rng.key()))),
            4 => Some(GovernanceChange::SetAdmin(rng.key())),
            5 => Some(GovernanceChange::SetTimings {
                beacon_delay_slots: u16::from_le_bytes([rng.byte(), rng.byte()]),
                exec_timeout_slots: rng.next_u64(),
                settle_timeout_slots: rng.next_u64(),
            }),
            _ => Some(GovernanceChange::SetTimelock(rng.next_u64())),
        };
        let mut executors = [[0u8; 32]; 8];
        for e in &mut executors {
            if rng.coin() {
                *e = rng.key();
            }
        }
        let mut keys = [[0u8; 32]; 8];
        for k in &mut keys {
            *k = rng.key();
        }
        if rng.coin() {
            keys[2] = [0; 32];
        }
        MarketSample {
            bump: rng.byte(),
            flags: rng.byte(),
            market_id: rng.next_u64(),
            keys,
            params: params(rng.next_u64()),
            digests: [rng.key(), rng.key()],
            executor_count: rng.byte(),
            quorum: rng.byte(),
            executors,
            beacon_delay: u16::from_le_bytes([rng.byte(), rng.byte()]),
            words: [0; 8].map(|_: u64| rng.next_u64()),
            roots: [rng.key(), rng.key()],
            pending_kind: pending.as_ref().map_or(0, GovernanceChange::kind),
            pending_eta: rng.next_u64(),
            pending_payload: pending.map_or_else(|| rng.bytes(40), |c| c.payload().unwrap()),
            salt: rng.key(),
            prev_committee: rng.key(),
        }
    }

    ///  Market offsets.
    fn bytes(&self) -> Vec<u8> {
        let mut d = vec![0u8; MARKET_LEN];
        put(&mut d, 0, &[0x21, self.bump, 2, self.flags]);
        put(&mut d, 4, &self.market_id.to_le_bytes());
        for (i, off) in [12, 44, 76, 108, 140, 172, 204, 236]
            .into_iter()
            .enumerate()
        {
            put(&mut d, off, &self.keys[i]);
        }
        put(&mut d, 268, &self.params.to_bytes());
        put(&mut d, 314, &self.digests[0]);
        put(&mut d, 346, &self.digests[1]);
        put(&mut d, 378, &[self.executor_count, self.quorum]);
        for (i, e) in self.executors.iter().enumerate() {
            put(&mut d, 380 + 32 * i, e);
        }
        put(&mut d, 636, &self.beacon_delay.to_le_bytes());
        for (i, off) in [638, 646, 654, 662, 670, 678, 686, 694]
            .into_iter()
            .enumerate()
        {
            put(&mut d, off, &self.words[i].to_le_bytes());
        }
        put(&mut d, 702, &self.roots[0]);
        put(&mut d, 734, &self.roots[1]);
        put(&mut d, 766, &[self.pending_kind]);
        put(&mut d, 767, &self.pending_eta.to_le_bytes());
        let len = u16::try_from(self.pending_payload.len()).unwrap();
        put(&mut d, 775, &len.to_le_bytes());
        put(&mut d, 777, &self.pending_payload);
        put(&mut d, 1039, &self.salt);
        put(&mut d, 1071, &self.prev_committee);
        d
    }
}

#[test]
fn market_fields_sit_at_their_c3_offsets() {
    let mut rng = Rng::new(11);
    for _ in 0..500 {
        let s = MarketSample::random(&mut rng);
        let m = decode_market(&s.bytes()).unwrap();
        assert_eq!((m.bump, m.layout_version), (s.bump, 2));
        assert_eq!(m.halted, s.flags & 1 == 1);
        assert_eq!(m.market_id, s.market_id);
        assert_eq!(m.creator, s.keys[0]);
        assert_eq!(m.admin, s.keys[1]);
        assert_eq!(m.pending_admin, Some(s.keys[2]).filter(|k| *k != [0; 32]));
        assert_eq!(
            [
                m.relay,
                m.base_mint,
                m.quote_mint,
                m.base_vault,
                m.quote_vault
            ],
            [s.keys[3], s.keys[4], s.keys[5], s.keys[6], s.keys[7]]
        );
        assert_eq!(m.params, s.params);
        assert_eq!(m.params_digest.0, s.digests[0]);
        assert_eq!(m.committee_digest.0, s.digests[1]);
        assert_eq!(
            (m.executor_count, m.receipt_quorum),
            (s.executor_count, s.quorum)
        );
        assert_eq!(m.executors, s.executors);
        assert_eq!(m.beacon_delay_slots, s.beacon_delay);
        assert_eq!(
            [
                m.timelock_slots,
                m.exec_timeout_slots,
                m.settle_timeout_slots,
                m.last_committed,
                m.last_settled,
                m.last_progress_slot,
                m.fees_accrued,
                m.fees_claimed,
            ],
            s.words
        );
        assert_eq!(m.prev_receipt.0, s.roots[0]);
        assert_eq!(m.state_root.0, s.roots[1]);
        let want = (s.pending_kind != 0).then(|| PendingChange {
            eta_slot: s.pending_eta,
            change: GovernanceChange::decode(s.pending_kind, &s.pending_payload).unwrap(),
        });
        assert_eq!(m.pending, want);
        assert_eq!(m.salt, s.salt);
        assert_eq!(m.prev_committee_digest.0, s.prev_committee);
    }
}

#[test]
fn market_flags_read_bit_zero_only() {
    let mut s = MarketSample::random(&mut Rng::new(12));
    for (flags, halted) in [(0u8, false), (1, true), (0xfe, false), (0xff, true)] {
        s.flags = flags;
        assert_eq!(decode_market(&s.bytes()).unwrap().halted, halted);
    }
}

#[test]
fn market_pending_slot() {
    let mut s = MarketSample::random(&mut Rng::new(13));
    // Kind 0 is "none", whatever the rest of the slot holds.
    s.pending_kind = 0;
    s.pending_payload = vec![0xab; 262];
    assert_eq!(decode_market(&s.bytes()).unwrap().pending, None);
    // A known kind with a payload of the wrong length, an unknown kind and
    // a length beyond the slot are malformed.
    s.pending_kind = GovernanceChange::SET_RELAY;
    s.pending_payload = vec![1; 33];
    assert_eq!(decode_market(&s.bytes()), Err(ClientError::Malformed));
    s.pending_kind = 7;
    s.pending_payload = vec![1; 32];
    assert_eq!(decode_market(&s.bytes()), Err(ClientError::Malformed));
    s.pending_kind = GovernanceChange::SET_TIMELOCK;
    s.pending_payload = 9u64.to_le_bytes().to_vec();
    let mut d = s.bytes();
    assert_eq!(
        decode_market(&d).unwrap().pending.unwrap().change,
        GovernanceChange::SetTimelock(9)
    );
    put(&mut d, 775, &263u16.to_le_bytes());
    assert_eq!(decode_market(&d), Err(ClientError::Malformed));
}

#[test]
fn market_params_must_decode() {
    let s = MarketSample::random(&mut Rng::new(14));
    let mut d = s.bytes();
    // Flow mode byte (params offset 43).
    d[268 + 43] = 2;
    assert_eq!(decode_market(&d), Err(ClientError::Malformed));
}

#[test]
fn market_helpers() {
    let mut s = MarketSample::random(&mut Rng::new(15));
    s.executors = [[0; 32]; 8];
    s.executors[1] = [7; 32];
    s.executors[6] = [8; 32];
    s.quorum = 2;
    s.words[3] = 5;
    s.words[4] = 4;
    s.words[6] = 100;
    s.words[7] = 30;
    let m = decode_market(&s.bytes()).unwrap();
    assert_eq!(m.live_slots(), 0b0100_0010);
    assert_eq!(m.executor_slot(&[8; 32]), Some(6));
    assert_eq!(m.executor_slot(&[0; 32]), None);
    assert_eq!(m.executor_slot(&[9; 32]), None);
    assert!(m.quorum_met(0b0100_0010));
    assert!(!m.quorum_met(0b0000_0011), "slot 0 is empty");
    assert!(m.in_flight());
    assert_eq!(m.unclaimed_fees(), 70);
    assert_eq!(m.vault(Side::Base), s.keys[6]);
    assert_eq!(m.vault(Side::Quote), s.keys[7]);
    assert_eq!(m.mint(Side::Base), s.keys[4]);
    assert_eq!(m.mint(Side::Quote), s.keys[5]);
}

///  Trader offsets.
fn trader_bytes(bump: u8, market: &Key, owner: &Key, words: &[u64; 10]) -> Vec<u8> {
    let mut d = vec![0u8; TRADER_LEN];
    put(&mut d, 0, &[0x22, bump, 2, 0]);
    put(&mut d, 4, market);
    put(&mut d, 36, owner);
    for (i, w) in words.iter().enumerate() {
        put(&mut d, 68 + 8 * i, &w.to_le_bytes());
    }
    d
}

#[test]
fn trader_fields_sit_at_their_c3_offsets() {
    let mut rng = Rng::new(21);
    for _ in 0..500 {
        let (market, owner) = (rng.key(), rng.key());
        let words = [0; 10].map(|_: u64| rng.next_u64());
        let bump = rng.byte();
        let t = decode_trader(&trader_bytes(bump, &market, &owner, &words)).unwrap();
        assert_eq!(
            t,
            TraderAccount {
                bump,
                layout_version: 2,
                market,
                owner,
                base: words[0],
                quote: words[1],
                requested_base: words[2],
                requested_quote: words[3],
                request_epoch: words[4],
                last_leaf_epoch: words[5],
                last_change_slot: words[6],
                floor_epoch: words[7],
                floor_base: words[8],
                floor_quote: words[9],
            }
        );
    }
}

struct BatchSample {
    head: [u8; 8],
    keys: [Key; 9],
    epoch: u64,
    count: u32,
    slots: [u64; 5],
    settlement_count: u32,
    fees: u64,
    verified_count: u32,
    applied_count: u32,
    sums: [i128; 2],
    verified: [u8; 128],
    applied: [u8; 128],
}

impl BatchSample {
    fn random(rng: &mut Rng) -> Self {
        let status = 1 + rng.byte() % 6;
        let reason = if status == 6 { 1 + rng.byte() % 6 } else { 0 };
        let mut keys = [[0u8; 32]; 9];
        for k in &mut keys {
            *k = rng.key();
        }
        let mut bitmap = || {
            let mut b = [0u8; 128];
            b.copy_from_slice(&rng.bytes(128));
            b
        };
        let (verified, applied) = (bitmap(), bitmap());
        let sum = |rng: &mut Rng| i128::from(rng.i64()) * i128::from(rng.i64());
        BatchSample {
            head: [
                0x23,
                rng.byte(),
                2,
                status,
                reason,
                rng.byte(),
                rng.byte(),
                0,
            ],
            keys,
            epoch: rng.next_u64(),
            count: u32::try_from(rng.below(1 << 20)).unwrap(),
            slots: [0; 5].map(|_: u64| rng.next_u64()),
            settlement_count: u32::try_from(rng.below(1025)).unwrap(),
            fees: rng.next_u64(),
            verified_count: u32::try_from(rng.below(1025)).unwrap(),
            applied_count: u32::try_from(rng.below(1025)).unwrap(),
            sums: [sum(rng), sum(rng)],
            verified,
            applied,
        }
    }

    ///  Batch offsets. Keys are market, root, terms, beacon, header
    /// digest, receipt, outcome digest, next state root, settlement root.
    fn bytes(&self) -> Vec<u8> {
        let mut d = vec![0u8; BATCH_LEN];
        put(&mut d, 0, &self.head);
        put(&mut d, 8, &self.keys[0]);
        put(&mut d, 40, &self.epoch.to_le_bytes());
        put(&mut d, 48, &self.keys[1]);
        put(&mut d, 80, &self.count.to_le_bytes());
        put(&mut d, 84, &self.keys[2]);
        put(&mut d, 116, &self.slots[0].to_le_bytes());
        put(&mut d, 124, &self.slots[1].to_le_bytes());
        put(&mut d, 132, &self.slots[2].to_le_bytes());
        put(&mut d, 140, &self.keys[3]);
        put(&mut d, 172, &self.slots[3].to_le_bytes());
        put(&mut d, 180, &self.slots[4].to_le_bytes());
        for (i, off) in [188, 220, 252, 284, 316].into_iter().enumerate() {
            put(&mut d, off, &self.keys[4 + i]);
        }
        put(&mut d, 348, &self.settlement_count.to_le_bytes());
        put(&mut d, 352, &self.fees.to_le_bytes());
        put(&mut d, 360, &self.verified_count.to_le_bytes());
        put(&mut d, 364, &self.applied_count.to_le_bytes());
        put(&mut d, 368, &self.sums[0].to_le_bytes());
        put(&mut d, 384, &self.sums[1].to_le_bytes());
        put(&mut d, 400, &self.verified);
        put(&mut d, 528, &self.applied);
        d
    }
}

#[test]
fn batch_fields_sit_at_their_c3_offsets() {
    let mut rng = Rng::new(31);
    for _ in 0..500 {
        let s = BatchSample::random(&mut rng);
        let b = decode_batch(&s.bytes()).unwrap();
        assert_eq!((b.bump, b.layout_version), (s.head[1], 2));
        assert_eq!(b.status as u8, s.head[3]);
        assert_eq!(b.abort_reason.map_or(0, |r| r as u8), s.head[4]);
        assert_eq!((b.cosign_count, b.cosign_bitmap), (s.head[5], s.head[6]));
        assert_eq!(b.market, s.keys[0]);
        assert_eq!(b.epoch, s.epoch);
        assert_eq!(b.root.0, s.keys[1]);
        assert_eq!(b.count, s.count);
        assert_eq!(b.terms_digest.0, s.keys[2]);
        assert_eq!(
            [
                b.commit_slot,
                b.beacon_slot_a,
                b.beacon_slot_b,
                b.reveal_slot,
                b.receipt_slot
            ],
            s.slots
        );
        assert_eq!(b.beacon.0, s.keys[3]);
        assert_eq!(
            [
                b.header_digest.0,
                b.receipt.0,
                b.outcome_digest.0,
                b.next_state_root.0,
                b.settlement_root.0
            ],
            [s.keys[4], s.keys[5], s.keys[6], s.keys[7], s.keys[8]]
        );
        assert_eq!(b.settlement_count, s.settlement_count);
        assert_eq!(b.fees, s.fees);
        assert_eq!(
            (b.verified_count, b.applied_count),
            (s.verified_count, s.applied_count)
        );
        assert_eq!([b.sum_base, b.sum_quote], s.sums);
        assert_eq!((b.verified, b.applied), (s.verified, s.applied));

        let naive = |map: &[u8; 128]| -> Vec<u32> {
            (0..s.settlement_count)
                .filter(|i| {
                    let i = usize::try_from(*i).unwrap();
                    (map[i / 8] >> (i % 8)) & 1 == 0
                })
                .collect()
        };
        assert_eq!(b.missing_verified(), naive(&s.verified));
        assert_eq!(b.missing_applied(), naive(&s.applied));
    }
}

#[test]
fn batch_closed_value_sets() {
    let mut s = BatchSample::random(&mut Rng::new(32));
    for status in 1..=6u8 {
        s.head[3] = status;
        s.head[4] = 0;
        let b = decode_batch(&s.bytes()).unwrap();
        assert_eq!(b.status as u8, status);
        assert_eq!(b.status.is_terminal(), status >= 5);
    }
    for bad in [0u8, 7, 0xff] {
        s.head[3] = bad;
        assert_eq!(decode_batch(&s.bytes()), Err(ClientError::Malformed));
    }
    s.head[3] = 6;
    for (reason, want) in [
        (1u8, AbortReason::Admin),
        (2, AbortReason::Relay),
        (3, AbortReason::BeaconExpired),
        (4, AbortReason::ExecTimeout),
        (5, AbortReason::SettleTimeout),
        (6, AbortReason::QuorumTimeout),
    ] {
        s.head[4] = reason;
        assert_eq!(decode_batch(&s.bytes()).unwrap().abort_reason, Some(want));
    }
    s.head[4] = 7;
    assert_eq!(decode_batch(&s.bytes()), Err(ClientError::Malformed));
    s.head[4] = 0;
    s.settlement_count = 1024;
    assert!(decode_batch(&s.bytes()).unwrap().missing_applied().len() <= 1024);
    s.settlement_count = 1025;
    assert_eq!(decode_batch(&s.bytes()), Err(ClientError::Malformed));
}

#[test]
fn leaves_past_the_bitmaps_count_as_missing() {
    let mut s = BatchSample::random(&mut Rng::new(33));
    s.settlement_count = 1024;
    s.verified = [0xff; 128];
    s.applied = [0xff; 128];
    let mut b = decode_batch(&s.bytes()).unwrap();
    assert!(b.missing_verified().is_empty());
    assert!(b.missing_applied().is_empty());
    // The decoder refuses such a count. A hand-built account can hold one.
    b.settlement_count = 1030;
    let beyond: Vec<u32> = (1024..1030).collect();
    assert_eq!(b.missing_verified(), beyond);
    assert_eq!(b.missing_applied(), beyond);
}

#[test]
fn batch_status_order_follows_the_program() {
    use BatchStatus::*;
    let order = [
        Committed,
        BeaconRevealed,
        ReceiptPosted,
        Verified,
        Settled,
        Aborted,
    ];
    assert!(order.windows(2).all(|w| w[0] < w[1]));
    for (i, s) in order.iter().enumerate() {
        assert_eq!(usize::from(*s as u8), i + 1);
        assert_eq!(BatchStatus::try_from(*s as u8), Ok(*s));
    }
}

#[test]
fn length_tag_and_layout_version_are_exact() {
    let mut rng = Rng::new(41);
    let market = MarketSample::random(&mut rng).bytes();
    let trader = trader_bytes(1, &rng.key(), &rng.key(), &[1; 10]);
    let batch = BatchSample::random(&mut rng).bytes();
    type DecodeFn = fn(&[u8]) -> Result<(), ClientError>;
    let decoders: [(Vec<u8>, DecodeFn); 3] = [
        (market, |d| decode_market(d).map(drop)),
        (trader, |d| decode_trader(d).map(drop)),
        (batch, |d| decode_batch(d).map(drop)),
    ];
    for (good, decode) in &decoders {
        assert_eq!(decode(good), Ok(()));
        assert_eq!(decode(&good[..good.len() - 1]), Err(ClientError::Malformed));
        let mut long = good.clone();
        long.push(0);
        assert_eq!(decode(&long), Err(ClientError::Malformed));
        assert_eq!(decode(&[]), Err(ClientError::Malformed));
        for version in [0u8, 1, 3, 0xff] {
            let mut d = good.clone();
            d[2] = version;
            assert_eq!(decode(&d), Err(ClientError::Malformed), "version {version}");
        }
        // v1 tags (1 market, 2 trader, 3 batch) and the other v2 tags.
        for tag in [1u8, 2, 3, 0x21, 0x22, 0x23] {
            let mut d = good.clone();
            if d[0] == tag {
                continue;
            }
            d[0] = tag;
            assert_eq!(decode(&d), Err(ClientError::Malformed), "tag {tag}");
        }
    }
}

#[test]
fn arbitrary_bytes_never_panic() {
    let mut rng = Rng::new(51);
    let lens = [
        0usize, 1, 2, 3, 147, 148, 149, 687, 688, 689, 1102, 1103, 1104,
    ];
    for _ in 0..3_000 {
        let len = if rng.coin() {
            lens[usize::try_from(rng.below(u64::try_from(lens.len()).unwrap())).unwrap()]
        } else {
            usize::try_from(rng.below(1200)).unwrap()
        };
        let mut d = rng.bytes(len);
        // Often give the right header so decoding reaches the fields.
        if len > 2 && rng.coin() {
            d[0] = [0x21, 0x22, 0x23][usize::try_from(rng.below(3)).unwrap()];
            d[2] = 2;
        }
        let _ = decode_market(&d);
        let _ = decode_trader(&d);
        let _ = decode_batch(&d);
    }
}

fn trader(base: u64, quote: u64, req: (u64, u64), request_epoch: u64) -> TraderAccount {
    let words = [base, quote, req.0, req.1, request_epoch, 0, 0, 0, 0, 0];
    decode_trader(&trader_bytes(0, &[1; 32], &[2; 32], &words)).unwrap()
}

#[test]
fn available_is_the_c7_formula_capped_at_i64_max() {
    let cap = i64::MAX as u64;
    // Nothing reserved for the batch in flight when the request was made.
    let t = trader(100, 50, (30, 80), 5);
    assert_eq!(available(&t, 5), (100, 50));
    assert_eq!(available(&t, 4), (100, 50));
    // Later batches may not use min(requested, balance).
    assert_eq!(available(&t, 6), (70, 0));
    assert_eq!(t.reserved(6), (30, 50));
    let rich = trader(u64::MAX, cap + 1, (0, 1), 0);
    assert_eq!(available(&rich, 1), (cap, cap));
    let mut rng = Rng::new(61);
    for _ in 0..2_000 {
        let t = trader(
            rng.next_u64(),
            rng.next_u64(),
            (rng.next_u64(), rng.next_u64()),
            rng.below(10),
        );
        let e = rng.below(12);
        let res = |bal: u64, req: u64| if e > t.request_epoch { bal.min(req) } else { 0 };
        let want = (
            (t.base - res(t.base, t.requested_base)).min(cap),
            (t.quote - res(t.quote, t.requested_quote)).min(cap),
        );
        assert_eq!(available(&t, e), want);
    }
}
