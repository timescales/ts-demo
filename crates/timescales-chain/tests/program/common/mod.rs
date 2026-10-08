//! Helpers shared by the integration suites: conversion to the Solana SDK
//! types, real legacy-transaction serialization, a deterministic generator
//! and sample market parameters.

#![allow(dead_code, clippy::unwrap_used)]

use solana_address::Address;
use solana_instruction::{AccountMeta, Instruction};
use solana_message::Message;
use solana_transaction::Transaction;
use timescales_auction::settlement::{AccountDelta, SettlementBatch};
use timescales_chain::program::{Ix, Key};
use timescales_core::{
    CommitmentScheme, EpochId, FeeBps, FlowMode, MarketId, MarketParams, QuoteAtoms, Rationing,
    TraderId,
};

pub(crate) fn sdk(ix: &Ix) -> Instruction {
    Instruction {
        program_id: Address::from(ix.program),
        accounts: ix
            .accounts
            .iter()
            .map(|m| AccountMeta {
                pubkey: Address::from(m.key),
                is_signer: m.signer,
                is_writable: m.writable,
            })
            .collect(),
        data: ix.data.clone(),
    }
}

/// A legacy transaction carrying `ixs` with fee payer `payer`, compiled by
/// `solana-message` and serialized by `solana-transaction` with one
/// signature slot per required signer: `(wire bytes, signatures)`.
pub(crate) fn wire(ixs: &[Ix], payer: &Key) -> (usize, usize) {
    let sdk_ixs: Vec<Instruction> = ixs.iter().map(sdk).collect();
    let msg = Message::new(&sdk_ixs, Some(&Address::from(*payer)));
    let signatures = usize::from(msg.header.num_required_signatures);
    let tx = Transaction::new_unsigned(msg);
    (bincode::serialize(&tx).unwrap().len(), signatures)
}

/// SplitMix64: reproducible inputs without a property-testing dependency.
pub(crate) struct Rng(u64);

impl Rng {
    pub(crate) fn new(seed: u64) -> Self {
        Self(seed)
    }

    pub(crate) fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }

    /// Uniform in `0..n` up to a negligible bias.
    pub(crate) fn below(&mut self, n: u64) -> u64 {
        self.next_u64() % n
    }

    pub(crate) fn coin(&mut self) -> bool {
        self.next_u64() & 1 == 1
    }

    pub(crate) fn byte(&mut self) -> u8 {
        self.next_u64().to_le_bytes()[0]
    }

    pub(crate) fn bytes(&mut self, n: usize) -> Vec<u8> {
        (0..n).map(|_| self.byte()).collect()
    }

    pub(crate) fn key(&mut self) -> Key {
        let mut k = [0u8; 32];
        for chunk in k.chunks_mut(8) {
            chunk.copy_from_slice(&self.next_u64().to_le_bytes());
        }
        k
    }

    pub(crate) fn i64(&mut self) -> i64 {
        i64::from_le_bytes(self.next_u64().to_le_bytes())
    }
}

/// Valid on-chain parameters (the program suites use the same values).
pub(crate) fn params(market_id: u64) -> MarketParams {
    MarketParams {
        market: MarketId(market_id),
        base_lot_size: 1,
        tick_size: 1,
        band_half_width: 16,
        max_order_lots_log2: 40,
        max_orders_per_trader: 8,
        max_batch_envelopes: 1024,
        max_order_lifetime: 16,
        maker_fee: FeeBps(0),
        taker_fee: FeeBps(10),
        flow: FlowMode::DualFlow,
        rationing: Rationing::ProRata,
        commitment_scheme: CommitmentScheme::Sha256,
    }
}

/// `n` deltas for distinct random traders, sorted by trader.
pub(crate) fn settlement(rng: &mut Rng, n: usize) -> SettlementBatch {
    let mut deltas: Vec<AccountDelta> = (0..n)
        .map(|_| AccountDelta {
            trader: TraderId(rng.key()),
            base: rng.i64() >> 8,
            quote: rng.i64() >> 8,
        })
        .collect();
    deltas.sort_by_key(|d| d.trader);
    SettlementBatch {
        market: MarketId(7),
        epoch: EpochId(3),
        deltas,
        fees: QuoteAtoms(0),
    }
}
