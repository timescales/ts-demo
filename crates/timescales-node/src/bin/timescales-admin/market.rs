//! `market id` and `market init` (`InitMarket`).

use anyhow::{Result, bail};
use serde_json::{Value, json};
use timescales_chain::program::{InitMarketArgs, Ix, MAX_EXECUTORS, spl};
use timescales_core::{Hash32, MarketParams};

use crate::util::{Key, b58, nonzero};

/// The market of `(program, creator, salt)`: its id and PDA.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct MarketAddress {
    pub(crate) id: u64,
    pub(crate) address: Key,
    pub(crate) bump: u8,
}

pub(crate) fn derive(program: &Key, creator: &Key, salt: &[u8; 32]) -> Result<MarketAddress> {
    let id = timescales_chain::program::derive_market_id(program, creator, salt);
    let (address, bump) = timescales_chain::program::market_pda(program, id)?;
    Ok(MarketAddress { id, address, bump })
}

pub(crate) fn describe_address(
    program: &Key,
    creator: &Key,
    salt: &[u8; 32],
    m: &MarketAddress,
) -> Value {
    json!({
        "market_id": m.id.to_string(),
        "address": b58(&m.address),
        "bump": m.bump,
        "program": b58(program),
        "creator": b58(creator),
        "salt": hex::encode(salt),
    })
}

/// The bounds of the timing fields, as the program checks them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Timings {
    pub(crate) beacon_delay_slots: u16,
    pub(crate) timelock_slots: u64,
    pub(crate) exec_timeout_slots: u64,
    pub(crate) settle_timeout_slots: u64,
}

impl Timings {
    /// Local defaults: d = 4, exec 150, settle 1,500, timelock 20
    /// (a `localnet` program build has `MIN_TIMELOCK = 0`).
    pub(crate) const LOCAL: Timings = Timings {
        beacon_delay_slots: 4,
        timelock_slots: 20,
        exec_timeout_slots: 150,
        settle_timeout_slots: 1_500,
    };

    /// Production defaults: d = 8, exec 750, settle 9,000, timelock
    /// 216,000 slots (about a day).
    pub(crate) const PRODUCTION: Timings = Timings {
        beacon_delay_slots: 8,
        timelock_slots: 216_000,
        exec_timeout_slots: 750,
        settle_timeout_slots: 9_000,
    };

    /// The bounds that do not depend on the build's `MIN_TIMELOCK`.
    pub(crate) fn check(&self) -> Result<()> {
        if !(4..=64).contains(&self.beacon_delay_slots) {
            bail!("beacon delay must be 4..=64 slots");
        }
        if !(150..=216_000).contains(&self.exec_timeout_slots) {
            bail!("exec timeout must be 150..=216000 slots");
        }
        let settle_min = self.exec_timeout_slots.saturating_mul(2);
        if !(settle_min..=1_296_000).contains(&self.settle_timeout_slots) {
            bail!("settle timeout must be between 2 x exec timeout and 1296000 slots");
        }
        if self.timelock_slots > 2_592_000 {
            bail!("timelock must be at most 2592000 slots");
        }
        Ok(())
    }
}

pub(crate) fn check_executors(executors: &[Key], quorum: u8) -> Result<()> {
    if executors.is_empty() || executors.len() > MAX_EXECUTORS {
        bail!("a market has 1..={MAX_EXECUTORS} executors");
    }
    for (i, e) in executors.iter().enumerate() {
        nonzero(e, "an executor key")?;
        if executors[..i].contains(e) {
            bail!("executor {} is listed twice", b58(e));
        }
    }
    if quorum == 0 || usize::from(quorum) > executors.len() {
        bail!("receipt quorum must be 1..={}", executors.len());
    }
    Ok(())
}

/// Everything `InitMarket` takes besides the program.
#[derive(Clone, Debug)]
pub(crate) struct InitPlan {
    pub(crate) creator: Key,
    pub(crate) salt: [u8; 32],
    pub(crate) admin: Key,
    pub(crate) relay: Key,
    pub(crate) params: MarketParams,
    pub(crate) committee_digest: Hash32,
    pub(crate) timings: Timings,
    pub(crate) receipt_quorum: u8,
    pub(crate) executors: Vec<Key>,
    pub(crate) base_mint: Key,
    pub(crate) quote_mint: Key,
}

impl InitPlan {
    pub(crate) fn address(&self, program: &Key) -> Result<MarketAddress> {
        derive(program, &self.creator, &self.salt)
    }

    /// The vaults: associated token accounts of the market PDA, which have
    /// no delegate and no close authority.
    pub(crate) fn vaults(&self, program: &Key) -> Result<(Key, Key)> {
        let market = self.address(program)?.address;
        Ok((
            timescales_chain::program::associated_token_address(&market, &self.base_mint),
            timescales_chain::program::associated_token_address(&market, &self.quote_mint),
        ))
    }

    /// `[create base vault, create quote vault, InitMarket]`, paid by the
    /// creator.
    pub(crate) fn instructions(&self, program: &Key) -> Result<Vec<Ix>> {
        nonzero(&self.admin, "admin")?;
        nonzero(&self.relay, "relay")?;
        if self.committee_digest == Hash32::ZERO {
            bail!("committee digest must not be zero");
        }
        if self.base_mint == self.quote_mint {
            bail!("base and quote mints must differ");
        }
        self.timings.check()?;
        check_executors(&self.executors, self.receipt_quorum)?;
        let m = self.address(program)?;
        if self.params.market.0 != m.id {
            bail!(
                "params name market {} but the derived id is {}",
                self.params.market.0,
                m.id
            );
        }
        self.params
            .validate_onchain()
            .map_err(|e| anyhow::anyhow!("market parameters: {e}"))?;
        let (base_vault, quote_vault) = self.vaults(program)?;
        let args = InitMarketArgs {
            salt: self.salt,
            admin: self.admin,
            relay: self.relay,
            params: self.params,
            committee_digest: self.committee_digest,
            beacon_delay_slots: self.timings.beacon_delay_slots,
            timelock_slots: self.timings.timelock_slots,
            exec_timeout_slots: self.timings.exec_timeout_slots,
            settle_timeout_slots: self.timings.settle_timeout_slots,
            receipt_quorum: self.receipt_quorum,
            executors: self.executors.clone(),
        };
        Ok(vec![
            spl::create_ata_idempotent(&self.creator, &m.address, &self.base_mint),
            spl::create_ata_idempotent(&self.creator, &m.address, &self.quote_mint),
            timescales_chain::program::init_market(
                program,
                &self.creator,
                &self.base_mint,
                &self.quote_mint,
                &base_vault,
                &quote_vault,
                &args,
            )?,
        ])
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use timescales_core::MarketId;

    use super::*;

    fn plan() -> InitPlan {
        let program = [1u8; 32];
        let creator = [2u8; 32];
        let salt = [3u8; 32];
        let id = derive(&program, &creator, &salt).unwrap().id;
        let mut params = crate::params::from_json(&serde_json::json!({
            "band_half_width": 32, "base_lot_size": 1000, "commitment_scheme": "sha256",
            "flow": "dual", "maker_fee_bps": 1, "market": 0, "max_batch_envelopes": 1024,
            "max_order_lifetime": 8, "max_order_lots_log2": 20, "max_orders_per_trader": 16,
            "rationing": "pro-rata", "taker_fee_bps": 5, "tick_size": 10
        }))
        .unwrap();
        params.market = MarketId(id);
        InitPlan {
            creator,
            salt,
            admin: [4; 32],
            relay: [5; 32],
            params,
            committee_digest: Hash32([6; 32]),
            timings: Timings::LOCAL,
            receipt_quorum: 2,
            executors: vec![[7; 32], [8; 32], [9; 32]],
            base_mint: [10; 32],
            quote_mint: [11; 32],
        }
    }

    #[test]
    fn init_creates_both_vaults_then_the_market() {
        let program = [1u8; 32];
        let p = plan();
        let ixs = p.instructions(&program).unwrap();
        assert_eq!(ixs.len(), 3);
        let (base_vault, quote_vault) = p.vaults(&program).unwrap();
        let init = &ixs[2];
        assert_eq!(init.data[0], 0);
        assert_eq!(init.data.len(), 211 + 32 * 3);
        assert_eq!(init.accounts[1].key, p.address(&program).unwrap().address);
        assert_eq!(init.accounts[4].key, base_vault);
        assert_eq!(init.accounts[5].key, quote_vault);
        assert_eq!(ixs[0].accounts[1].key, base_vault);
        assert_eq!(ixs[1].accounts[1].key, quote_vault);
    }

    #[test]
    fn refuses_what_the_program_refuses() {
        let program = [1u8; 32];
        let mut p = plan();
        p.receipt_quorum = 4;
        assert!(p.instructions(&program).is_err());
        let mut p = plan();
        p.executors[2] = p.executors[0];
        assert!(p.instructions(&program).is_err());
        let mut p = plan();
        p.params.market = MarketId(p.params.market.0 + 1);
        assert!(p.instructions(&program).is_err());
        let mut p = plan();
        p.timings.settle_timeout_slots = 299;
        assert!(p.instructions(&program).is_err());
        let mut p = plan();
        p.committee_digest = Hash32::ZERO;
        assert!(p.instructions(&program).is_err());
    }

    #[test]
    fn the_market_id_and_address_follow_c1() {
        let program = timescales_chain::program::decode_base58(crate::rpc::DEV_PROGRAM_ID).unwrap();
        let m = derive(&program, &[2; 32], &[3; 32]).unwrap();
        let h = timescales_core::crypto::hash_parts(
            timescales_core::crypto::domain::MARKET_ID,
            &[&program, &[2; 32], &[3; 32]],
        );
        assert_eq!(
            m.id,
            u64::from_le_bytes(h.as_bytes()[..8].try_into().unwrap())
        );
        assert_eq!(
            m.address,
            timescales_chain::program::find_pda(&[b"market", &m.id.to_le_bytes()], &program)
                .unwrap()
                .0
        );
    }
}
