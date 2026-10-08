//! Market parameters as JSON. The protocol crates stay serialisation free.
//! This mapping is the CLI's.

use anyhow::{Context, Result, bail};
use serde_json::{Value, json};
use timescales_core::{CommitmentScheme, FeeBps, FlowMode, MarketId, MarketParams, Rationing};

pub(crate) fn to_json(p: &MarketParams) -> Value {
    json!({
        "market": p.market.0,
        "base_lot_size": p.base_lot_size,
        "tick_size": p.tick_size,
        "band_half_width": p.band_half_width,
        "max_order_lots_log2": p.max_order_lots_log2,
        "max_orders_per_trader": p.max_orders_per_trader,
        "max_batch_envelopes": p.max_batch_envelopes,
        "max_order_lifetime": p.max_order_lifetime,
        "maker_fee_bps": p.maker_fee.0,
        "taker_fee_bps": p.taker_fee.0,
        "flow": match p.flow { FlowMode::SingleBook => "single", FlowMode::DualFlow => "dual" },
        "rationing": match p.rationing { Rationing::Lottery => "lottery", Rationing::ProRata => "pro-rata" },
        "commitment_scheme": match p.commitment_scheme {
            CommitmentScheme::Sha256 => "sha256",
            CommitmentScheme::PoseidonBn254 => "poseidon-bn254",
        },
    })
}

pub(crate) fn from_json(v: &Value) -> Result<MarketParams> {
    let u = |k: &str| {
        v.get(k)
            .and_then(Value::as_u64)
            .with_context(|| format!("missing integer `{k}`"))
    };
    let s = |k: &str| {
        v.get(k)
            .and_then(Value::as_str)
            .with_context(|| format!("missing string `{k}`"))
    };
    let p = MarketParams {
        market: MarketId(u("market")?),
        base_lot_size: u("base_lot_size")?,
        tick_size: u("tick_size")?,
        band_half_width: u32::try_from(u("band_half_width")?)?,
        max_order_lots_log2: u8::try_from(u("max_order_lots_log2")?)?,
        max_orders_per_trader: u16::try_from(u("max_orders_per_trader")?)?,
        max_batch_envelopes: u32::try_from(u("max_batch_envelopes")?)?,
        max_order_lifetime: u32::try_from(u("max_order_lifetime")?)?,
        maker_fee: FeeBps(u16::try_from(u("maker_fee_bps")?)?),
        taker_fee: FeeBps(u16::try_from(u("taker_fee_bps")?)?),
        flow: match s("flow")? {
            "single" => FlowMode::SingleBook,
            "dual" => FlowMode::DualFlow,
            other => bail!("unknown flow `{other}`"),
        },
        rationing: match s("rationing")? {
            "lottery" => Rationing::Lottery,
            "pro-rata" => Rationing::ProRata,
            other => bail!("unknown rationing `{other}`"),
        },
        commitment_scheme: match s("commitment_scheme")? {
            "sha256" => CommitmentScheme::Sha256,
            "poseidon-bn254" => CommitmentScheme::PoseidonBn254,
            other => bail!("unknown commitment scheme `{other}`"),
        },
    };
    p.validate().map_err(|e| anyhow::anyhow!("{e}"))?;
    Ok(p)
}
