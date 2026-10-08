//! Market parameter files (`config/markets/*.json`), in the JSON format the
//! `timescales` CLI writes (`timescales params`).

use std::path::Path;

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
    Ok(MarketParams {
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
    })
}

/// Reads a parameter file for an on-chain market: the `market` field is
/// replaced by the derived id, and the result must pass
/// `validate_onchain`.
pub(crate) fn load_for_market(path: &Path, market_id: u64) -> Result<MarketParams> {
    let text = std::fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
    let v: Value =
        serde_json::from_str(&text).with_context(|| format!("parse {}", path.display()))?;
    let mut p =
        from_json(&v).with_context(|| format!("market parameters in {}", path.display()))?;
    p.market = MarketId(market_id);
    p.validate_onchain()
        .map_err(|e| anyhow::anyhow!("{}: {e}", path.display()))?;
    Ok(p)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    fn repo_file(rel: &str) -> std::path::PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .join(rel)
    }

    #[test]
    fn the_local_market_passes_the_onchain_rules() {
        let p = load_for_market(&repo_file("config/markets/local-dual.json"), 77).unwrap();
        assert_eq!(p.market, MarketId(77));
        assert_eq!(p.flow, FlowMode::DualFlow);
        assert_eq!(p.max_batch_envelopes, 1024);
        assert_eq!(p.max_order_lifetime, 8);
        assert_eq!(from_json(&to_json(&p)).unwrap(), p);
    }

    #[test]
    fn refuses_params_the_program_would_refuse() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("p.json");
        // The research market config allows 2^21 envelopes per batch.
        std::fs::copy(repo_file("config/market-dual.json"), &path).unwrap();
        let err = load_for_market(&path, 1).unwrap_err();
        assert!(err.to_string().contains("settlement limit"), "{err}");
    }
}
