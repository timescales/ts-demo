//! `bootstrap-local`: on a local validator, fund the stack's
//! keys from the validator's faucet, create two mints (6 decimals each),
//! initialize the market with the derived id, the three simulated enclaves
//! as executors and `receipt_quorum = 2`, give the four test traders SOL
//! and tokens, and write `env.json` for the e2e tests, the load generator
//! and `scripts/e2e/up.sh`.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context, Result, bail};
use clap::Args;
use rand_core::{OsRng, RngCore};
use serde_json::{Value, json};
use timescales_chain::program::{Ix, TOKEN_PROGRAM, spl, system};
use timescales_chain::{FileSigner, Level, TxOp, TxSigner};
use timescales_core::crypto::{Keypair, Zeroizing};

use crate::keys::{ENCLAVES, LOCAL_LABEL, TRADERS, load_signer, manifest, names};
use crate::market::{InitPlan, Timings};
use crate::rpc::{Chain, ChainArgs};
use crate::util::{Key, b58, parse_hex32, parse_key};

const LAMPORTS_PER_SOL: u64 = 1_000_000_000;
const DECIMALS: u8 = 6;
/// Transfers per funding transaction. Well inside the size limit.
const TRANSFERS_PER_TX: usize = 8;

#[derive(Clone, Debug, Args)]
pub(crate) struct BootstrapArgs {
    /// Key directory written by `keygen --profile local`.
    #[arg(long, default_value = "target/e2e/secrets")]
    pub(crate) secrets: PathBuf,
    /// Salt of the market id (hex, 32 bytes) [default: random].
    #[arg(long)]
    pub(crate) salt: Option<String>,
    /// Committee description (`committee build`) [default: built here from
    /// `<secrets>/members.toml` with threshold 2 and written next to
    /// `--out`].
    #[arg(long)]
    pub(crate) committee: Option<PathBuf>,
    /// Market parameters. `market` is replaced by the derived id.
    #[arg(long, default_value = "config/markets/local-dual.json")]
    pub(crate) market_config: PathBuf,
    /// Keypair holding the SOL to hand out [default:
    /// $TIMESCALES_FUNDER_KEYPAIR, else the validator's faucet at
    /// target/e2e/ledger/faucet-keypair.json].
    #[arg(long)]
    pub(crate) funder: Option<PathBuf>,
    #[arg(long, default_value_t = 2)]
    pub(crate) receipt_quorum: u8,
    /// Governance timelock. A program built without the `localnet` feature
    /// (as on devnet) needs at least 216000 slots. The other timings are
    /// the local ones either way.
    #[arg(long, default_value_t = Timings::LOCAL.timelock_slots)]
    pub(crate) timelock_slots: u64,
    /// Where to write the environment file. The market's parameter file
    /// and the committee (when built here) go next to it.
    #[arg(long, default_value = "target/e2e/env.json")]
    pub(crate) out: PathBuf,
    /// SOL for each test trader and enclave fee payer (decimals allowed).
    #[arg(long, default_value = "10", value_parser = parse_sol)]
    pub(crate) sol_each: u64,
    /// SOL for the admin, which pays the rent of the mints, the market and
    /// the traders' token accounts.
    #[arg(long, default_value = "100", value_parser = parse_sol)]
    pub(crate) admin_sol: u64,
    /// SOL for the relay and the cranker each.
    #[arg(long, default_value = "10", value_parser = parse_sol)]
    pub(crate) service_sol: u64,
    /// Whole base tokens minted to each trader.
    #[arg(long, default_value_t = 1_000)]
    pub(crate) base_tokens: u64,
    /// Whole quote tokens minted to each trader.
    #[arg(long, default_value_t = 1_000_000)]
    pub(crate) quote_tokens: u64,
    #[command(flatten)]
    pub(crate) chain: ChainArgs,
}

/// A keypair that lives only for this run (the mints: their authority is
/// the admin, so their own keys are never needed again).
fn ephemeral_signer() -> Result<Arc<dyn TxSigner>> {
    let mut seed = Zeroizing::new([0u8; 32]);
    OsRng.fill_bytes(seed.as_mut_slice());
    let mut bytes = Zeroizing::new([0u8; 64]);
    bytes[..32].copy_from_slice(seed.as_slice());
    bytes[32..].copy_from_slice(&Keypair::from_seed(*seed).public());
    Ok(Arc::new(
        FileSigner::from_bytes(bytes).map_err(|e| anyhow::anyhow!("{e}"))?,
    ))
}

/// Whole or decimal SOL ("0.25") to lamports.
fn parse_sol(s: &str) -> Result<u64, String> {
    let (whole, frac) = s.split_once('.').unwrap_or((s, ""));
    if whole.is_empty() && frac.is_empty() || frac.len() > 9 {
        return Err(format!("`{s}` is not an amount of SOL"));
    }
    let digits = |d: &str| d.is_empty() || d.bytes().all(|b| b.is_ascii_digit());
    if !digits(whole) || !digits(frac) {
        return Err(format!("`{s}` is not an amount of SOL"));
    }
    let whole: u64 = if whole.is_empty() {
        0
    } else {
        whole.parse().map_err(|e| format!("{e}"))?
    };
    let frac: u64 = if frac.is_empty() {
        0
    } else {
        format!("{frac:0<9}").parse().map_err(|e| format!("{e}"))?
    };
    whole
        .checked_mul(LAMPORTS_PER_SOL)
        .and_then(|l| l.checked_add(frac))
        .ok_or_else(|| format!("`{s}` overflows"))
}

fn atoms(tokens: u64) -> Result<u64> {
    tokens
        .checked_mul(10u64.pow(u32::from(DECIMALS)))
        .context("token amount overflows u64")
}

/// Amount held by a classic token account (bytes 64..72).
async fn token_amount(c: &Chain, account: Key) -> Result<Option<u64>> {
    Ok(match c.account(account, Level::Confirmed).await? {
        Some(a) if a.owner == TOKEN_PROGRAM && a.data.len() == spl::TOKEN_ACCOUNT_LEN => {
            Some(u64::from_le_bytes(a.data[64..72].try_into()?))
        }
        _ => None,
    })
}

struct Named {
    name: String,
    signer: Arc<dyn TxSigner>,
    path: PathBuf,
}

fn named(dir: &Path, name: &str, file: &str) -> Result<Named> {
    let path = dir.join(file);
    Ok(Named {
        name: name.to_owned(),
        signer: load_signer(&path)?,
        path,
    })
}

pub(crate) async fn run(a: BootstrapArgs) -> Result<Value> {
    let keys = manifest(&a.secrets)?;
    if keys["label"] != LOCAL_LABEL {
        bail!(
            "{} holds `{}` keys; bootstrap-local only uses keys from `keygen --profile local`",
            a.secrets.display(),
            keys["label"]
        );
    }
    let c = a.chain.connect()?;
    let genesis = c.genesis_hash().await.context("reach the validator")?;
    timescales_service::check_cluster_profile(timescales_service::Profile::Local, &genesis)
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    let program = c.program;
    match c.account(program, Level::Confirmed).await? {
        Some(p) if p.data.is_empty() => bail!("{} is not a program", b58(&program)),
        Some(_) => {}
        None => bail!(
            "the settlement program {} is not deployed on {}",
            b58(&program),
            a.chain.rpc_url()
        ),
    }

    let dir = &a.secrets;
    let admin = named(dir, "admin", names::ADMIN)?;
    let relay = named(dir, "relay", names::RELAY)?;
    let cranker = named(dir, "cranker", names::CRANKER)?;
    let fee_payers = ENCLAVES
        .iter()
        .map(|x| named(dir, &format!("enclave-{x}"), &names::enclave_fee_payer(x)))
        .collect::<Result<Vec<_>>>()?;
    let traders = (1..=TRADERS)
        .map(|i| named(dir, &format!("trader-{i}"), &names::trader(i)))
        .collect::<Result<Vec<_>>>()?;
    let funder_path = a
        .funder
        .clone()
        .or_else(|| std::env::var_os("TIMESCALES_FUNDER_KEYPAIR").map(PathBuf::from))
        .unwrap_or_else(|| PathBuf::from("target/e2e/ledger/faucet-keypair.json"));
    let funder = load_signer(&funder_path).with_context(|| {
        format!(
            "the funder keypair {} (scripts/e2e/up.sh makes the validator's faucet key 0600)",
            funder_path.display()
        )
    })?;

    let executors = ENCLAVES
        .iter()
        .map(|x| {
            crate::keys::simulated_enclave_public(&dir.join(names::enclave_keys(x))).map(|(e, _)| e)
        })
        .collect::<Result<Vec<_>>>()?;

    let salt = match &a.salt {
        Some(s) => parse_hex32(s).context("--salt")?,
        None => {
            let mut s = [0u8; 32];
            OsRng.fill_bytes(&mut s);
            s
        }
    };
    let creator = admin.signer.address();
    let address = crate::market::derive(&program, &creator, &salt)?;
    let out_dir = a
        .out
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .map_or_else(|| PathBuf::from("."), Path::to_path_buf);
    std::fs::create_dir_all(&out_dir)?;

    let committee_file = match &a.committee {
        Some(p) => p.clone(),
        None => {
            let members = crate::committee::read_members(&dir.join(names::MEMBERS_TOML))?;
            let built = crate::committee::build(address.address, 2, members)?;
            let path = out_dir.join("committee.bin");
            crate::committee::write(&path, &built)?;
            path
        }
    };
    let committee = crate::committee::read(&committee_file)?;
    crate::committee::check_market(&committee, &address.address)?;
    let params = crate::params::load_for_market(&a.market_config, address.id)?;
    let params_file = out_dir.join("market-params.json");
    std::fs::write(
        &params_file,
        serde_json::to_string_pretty(&crate::params::to_json(&params))? + "\n",
    )?;

    // 1. SOL for every key that pays fees or rent.
    let sol = a.sol_each;
    let mut grants: Vec<(Key, u64)> = vec![
        (creator, a.admin_sol),
        (relay.signer.address(), a.service_sol),
        (cranker.signer.address(), a.service_sol),
    ];
    grants.extend(fee_payers.iter().map(|f| (f.signer.address(), sol)));
    grants.extend(traders.iter().map(|t| (t.signer.address(), sol)));
    let mut funded = Vec::new();
    for chunk in grants.chunks(TRANSFERS_PER_TX) {
        let mut ixs = Vec::new();
        for (to, lamports) in chunk {
            let have = c
                .account(*to, Level::Confirmed)
                .await?
                .map_or(0, |a| a.lamports);
            if have < *lamports {
                ixs.push(system::transfer(&funder.address(), to, lamports - have));
            }
            funded.push(json!({"address": b58(to), "lamports": lamports.max(&have).to_string()}));
        }
        if !ixs.is_empty() {
            c.send(TxOp::Admin, ixs, funder.clone(), vec![]).await?;
        }
    }

    // 2. Mints and the market, unless this salt's market already exists.
    let existing = match c.account(address.address, Level::Confirmed).await? {
        Some(acc) if acc.owner == program => Some(c.market(address.address).await?.0),
        _ => None,
    };
    let (base_mint, quote_mint) = match &existing {
        Some(m) => (m.base_mint, m.quote_mint),
        None => {
            let base = ephemeral_signer()?;
            let quote = ephemeral_signer()?;
            let rent = c
                .rpc
                .minimum_balance_for_rent_exemption(spl::MINT_LEN)
                .await?;
            let mut ixs = Vec::new();
            for m in [&base, &quote] {
                ixs.push(system::create_account(
                    &creator,
                    &m.address(),
                    rent,
                    u64::try_from(spl::MINT_LEN)?,
                    &TOKEN_PROGRAM,
                ));
                ixs.push(spl::initialize_mint2(
                    &m.address(),
                    &creator,
                    None,
                    DECIMALS,
                ));
            }
            c.send(
                TxOp::Admin,
                ixs,
                admin.signer.clone(),
                vec![base.clone(), quote.clone()],
            )
            .await
            .context("create the mints")?;
            (base.address(), quote.address())
        }
    };
    let plan = InitPlan {
        creator,
        salt,
        admin: creator,
        relay: relay.signer.address(),
        params,
        committee_digest: committee.digest(),
        timings: Timings {
            timelock_slots: a.timelock_slots,
            ..Timings::LOCAL
        },
        receipt_quorum: a.receipt_quorum,
        executors: executors.clone(),
        base_mint,
        quote_mint,
    };
    let (base_vault, quote_vault) = plan.vaults(&program)?;
    match &existing {
        Some(m) => {
            if m.params != params || m.committee_digest != committee.digest() {
                bail!(
                    "market {} already exists with other parameters or another committee",
                    b58(&address.address)
                );
            }
        }
        None => {
            c.send(
                TxOp::Admin,
                plan.instructions(&program)?,
                admin.signer.clone(),
                vec![],
            )
            .await
            .context("InitMarket")?;
        }
    }
    let (market, _) = c.market(address.address).await?;

    // 3. Tokens for the test traders.
    let base_atoms = atoms(a.base_tokens)?;
    let quote_atoms = atoms(a.quote_tokens)?;
    let mut trader_entries = Vec::new();
    for t in &traders {
        let owner = t.signer.address();
        let base_ata = timescales_chain::program::associated_token_address(&owner, &base_mint);
        let quote_ata = timescales_chain::program::associated_token_address(&owner, &quote_mint);
        let mut ixs: Vec<Ix> = vec![
            spl::create_ata_idempotent(&creator, &owner, &base_mint),
            spl::create_ata_idempotent(&creator, &owner, &quote_mint),
        ];
        let have_base = token_amount(&c, base_ata).await?.unwrap_or(0);
        let have_quote = token_amount(&c, quote_ata).await?.unwrap_or(0);
        if have_base < base_atoms {
            ixs.push(spl::mint_to(
                &base_mint,
                &base_ata,
                &creator,
                base_atoms - have_base,
            ));
        }
        if have_quote < quote_atoms {
            ixs.push(spl::mint_to(
                &quote_mint,
                &quote_ata,
                &creator,
                quote_atoms - have_quote,
            ));
        }
        c.send(TxOp::Admin, ixs, admin.signer.clone(), vec![])
            .await
            .with_context(|| format!("fund {}", t.name))?;
        let base = token_amount(&c, base_ata)
            .await?
            .context("base token account missing")?;
        let quote = token_amount(&c, quote_ata)
            .await?
            .context("quote token account missing")?;
        if base < base_atoms || quote < quote_atoms {
            bail!(
                "{} holds {base} base and {quote} quote atoms after funding",
                t.name
            );
        }
        trader_entries.push(json!({
            "name": t.name,
            "owner": b58(&owner),
            "keypair": t.path,
            "base_ata": b58(&base_ata),
            "quote_ata": b58(&quote_ata),
            "base_atoms": base.to_string(),
            "quote_atoms": quote.to_string(),
        }));
    }

    let enclaves = ENCLAVES
        .iter()
        .zip(&executors)
        .zip(&fee_payers)
        .map(|((x, e), f)| {
            json!({
                "name": x,
                "executor": b58(e),
                "executor_hex": hex::encode(e),
                "fee_payer": b58(&f.signer.address()),
                "fee_payer_keypair": f.path,
                "key_file": dir.join(names::enclave_keys(x)),
            })
        })
        .collect::<Vec<_>>();
    let env = json!({
        "label": LOCAL_LABEL,
        "rpc_url": a.chain.rpc_url(),
        "program_id": b58(&program),
        "genesis_hash": b58(&genesis),
        "secrets": dir,
        "market": {
            "address": b58(&address.address),
            "market_id": address.id.to_string(),
            "salt": hex::encode(salt),
            "creator": b58(&creator),
            "admin": b58(&market.admin),
            "relay": b58(&market.relay),
            "params_file": params_file,
            "params": crate::params::to_json(&market.params),
            "params_digest": market.params_digest.to_hex(),
            "committee_file": committee_file,
            "committee_digest": market.committee_digest.to_hex(),
            "committee_threshold": committee.threshold,
            "receipt_quorum": market.receipt_quorum,
            "beacon_delay_slots": market.beacon_delay_slots,
            "timelock_slots": market.timelock_slots.to_string(),
            "exec_timeout_slots": market.exec_timeout_slots.to_string(),
            "settle_timeout_slots": market.settle_timeout_slots.to_string(),
        },
        "mints": {
            "base": {"address": b58(&base_mint), "decimals": DECIMALS, "vault": b58(&base_vault)},
            "quote": {"address": b58(&quote_mint), "decimals": DECIMALS, "vault": b58(&quote_vault)},
        },
        "keys": {
            "admin": admin.path,
            "relay": relay.path,
            "cranker": cranker.path,
        },
        "enclaves": enclaves,
        "traders": trader_entries,
        "funded": funded,
    });
    std::fs::write(&a.out, serde_json::to_string_pretty(&env)? + "\n")
        .with_context(|| format!("write {}", a.out.display()))?;
    Ok(env)
}

/// `--creator` given as a key or as a keypair file.
pub(crate) fn creator_key(s: &str) -> Result<Key> {
    let p = Path::new(s);
    if p.is_file() {
        return Ok(load_signer(p)?.address());
    }
    parse_key(s)
}

#[cfg(test)]
mod tests {
    use super::parse_sol;

    #[test]
    fn sol_amounts() {
        assert_eq!(parse_sol("10"), Ok(10_000_000_000));
        assert_eq!(parse_sol("0.25"), Ok(250_000_000));
        assert_eq!(parse_sol(".5"), Ok(500_000_000));
        assert_eq!(parse_sol("1.000000001"), Ok(1_000_000_001));
        for bad in ["", ".", "1.0000000001", "-1", "1e3", "x"] {
            assert!(parse_sol(bad).is_err(), "{bad}");
        }
    }
}
