//! `executor verify`: check an enclave's registration evidence with
//! the verifier and policy the key-release members use, then print the
//! `ProposeChange(SetExecutors)` transaction for the admin multisig.
//!
//! The identity is the JSON of `GET /enclave/v1/identity?market&nonce`,
//! fetched by the operator with the nonce passed here, so verification can
//! run offline. The policy is the `[member.policy]` table of a member's
//! configuration.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use base64::Engine;
use clap::Args;
use serde_json::{Value, json};
use timescales_chain::program::GovernanceChange;
use timescales_core::{Decode, ExecutorId, Hash32};
use timescales_executor::attestation::{
    Evidence, Measurement, Platform, QuoteVerifier, TcbStatus, VerifiedReport,
    registration_report_data,
};
use timescales_executor::policy::{AttestationPolicy, Profile, TdAttributesRule, TdPolicy};

use crate::rpc::{ChainArgs, blockhash_for};
use crate::util::{Key, b58, parse_hex32, parse_key};

#[derive(Clone, Debug, Args)]
pub(crate) struct VerifyArgs {
    /// The enclave's identity JSON (`/enclave/v1/identity`).
    #[arg(long)]
    pub(crate) identity: PathBuf,
    /// The nonce the identity was requested with (hex, 32 bytes).
    #[arg(long)]
    pub(crate) nonce: String,
    #[arg(long)]
    pub(crate) market: String,
    /// A key-release member's configuration. Its `[member.policy]` table
    /// and profile are used.
    #[arg(long)]
    pub(crate) member_config: PathBuf,
    /// Also print the SetExecutors proposal adding this executor to the
    /// market's live executors.
    #[arg(long)]
    pub(crate) propose: bool,
    /// Receipt quorum of the proposed set [default: the market's].
    #[arg(long, requires = "propose")]
    pub(crate) quorum: Option<u8>,
    /// Recent blockhash for the unsigned proposal (offline signing).
    #[arg(long, requires = "propose")]
    pub(crate) blockhash: Option<String>,
    #[command(flatten)]
    pub(crate) chain: ChainArgs,
}

/// The parts of the identity JSON the check needs.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Identity {
    pub(crate) executor: Key,
    pub(crate) seal_key: [u8; 32],
    pub(crate) platform: Platform,
    pub(crate) measurement: Hash32,
    pub(crate) evidence: Evidence,
    pub(crate) fee_payer: Option<Key>,
}

fn field<'a>(v: &'a Value, k: &str) -> Result<&'a str> {
    v.get(k)
        .and_then(Value::as_str)
        .with_context(|| format!("identity has no string `{k}`"))
}

fn platform_name(p: Platform) -> &'static str {
    match p {
        Platform::Simulated => "simulated",
        Platform::IntelTdx => "intel_tdx",
        Platform::AmdSevSnp => "amd_sev_snp",
        Platform::AwsNitro => "aws_nitro",
    }
}

fn parse_platform(s: &str) -> Result<Platform> {
    Ok(match s {
        "simulated" => Platform::Simulated,
        "intel_tdx" => Platform::IntelTdx,
        other => bail!("unknown platform `{other}`"),
    })
}

pub(crate) fn parse_identity(v: &Value) -> Result<Identity> {
    let evidence = base64::engine::general_purpose::STANDARD
        .decode(field(v, "evidence_b64")?)
        .context("evidence_b64")?;
    Ok(Identity {
        executor: parse_key(field(v, "executor")?).context("executor")?,
        seal_key: parse_hex32(field(v, "seal_key")?).context("seal_key")?,
        platform: parse_platform(field(v, "platform")?)?,
        measurement: Hash32(parse_hex32(field(v, "measurement")?).context("measurement")?),
        evidence: Evidence::decode_exact(&evidence).context("evidence encoding")?,
        fee_payer: v
            .get("fee_payer")
            .and_then(Value::as_str)
            .map(parse_key)
            .transpose()
            .context("fee_payer")?,
    })
}

/// `[member.policy]`, with what the verifier needs beside it.
#[derive(Debug)]
pub(crate) struct MemberPolicy {
    pub(crate) profile: Profile,
    pub(crate) policy: AttestationPolicy,
    pub(crate) simulated_vendor_root: Option<[u8; 32]>,
    pub(crate) tdx_collateral_file: Option<PathBuf>,
}

fn hex_n<const N: usize>(s: &str, what: &str) -> Result<Option<[u8; N]>> {
    let s = s.trim();
    if s.is_empty() {
        return Ok(None);
    }
    let mut out = [0u8; N];
    hex::decode_to_slice(s, &mut out)
        .with_context(|| format!("{what}: expected {} hex digits", 2 * N))?;
    Ok(Some(out))
}

pub(crate) fn read_member_policy(path: &Path) -> Result<MemberPolicy> {
    let text = std::fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
    let doc: toml::Table =
        toml::from_str(&text).with_context(|| format!("parse {}", path.display()))?;
    let member = doc
        .get("member")
        .and_then(toml::Value::as_table)
        .with_context(|| format!("{} has no [member] table", path.display()))?;
    let profile = match member.get("profile").and_then(toml::Value::as_str) {
        Some("local") => Profile::Local,
        Some("devnet") => Profile::Devnet,
        Some("production") => Profile::Production,
        other => bail!("member profile {other:?} is not local, devnet or production"),
    };
    let p = member
        .get("policy")
        .and_then(toml::Value::as_table)
        .context("no [member.policy] table")?;
    let strings = |k: &str| -> Result<Vec<String>> {
        p.get(k)
            .and_then(toml::Value::as_array)
            .with_context(|| format!("policy.{k} must be an array"))?
            .iter()
            .map(|v| {
                v.as_str()
                    .map(str::to_owned)
                    .with_context(|| format!("policy.{k} must hold strings"))
            })
            .collect()
    };
    let string = |k: &str| p.get(k).and_then(toml::Value::as_str).unwrap_or("");
    let platforms = strings("platforms")?
        .iter()
        .map(|s| parse_platform(s))
        .collect::<Result<BTreeSet<_>>>()?;
    let measurements = strings("measurements")?
        .iter()
        .map(|s| parse_hex32(s).map(|h| Measurement(Hash32(h))))
        .collect::<Result<BTreeSet<_>>>()?;
    let min_tcb = match string("min_tcb") {
        "up_to_date" => TcbStatus::UpToDate,
        "sw_hardening_needed" => TcbStatus::SwHardeningNeeded,
        "configuration_needed" => TcbStatus::ConfigurationNeeded,
        "out_of_date" => TcbStatus::OutOfDate,
        other => bail!("policy.min_tcb `{other}` is not a TCB status"),
    };
    let allow_debug = p
        .get("allow_debug")
        .and_then(toml::Value::as_bool)
        .context("policy.allow_debug must be a bool")?;
    let policy = AttestationPolicy {
        platforms,
        measurements,
        min_tcb,
        allow_debug,
        blocked_platforms: BTreeSet::new(),
        td: TdPolicy {
            mr_config_id: hex_n::<48>(string("tdx_mr_config_id"), "tdx_mr_config_id")?,
            attributes: hex_n::<8>(string("tdx_td_attributes_mask"), "tdx_td_attributes_mask")?
                .map(TdAttributesRule::require),
            xfam: hex_n::<8>(string("tdx_xfam"), "tdx_xfam")?,
        },
    };
    let simulated_vendor_root =
        hex_n::<32>(string("simulated_vendor_root"), "simulated_vendor_root")?;
    if policy.platforms.contains(&Platform::Simulated) && simulated_vendor_root.is_none() {
        bail!("policy.simulated_vendor_root is required when \"simulated\" is a platform");
    }
    Ok(MemberPolicy {
        profile,
        policy,
        simulated_vendor_root,
        tdx_collateral_file: p
            .get("tdx_collateral_file")
            .and_then(toml::Value::as_str)
            .filter(|s| !s.is_empty())
            .map(PathBuf::from),
    })
}

/// Security version the simulated vendor is at. `keygen` certifies
/// platforms at it.
const SIM_CURRENT_SVN: u16 = crate::keys::SIM_PLATFORM_SVN;

fn verifier_for(platform: Platform, mp: &MemberPolicy) -> Result<Box<dyn QuoteVerifier>> {
    match platform {
        Platform::Simulated => simulated_verifier(mp),
        Platform::IntelTdx => {
            let path = mp
                .tdx_collateral_file
                .as_ref()
                .context("policy.tdx_collateral_file is required for Intel TDX evidence")?;
            let json = std::fs::read(path).with_context(|| format!("read {}", path.display()))?;
            let v = timescales_executor::attestation::tdx::TdxDcapVerifier::from_collateral_json(
                &json,
                || crate::util::now_ms() / 1000,
            )
            .map_err(|e| anyhow::anyhow!("collateral {}: {e}", path.display()))?;
            Ok(Box::new(v))
        }
        other => bail!("{} evidence is not supported", platform_name(other)),
    }
}

#[cfg(feature = "sim-platform")]
fn simulated_verifier(mp: &MemberPolicy) -> Result<Box<dyn QuoteVerifier>> {
    let root = mp
        .simulated_vendor_root
        .context("policy.simulated_vendor_root is not set")?;
    Ok(Box::new(
        timescales_executor::attestation::simulated::SimulatedQuoteVerifier::from_root(
            root,
            SIM_CURRENT_SVN,
        ),
    ))
}

#[cfg(not(feature = "sim-platform"))]
fn simulated_verifier(mp: &MemberPolicy) -> Result<Box<dyn QuoteVerifier>> {
    bail!(
        "simulated evidence (vendor root {}, svn {SIM_CURRENT_SVN}) needs the `-sim` build of \
         timescales-admin (feature sim-platform)",
        mp.simulated_vendor_root
            .map(hex::encode)
            .unwrap_or_default()
    )
}

/// Verification, appraisal and the identity's own claims, in that order.
pub(crate) fn verify(
    id: &Identity,
    mp: &MemberPolicy,
    program: &Key,
    market: &Key,
    nonce: &[u8; 32],
) -> Result<VerifiedReport> {
    if let Err(issues) = mp.policy.check_profile(mp.profile) {
        let issues: Vec<String> = issues.iter().map(ToString::to_string).collect();
        bail!(
            "the member policy breaks its profile's rules: {}",
            issues.join("; ")
        );
    }
    if id.evidence.platform != id.platform {
        bail!(
            "the identity claims {} but its evidence is {}",
            platform_name(id.platform),
            platform_name(id.evidence.platform)
        );
    }
    let report = verifier_for(id.evidence.platform, mp)?
        .verify(&id.evidence)
        .map_err(|e| anyhow::anyhow!("evidence rejected: {e}"))?;
    let expected = registration_report_data(
        &id.seal_key,
        &ExecutorId(id.executor),
        program,
        market,
        nonce,
    );
    mp.policy
        .appraise(&report, &expected)
        .map_err(|e| anyhow::anyhow!("policy refuses the evidence: {e}"))?;
    if report.measurement.0 != id.measurement {
        bail!("the identity's measurement differs from the one its evidence attests");
    }
    Ok(report)
}

pub(crate) async fn run(a: VerifyArgs) -> Result<Value> {
    let program = a.chain.program_id()?;
    let market = parse_key(&a.market)?;
    let nonce = parse_hex32(&a.nonce).context("--nonce")?;
    let text = std::fs::read_to_string(&a.identity)
        .with_context(|| format!("read {}", a.identity.display()))?;
    let id = parse_identity(&serde_json::from_str(&text)?)?;
    let mp = read_member_policy(&a.member_config)?;
    let report = verify(&id, &mp, &program, &market, &nonce)?;
    let mut out = json!({
        "verified": true,
        "executor": b58(&id.executor),
        "executor_hex": hex::encode(id.executor),
        "seal_key": hex::encode(id.seal_key),
        "platform": platform_name(report.platform),
        "measurement": report.measurement.0.to_hex(),
        "tcb": format!("{:?}", report.tcb),
        "platform_id": report.platform_id.to_hex(),
        "fee_payer": id.fee_payer.as_ref().map(b58),
    });
    if report.platform == Platform::Simulated {
        out["warning"] = json!(
            "SIMULATED platform: the evidence comes from a dev vendor key and proves nothing \
             about the host"
        );
    }
    if a.propose {
        let (m, _) = a.chain.connect()?.market(market).await?;
        let mut keys: Vec<Key> = m
            .executors
            .iter()
            .copied()
            .filter(|k| *k != [0; 32])
            .collect();
        if keys.contains(&id.executor) {
            bail!(
                "{} is already an executor of this market",
                b58(&id.executor)
            );
        }
        keys.push(id.executor);
        let quorum = a.quorum.unwrap_or(m.receipt_quorum);
        crate::market::check_executors(&keys, quorum)?;
        let change = GovernanceChange::SetExecutors { keys, quorum };
        let ix = timescales_chain::program::propose_change(&program, &m.admin, &market, &change)?;
        let blockhash = blockhash_for(&a.chain, a.blockhash.as_deref()).await?;
        let mut proposal = crate::tx::unsigned_json("propose_change", &[ix], &m.admin, &blockhash)?;
        proposal["change"] = crate::governance::describe_change(&change);
        out["proposal"] = proposal;
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use timescales_core::Encode;

    use super::*;

    fn member_config(dir: &Path, extra: &str) -> PathBuf {
        let path = dir.join("krc-1.toml");
        std::fs::write(
            &path,
            format!(
                "[member]\nprofile = \"local\"\nindex = 1\n[member.policy]\n\
                 platforms = [\"simulated\"]\nmeasurements = [\"{}\"]\nallow_debug = false\n\
                 min_tcb = \"up_to_date\"\n{extra}\n",
                hex::encode([7u8; 32])
            ),
        )
        .unwrap();
        path
    }

    #[test]
    fn reads_the_member_policy_table() {
        let dir = tempfile::tempdir().unwrap();
        let path = member_config(
            dir.path(),
            &format!("simulated_vendor_root = \"{}\"", hex::encode([1u8; 32])),
        );
        let mp = read_member_policy(&path).unwrap();
        assert_eq!(mp.profile, Profile::Local);
        assert_eq!(mp.simulated_vendor_root, Some([1; 32]));
        assert!(mp.policy.platforms.contains(&Platform::Simulated));
        assert!(
            mp.policy
                .measurements
                .contains(&Measurement(Hash32([7; 32])))
        );
        assert_eq!(mp.policy.td, TdPolicy::default());
        // A simulated platform needs the vendor root.
        let path = member_config(dir.path(), "");
        assert!(read_member_policy(&path).is_err());
    }

    #[test]
    fn identity_json_round_trips_its_fields() {
        let evidence = Evidence {
            platform: Platform::Simulated,
            quote: vec![1, 2, 3],
        };
        let v = json!({
            "executor": b58(&[2; 32]),
            "seal_key": hex::encode([3u8; 32]),
            "platform": "simulated",
            "measurement": hex::encode([4u8; 32]),
            "fee_payer": b58(&[5; 32]),
            "evidence_b64": base64::engine::general_purpose::STANDARD.encode(evidence.to_bytes()),
        });
        let id = parse_identity(&v).unwrap();
        assert_eq!(id.executor, [2; 32]);
        assert_eq!(id.evidence, evidence);
        assert_eq!(id.fee_payer, Some([5; 32]));
    }

    #[cfg(feature = "sim-platform")]
    #[test]
    fn accepts_genuine_simulated_evidence_and_refuses_a_wrong_nonce() {
        use timescales_executor::attestation::simulated::SimulatedVendor;
        let dir = tempfile::tempdir().unwrap();
        let vendor = SimulatedVendor::from_seed([9; 32], SIM_CURRENT_SVN);
        let mp = read_member_policy(&member_config(
            dir.path(),
            &format!(
                "simulated_vendor_root = \"{}\"",
                hex::encode(vendor.root_key())
            ),
        ))
        .unwrap();
        let mut rng = rand_core::OsRng;
        let platform = vendor.platform(&mut rng, SIM_CURRENT_SVN);
        let (program, market, nonce) = ([1u8; 32], [2u8; 32], [3u8; 32]);
        let executor = [4u8; 32];
        let seal_key = [5u8; 32];
        let rd =
            registration_report_data(&seal_key, &ExecutorId(executor), &program, &market, &nonce);
        let id = Identity {
            executor,
            seal_key,
            platform: Platform::Simulated,
            measurement: Hash32([7; 32]),
            evidence: platform.quote(Measurement(Hash32([7; 32])), false, rd),
            fee_payer: None,
        };
        verify(&id, &mp, &program, &market, &nonce).unwrap();
        let err = verify(&id, &mp, &program, &market, &[0; 32]).unwrap_err();
        assert!(err.to_string().contains("policy refuses"), "{err}");
        let other = Identity {
            measurement: Hash32([8; 32]),
            evidence: platform.quote(Measurement(Hash32([8; 32])), false, rd),
            ..id
        };
        assert!(verify(&other, &mp, &program, &market, &nonce).is_err());
    }

    #[cfg(not(feature = "sim-platform"))]
    #[test]
    fn simulated_evidence_needs_the_sim_build() {
        let dir = tempfile::tempdir().unwrap();
        let mp = read_member_policy(&member_config(
            dir.path(),
            &format!("simulated_vendor_root = \"{}\"", hex::encode([1u8; 32])),
        ))
        .unwrap();
        let id = Identity {
            executor: [4; 32],
            seal_key: [5; 32],
            platform: Platform::Simulated,
            measurement: Hash32([7; 32]),
            evidence: Evidence {
                platform: Platform::Simulated,
                quote: vec![],
            },
            fee_payer: None,
        };
        let err = verify(&id, &mp, &[1; 32], &[2; 32], &[3; 32]).unwrap_err();
        assert!(err.to_string().contains("sim-platform"), "{err}");
    }
}
