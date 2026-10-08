//! `timescales-admin keygen --profile <p> --out <dir>`: every key file a
//! deployment of one market needs, and the loaders
//! the other commands use.
//!
//! Secret files are created with mode 0400 and never overwritten. A
//! member's at-rest key file is 0600 because the member ratchets it in place.
//! Public halves go to `keys.json` (0644) so that scripts can
//! template configurations without reading secrets.
//!
//! Simulated enclave key file (`enclave-<x>.keys`, profile local and devnet):
//!
//! ```text
//! "TSCLSIMK" || version u8 (1) || seal_seed32 || executor_seed32 || platform_seed32
//! || has_certificate u8 || [PlatformCertificate (98 B): platform_key32 || svn u16 || sig64]
//! ```
//!
//! The certificate is the dev vendor's signature over the platform key. Only
//! a `sim-platform` build can issue it, so other builds write the file with
//! `has_certificate = 0` and say so.

use std::fs::OpenOptions;
use std::io::Write;
use std::path::Path;
use std::sync::Arc;

use anyhow::{Context, Result, bail};
use base64::Engine;
use clap::ValueEnum;
use rand_core::{OsRng, RngCore};
use serde_json::{Value, json};
use timescales_chain::{FileSigner, TxSigner};
use timescales_core::crypto::{Keypair, SealSecret, Zeroizing};
use timescales_service::store::RatchetSealer;

use crate::util::{Key, b58};

/// What the files are good for, written next to them.
pub(crate) const LOCAL_LABEL: &str = "INSECURE-LOCAL";

pub(crate) const SIM_KEY_MAGIC: &[u8; 8] = b"TSCLSIMK";
pub(crate) const SIM_KEY_VERSION: u8 = 1;
/// Security version the dev vendor certifies simulated platforms at.
pub(crate) const SIM_PLATFORM_SVN: u16 = 1;

/// Members and enclaves of the local and devnet stacks.
pub(crate) const MEMBERS: u8 = 3;
pub(crate) const ENCLAVES: [&str; 3] = ["a", "b", "c"];
pub(crate) const TRADERS: usize = 4;

#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub(crate) enum KeyProfile {
    /// Every key of the native stack, including the admin and four test
    /// traders. Labelled INSECURE-LOCAL.
    Local,
    /// The service keys of a devnet market with simulated enclaves. No admin
    /// (use a multisig) and no traders.
    Devnet,
    /// The service keys of a production market: no admin, no simulated
    /// platform, no traders. TDX enclaves draw their keys at boot. Only
    /// their fee payers are files.
    Production,
}

impl KeyProfile {
    fn label(self) -> &'static str {
        match self {
            KeyProfile::Local => LOCAL_LABEL,
            KeyProfile::Devnet => "DEVNET",
            KeyProfile::Production => "PRODUCTION",
        }
    }
}

/// File names inside the key directory.
pub(crate) mod names {
    pub(crate) const ADMIN: &str = "admin.json";
    pub(crate) const RELAY: &str = "relay.json";
    pub(crate) const CRANKER: &str = "cranker.json";
    pub(crate) const NODE_SERVICE: &str = "node-service.hex";
    pub(crate) const NODE_KEK: &str = "node-kek.hex";
    pub(crate) const NODE_NONCE: &str = "node-nonce.hex";
    pub(crate) const ADMIN_TOKEN: &str = "admin-token";
    pub(crate) const DEALER: &str = "dealer.hex";
    pub(crate) const SIM_VENDOR: &str = "sim-vendor.hex";
    pub(crate) const MANIFEST: &str = "keys.json";
    pub(crate) const MEMBERS_TOML: &str = "members.toml";
    pub(crate) const LABEL: &str = "LABEL";

    pub(crate) fn member_identity(i: u8) -> String {
        format!("member-{i}-identity.hex")
    }
    pub(crate) fn member_transport(i: u8) -> String {
        format!("member-{i}-transport.hex")
    }
    pub(crate) fn member_kek(i: u8) -> String {
        format!("member-{i}-kek.keys")
    }
    pub(crate) fn enclave_keys(x: &str) -> String {
        format!("enclave-{x}.keys")
    }
    pub(crate) fn enclave_fee_payer(x: &str) -> String {
        format!("enclave-{x}-fee-payer.json")
    }
    pub(crate) fn trader(i: usize) -> String {
        format!("trader-{i}.json")
    }
}

fn random32() -> Zeroizing<[u8; 32]> {
    let mut b = Zeroizing::new([0u8; 32]);
    OsRng.fill_bytes(b.as_mut_slice());
    b
}

/// Creates `path` with `mode`, refusing to overwrite.
fn write_new(path: &Path, bytes: &[u8], mode: u32) -> Result<()> {
    let mut opts = OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(mode);
    }
    #[cfg(not(unix))]
    let _ = mode;
    let mut f = opts
        .open(path)
        .with_context(|| format!("create {} (it must not exist yet)", path.display()))?;
    f.write_all(bytes)?;
    f.sync_all()?;
    Ok(())
}

fn write_secret(path: &Path, bytes: &[u8]) -> Result<()> {
    write_new(path, bytes, 0o400)
}

/// `secret || public` as the Solana CLI's JSON array.
fn solana_keypair_json(seed: &[u8; 32]) -> Zeroizing<String> {
    let public = Keypair::from_seed(*seed).public();
    let mut s = Zeroizing::new(String::with_capacity(64 * 4 + 2));
    s.push('[');
    for (i, b) in seed.iter().chain(public.iter()).enumerate() {
        if i > 0 {
            s.push(',');
        }
        s.push_str(&b.to_string());
    }
    s.push(']');
    s
}

/// Writes a new Solana keypair file and returns its address.
fn new_solana_keypair(dir: &Path, name: &str) -> Result<Key> {
    let seed = random32();
    write_secret(&dir.join(name), solana_keypair_json(&seed).as_bytes())?;
    Ok(Keypair::from_seed(*seed).public())
}

/// Writes a new 32-byte secret as hex and returns it.
fn new_hex_secret(dir: &Path, name: &str) -> Result<Zeroizing<[u8; 32]>> {
    let secret = random32();
    let text = Zeroizing::new(format!("{}\n", hex::encode(*secret)));
    write_secret(&dir.join(name), text.as_bytes())?;
    Ok(secret)
}

/// Public keys of a simulated enclave key file.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct SimulatedEnclave {
    executor: [u8; 32],
    seal_key: [u8; 32],
    platform_key: [u8; 32],
    certified: bool,
}

/// Writes the simulated key file of one enclave.
fn new_simulated_enclave(path: &Path, vendor_seed: &[u8; 32]) -> Result<SimulatedEnclave> {
    let seal = random32();
    let executor = random32();
    let platform = random32();
    let platform_key = Keypair::from_seed(*platform).public();
    let mut file = Zeroizing::new(Vec::with_capacity(8 + 1 + 96 + 1 + 98));
    file.extend_from_slice(SIM_KEY_MAGIC);
    file.push(SIM_KEY_VERSION);
    file.extend_from_slice(seal.as_slice());
    file.extend_from_slice(executor.as_slice());
    file.extend_from_slice(platform.as_slice());
    let certificate = platform_certificate(vendor_seed, &platform_key);
    match &certificate {
        Some(c) => {
            file.push(1);
            file.extend_from_slice(c);
        }
        None => file.push(0),
    }
    write_secret(path, &file)?;
    Ok(SimulatedEnclave {
        executor: Keypair::from_seed(*executor).public(),
        seal_key: SealSecret::from_bytes(*seal).public(),
        platform_key,
        certified: certificate.is_some(),
    })
}

#[cfg(feature = "sim-platform")]
fn platform_certificate(vendor_seed: &[u8; 32], platform_key: &[u8; 32]) -> Option<Vec<u8>> {
    let vendor = timescales_executor::attestation::simulated::SimulatedVendor::from_seed(
        *vendor_seed,
        SIM_PLATFORM_SVN,
    );
    Some(
        vendor
            .certify(platform_key, SIM_PLATFORM_SVN)
            .to_bytes()
            .to_vec(),
    )
}

#[cfg(not(feature = "sim-platform"))]
fn platform_certificate(_vendor_seed: &[u8; 32], _platform_key: &[u8; 32]) -> Option<Vec<u8>> {
    None
}

/// Writes every key of `profile` into `dir` (created, mode 0700) and returns
/// the public manifest that is also written to `keys.json`.
pub(crate) fn keygen(profile: KeyProfile, dir: &Path) -> Result<Value> {
    create_private_dir(dir)?;
    if std::fs::read_dir(dir)?.next().is_some() {
        bail!(
            "{} is not empty; keygen never overwrites keys",
            dir.display()
        );
    }
    let label = profile.label();
    write_new(
        &dir.join(names::LABEL),
        format!(
            "{label}\nWritten by `timescales-admin keygen --profile {}`.\n{}\n",
            profile_name(profile),
            match profile {
                KeyProfile::Local =>
                    "Development keys for the native local stack. Never use them with real value.",
                KeyProfile::Devnet =>
                    "Devnet keys; the enclaves use the simulated platform, which gives no security.",
                KeyProfile::Production => "Production service keys. Keep them in a secret store.",
            }
        )
        .as_bytes(),
        0o444,
    )?;

    let mut manifest = json!({
        "profile": profile_name(profile),
        "label": label,
    });
    if profile == KeyProfile::Local {
        manifest["admin"] = json!(b58(&new_solana_keypair(dir, names::ADMIN)?));
    }
    manifest["relay"] = json!(b58(&new_solana_keypair(dir, names::RELAY)?));
    manifest["cranker"] = json!(b58(&new_solana_keypair(dir, names::CRANKER)?));
    let service = new_hex_secret(dir, names::NODE_SERVICE)?;
    manifest["node_service"] = json!(hex::encode(Keypair::from_seed(*service).public()));
    new_hex_secret(dir, names::NODE_KEK)?;
    new_hex_secret(dir, names::NODE_NONCE)?;
    let token = random32();
    let token = Zeroizing::new(format!(
        "{}\n",
        base64::engine::general_purpose::STANDARD.encode(token.as_slice())
    ));
    write_secret(&dir.join(names::ADMIN_TOKEN), token.as_bytes())?;
    let dealer = new_hex_secret(dir, names::DEALER)?;
    manifest["dealer"] = json!(hex::encode(Keypair::from_seed(*dealer).public()));

    let mut members = Vec::new();
    let mut members_toml = String::from(
        "# Public keys of the key-release committee, for `timescales-admin committee build`.\n",
    );
    for i in 1..=MEMBERS {
        let identity = new_hex_secret(dir, &names::member_identity(i))?;
        let transport = new_hex_secret(dir, &names::member_transport(i))?;
        RatchetSealer::create(&dir.join(names::member_kek(i)), 0, random32())
            .map_err(|e| anyhow::anyhow!("member {i} at-rest key: {e}"))?;
        let identity = hex::encode(Keypair::from_seed(*identity).public());
        let transport = hex::encode(SealSecret::from_bytes(*transport).public());
        members_toml.push_str(&format!(
            "\n[[member]]\nindex = {i}\nidentity = \"{identity}\"\ntransport = \"{transport}\"\n"
        ));
        members.push(json!({"index": i, "identity": identity, "transport": transport}));
    }
    write_new(
        &dir.join(names::MEMBERS_TOML),
        members_toml.as_bytes(),
        0o644,
    )?;
    manifest["members"] = json!(members);

    let simulated = profile != KeyProfile::Production;
    let vendor_seed = if simulated {
        let seed = new_hex_secret(dir, names::SIM_VENDOR)?;
        manifest["sim_vendor_root"] = json!(hex::encode(Keypair::from_seed(*seed).public()));
        Some(seed)
    } else {
        None
    };
    let mut enclaves = Vec::new();
    for x in ENCLAVES {
        let fee_payer = new_solana_keypair(dir, &names::enclave_fee_payer(x))?;
        let mut entry = json!({"name": x, "fee_payer": b58(&fee_payer)});
        if let Some(seed) = &vendor_seed {
            let e = new_simulated_enclave(&dir.join(names::enclave_keys(x)), seed)?;
            entry["executor"] = json!(hex::encode(e.executor));
            entry["executor_b58"] = json!(b58(&e.executor));
            entry["seal_key"] = json!(hex::encode(e.seal_key));
            entry["platform_key"] = json!(hex::encode(e.platform_key));
            entry["certified"] = json!(e.certified);
        }
        enclaves.push(entry);
    }
    manifest["enclaves"] = json!(enclaves);
    if vendor_seed.is_some() && !cfg!(feature = "sim-platform") {
        eprintln!(
            "note: this build has no sim-platform feature, so the simulated enclave key files \
             carry no platform certificate; rebuild with `--features sim-platform` to write \
             keys a simulated enclave can boot with"
        );
    }

    if profile == KeyProfile::Local {
        let traders = (1..=TRADERS)
            .map(|i| new_solana_keypair(dir, &names::trader(i)).map(|k| b58(&k)))
            .collect::<Result<Vec<_>>>()?;
        manifest["traders"] = json!(traders);
    }
    write_new(
        &dir.join(names::MANIFEST),
        (serde_json::to_string_pretty(&manifest)? + "\n").as_bytes(),
        0o644,
    )?;
    Ok(manifest)
}

fn profile_name(p: KeyProfile) -> &'static str {
    match p {
        KeyProfile::Local => "local",
        KeyProfile::Devnet => "devnet",
        KeyProfile::Production => "production",
    }
}

fn create_private_dir(dir: &Path) -> Result<()> {
    std::fs::create_dir_all(dir).with_context(|| format!("create {}", dir.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

/// A Solana keypair file as a transaction signer (permission-checked).
pub(crate) fn load_signer(path: &Path) -> Result<Arc<dyn TxSigner>> {
    let bytes = timescales_service::keys::solana_keypair_bytes(path)
        .with_context(|| format!("load keypair {}", path.display()))?;
    let signer =
        FileSigner::from_bytes(bytes).map_err(|e| anyhow::anyhow!("{}: {e}", path.display()))?;
    Ok(Arc::new(signer))
}

/// The public manifest of a key directory.
pub(crate) fn manifest(dir: &Path) -> Result<Value> {
    let path = dir.join(names::MANIFEST);
    let text =
        std::fs::read_to_string(&path).with_context(|| format!("read {}", path.display()))?;
    Ok(serde_json::from_str(&text)?)
}

/// Public keys of a simulated enclave key file: (executor, seal key).
pub(crate) fn simulated_enclave_public(path: &Path) -> Result<([u8; 32], [u8; 32])> {
    let bytes = std::fs::read(path).with_context(|| format!("read {}", path.display()))?;
    let bytes = Zeroizing::new(bytes);
    let head = SIM_KEY_MAGIC.len() + 1;
    if bytes.len() < head + 96 + 1
        || &bytes[..SIM_KEY_MAGIC.len()] != SIM_KEY_MAGIC
        || bytes[SIM_KEY_MAGIC.len()] != SIM_KEY_VERSION
    {
        bail!("{} is not a simulated enclave key file", path.display());
    }
    let seed = |i: usize| -> Result<[u8; 32]> {
        Ok(bytes[head + 32 * i..head + 32 * (i + 1)].try_into()?)
    };
    let seal = Zeroizing::new(seed(0)?);
    let executor = Zeroizing::new(seed(1)?);
    Ok((
        Keypair::from_seed(*executor).public(),
        SealSecret::from_bytes(*seal).public(),
    ))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    #[cfg(unix)]
    fn mode(p: &Path) -> u32 {
        use std::os::unix::fs::PermissionsExt;
        std::fs::metadata(p).unwrap().permissions().mode() & 0o777
    }

    #[test]
    fn local_profile_writes_every_key_of_the_stack() {
        let dir = tempfile::tempdir().unwrap();
        let out = dir.path().join("secrets");
        let m = keygen(KeyProfile::Local, &out).unwrap();
        assert_eq!(m["label"], LOCAL_LABEL);
        assert_eq!(m["members"].as_array().unwrap().len(), 3);
        assert_eq!(m["enclaves"].as_array().unwrap().len(), 3);
        assert_eq!(m["traders"].as_array().unwrap().len(), TRADERS);

        let admin = load_signer(&out.join(names::ADMIN)).unwrap();
        assert_eq!(b58(&admin.address()), m["admin"]);
        let service =
            timescales_service::keys::ed25519_seed(&out.join(names::NODE_SERVICE)).unwrap();
        assert_eq!(hex::encode(service.public()), m["node_service"]);
        timescales_service::keys::kek(&out.join(names::NODE_KEK)).unwrap();
        let transport =
            timescales_service::keys::x25519_secret(&out.join(names::member_transport(2))).unwrap();
        assert_eq!(
            hex::encode(transport.public()),
            m["members"][1]["transport"]
        );
        RatchetSealer::load(&out.join(names::member_kek(1))).unwrap();
        let (executor, seal) =
            simulated_enclave_public(&out.join(names::enclave_keys("b"))).unwrap();
        assert_eq!(hex::encode(executor), m["enclaves"][1]["executor"]);
        assert_eq!(hex::encode(seal), m["enclaves"][1]["seal_key"]);
        assert_eq!(
            m["enclaves"][1]["certified"],
            cfg!(feature = "sim-platform")
        );
        assert_eq!(manifest(&out).unwrap(), m);

        #[cfg(unix)]
        {
            assert_eq!(mode(&out), 0o700);
            assert_eq!(mode(&out.join(names::ADMIN)), 0o400);
            assert_eq!(mode(&out.join(names::enclave_keys("a"))), 0o400);
            assert_eq!(mode(&out.join(names::ADMIN_TOKEN)), 0o400);
            assert_eq!(mode(&out.join(names::member_kek(3))), 0o600);
            assert_eq!(mode(&out.join(names::MANIFEST)), 0o644);
        }
        let label = std::fs::read_to_string(out.join(names::LABEL)).unwrap();
        assert!(label.starts_with(LOCAL_LABEL), "{label}");
    }

    #[test]
    fn production_profile_has_no_admin_traders_or_simulated_keys() {
        let dir = tempfile::tempdir().unwrap();
        let m = keygen(KeyProfile::Production, dir.path()).unwrap();
        assert!(m.get("admin").is_none());
        assert!(m.get("traders").is_none());
        assert!(m.get("sim_vendor_root").is_none());
        assert!(!dir.path().join(names::SIM_VENDOR).exists());
        assert!(!dir.path().join(names::enclave_keys("a")).exists());
        assert!(dir.path().join(names::enclave_fee_payer("a")).exists());
    }

    #[test]
    fn never_overwrites_a_key_directory() {
        let dir = tempfile::tempdir().unwrap();
        keygen(KeyProfile::Devnet, dir.path()).unwrap();
        let err = keygen(KeyProfile::Devnet, dir.path()).unwrap_err();
        assert!(err.to_string().contains("not empty"), "{err}");
    }

    #[cfg(feature = "sim-platform")]
    #[test]
    fn simulated_certificates_verify_under_the_vendor_root() {
        use timescales_executor::attestation::simulated::PlatformCertificate;
        let dir = tempfile::tempdir().unwrap();
        let m = keygen(KeyProfile::Local, dir.path()).unwrap();
        let root = crate::util::parse_hex32(m["sim_vendor_root"].as_str().unwrap()).unwrap();
        let bytes = std::fs::read(dir.path().join(names::enclave_keys("c"))).unwrap();
        assert_eq!(bytes[9 + 96], 1);
        let cert = PlatformCertificate::from_bytes(&bytes[9 + 96 + 1..]).unwrap();
        cert.verify(&root).unwrap();
        assert_eq!(
            hex::encode(cert.platform_key),
            m["enclaves"][2]["platform_key"]
        );
    }
}
