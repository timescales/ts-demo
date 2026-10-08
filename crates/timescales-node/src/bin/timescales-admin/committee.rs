//! `committee build` and `committee digest`: the description whose
//! digest the market anchors on chain.

use std::path::Path;

use anyhow::{Context, Result, bail};
use serde::Deserialize;
use serde_json::{Value, json};
use timescales_core::{Decode, Encode};
use timescales_service::wire::{CommitteeDescription, CommitteeMember};

use crate::util::{Key, b58, parse_hex32};

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct MembersFile {
    member: Vec<MemberEntry>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct MemberEntry {
    index: u8,
    /// Ed25519 identity public key, hex.
    identity: String,
    /// X25519 transport public key, hex.
    transport: String,
}

/// Reads a members file (`keys.toml` format written by `keygen`).
pub(crate) fn read_members(path: &Path) -> Result<Vec<CommitteeMember>> {
    let text = std::fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
    let file: MembersFile =
        toml::from_str(&text).with_context(|| format!("parse {}", path.display()))?;
    let mut members = file
        .member
        .into_iter()
        .map(|m| {
            Ok(CommitteeMember {
                index: m.index,
                identity: parse_hex32(&m.identity)
                    .with_context(|| format!("member {} identity", m.index))?,
                transport: parse_hex32(&m.transport)
                    .with_context(|| format!("member {} transport", m.index))?,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    members.sort_by_key(|m| m.index);
    Ok(members)
}

pub(crate) fn build(
    market: Key,
    threshold: u8,
    members: Vec<CommitteeMember>,
) -> Result<CommitteeDescription> {
    let c = CommitteeDescription {
        version: CommitteeDescription::VERSION,
        market,
        threshold,
        members,
    };
    c.validate()
        .map_err(|e| anyhow::anyhow!("invalid committee: {e}"))?;
    Ok(c)
}

pub(crate) fn read(path: &Path) -> Result<CommitteeDescription> {
    let bytes = std::fs::read(path).with_context(|| format!("read {}", path.display()))?;
    let c = CommitteeDescription::decode_exact(&bytes)
        .with_context(|| format!("{} is not a committee description", path.display()))?;
    c.validate()
        .map_err(|e| anyhow::anyhow!("{}: invalid committee: {e}", path.display()))?;
    Ok(c)
}

pub(crate) fn write(path: &Path, c: &CommitteeDescription) -> Result<()> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    std::fs::write(path, c.to_bytes()).with_context(|| format!("write {}", path.display()))
}

pub(crate) fn describe(c: &CommitteeDescription) -> Value {
    json!({
        "digest": c.digest().to_hex(),
        "market": b58(&c.market),
        "threshold": c.threshold,
        "members": c.members.iter().map(|m| json!({
            "index": m.index,
            "identity": hex::encode(m.identity),
            "transport": hex::encode(m.transport),
        })).collect::<Vec<_>>(),
    })
}

/// Checks that `c` is the committee of `market`.
pub(crate) fn check_market(c: &CommitteeDescription, market: &Key) -> Result<()> {
    if c.market != *market {
        bail!(
            "the committee is for market {}, not {}",
            b58(&c.market),
            b58(market)
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    fn members_file(dir: &Path, n: u8) -> std::path::PathBuf {
        let mut text = String::new();
        for i in (1..=n).rev() {
            let identity = timescales_core::crypto::Keypair::from_seed([i; 32]).public();
            let transport = timescales_core::crypto::SealSecret::from_bytes([i + 100; 32]).public();
            text.push_str(&format!(
                "[[member]]\nindex = {i}\nidentity = \"{}\"\ntransport = \"{}\"\n",
                hex::encode(identity),
                hex::encode(transport)
            ));
        }
        let path = dir.join("members.toml");
        std::fs::write(&path, text).unwrap();
        path
    }

    #[test]
    fn builds_writes_and_reads_back_a_committee() {
        let dir = tempfile::tempdir().unwrap();
        let members = read_members(&members_file(dir.path(), 3)).unwrap();
        assert_eq!(
            members.iter().map(|m| m.index).collect::<Vec<_>>(),
            [1, 2, 3]
        );
        let c = build([5; 32], 2, members).unwrap();
        let path = dir.path().join("out/committee.bin");
        write(&path, &c).unwrap();
        let back = read(&path).unwrap();
        assert_eq!(back, c);
        assert_eq!(describe(&back)["digest"], c.digest().to_hex());
        check_market(&back, &[5; 32]).unwrap();
        assert!(check_market(&back, &[6; 32]).is_err());
    }

    #[test]
    fn refuses_a_committee_with_two_disjoint_quorums() {
        let dir = tempfile::tempdir().unwrap();
        let members = read_members(&members_file(dir.path(), 3)).unwrap();
        // n = 3 > 2t - 1 = 1.
        let err = build([5; 32], 1, members).unwrap_err();
        assert!(err.to_string().contains("disjoint"), "{err}");
    }
}
