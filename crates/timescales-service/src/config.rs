//! Configuration files, profiles and the start-up refusals every service
//! shares.

use std::fmt;
use std::io::Read;
use std::path::{Path, PathBuf};

use serde::Deserialize;
use serde::de::DeserializeOwned;
use thiserror::Error;

use crate::KeyError;

/// Largest configuration file read.
const MAX_CONFIG_BYTES: u64 = 1024 * 1024;

/// SHA-256 genesis hash of Solana mainnet-beta,
/// `5eykt4UsFv8P8NJdTREpY1vzqKqZKvdpKuc147dw2N9d`.
pub const MAINNET_BETA_GENESIS_HASH: [u8; 32] = [
    0x45, 0x29, 0x69, 0x98, 0xa6, 0xf8, 0xe2, 0xa7, 0x84, 0xdb, 0x5d, 0x9f, 0x95, 0xe1, 0x8f, 0xc2,
    0x3f, 0x70, 0x44, 0x1a, 0x10, 0x39, 0x44, 0x68, 0x01, 0x08, 0x98, 0x79, 0xb0, 0x8c, 0x7e, 0xf0,
];

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Profile {
    Local,
    Devnet,
    Production,
}

impl Profile {
    /// The configuration spelling: `"local"`, `"devnet"` or `"production"`.
    pub const fn as_str(self) -> &'static str {
        match self {
            Profile::Local => "local",
            Profile::Devnet => "devnet",
            Profile::Production => "production",
        }
    }

    pub fn parse(s: &str) -> Option<Profile> {
        match s {
            "local" => Some(Profile::Local),
            "devnet" => Some(Profile::Devnet),
            "production" => Some(Profile::Production),
            _ => None,
        }
    }
}

impl fmt::Display for Profile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// One rule a configuration breaks.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConfigIssue {
    /// Dotted TOML path, e.g. `api.cors_allowed_origins`.
    pub field: String,
    pub message: String,
}

impl ConfigIssue {
    pub fn new(field: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            field: field.into(),
            message: message.into(),
        }
    }
}

impl fmt::Display for ConfigIssue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.field, self.message)
    }
}

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("reading {path}: {source}")]
    Io {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("parsing {path}: {message}")]
    Parse { path: PathBuf, message: String },
    #[error("{} configuration issue(s): {}", .0.len(), Issues(.0))]
    Invalid(Vec<ConfigIssue>),
    #[error("profile {0:?} refused on mainnet-beta")]
    MainnetNonProduction(Profile),
    #[error("simulation build refused under the production profile")]
    SimulationBuild,
    #[error(transparent)]
    Key(#[from] KeyError),
}

/// Lists issues on one line, for the error message.
struct Issues<'a>(&'a [ConfigIssue]);

impl fmt::Display for Issues<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (i, issue) in self.0.iter().enumerate() {
            if i > 0 {
                f.write_str("; ")?;
            }
            write!(f, "{issue}")?;
        }
        Ok(())
    }
}

pub trait Validate {
    fn validate(&self, profile: Profile) -> Result<(), Vec<ConfigIssue>>;
}

/// Reads a TOML configuration, settles its profile and validates it.
///
/// The profile is the `profile` key of the file, either at the top level
/// or in one top-level table (`[node]`, `[member]`, `[dealer]`,
/// `[enclave]`). `profile_override` (a command-line flag) replaces it,
/// in the file's table too, so the returned configuration carries the
/// profile it was validated under. A file without a profile, or with two
/// different ones, is refused unless overridden. Unknown fields are
/// refused by the configuration types themselves (`deny_unknown_fields`).
pub fn load_config<T: DeserializeOwned + Validate>(
    path: &Path,
    profile_override: Option<Profile>,
) -> Result<T, ConfigError> {
    let text = read_config(path)?;
    let parse_error = |message: String| ConfigError::Parse {
        path: path.to_path_buf(),
        message,
    };
    let mut table: toml::Table = toml::from_str(&text).map_err(|e| parse_error(e.to_string()))?;
    let profile = settle_profile(&mut table, profile_override)
        .map_err(|issue| ConfigError::Invalid(vec![issue]))?;
    let config: T = if profile_override.is_some() {
        T::deserialize(table).map_err(|e| parse_error(e.to_string()))?
    } else {
        // Parsed from the text again so errors carry line and column.
        toml::from_str(&text).map_err(|e| parse_error(e.to_string()))?
    };
    config.validate(profile).map_err(ConfigError::Invalid)?;
    Ok(config)
}

fn read_config(path: &Path) -> Result<String, ConfigError> {
    let io = |source| ConfigError::Io {
        path: path.to_path_buf(),
        source,
    };
    let file = std::fs::File::open(path).map_err(io)?;
    let mut text = String::new();
    file.take(MAX_CONFIG_BYTES + 1)
        .read_to_string(&mut text)
        .map_err(io)?;
    if u64::try_from(text.len()).unwrap_or(u64::MAX) > MAX_CONFIG_BYTES {
        return Err(ConfigError::Parse {
            path: path.to_path_buf(),
            message: format!("larger than {MAX_CONFIG_BYTES} bytes"),
        });
    }
    Ok(text)
}

/// Finds the file's profile and applies the override.
fn settle_profile(
    table: &mut toml::Table,
    profile_override: Option<Profile>,
) -> Result<Profile, ConfigIssue> {
    let mut found: Vec<(String, &mut toml::Value)> = Vec::new();
    for (key, value) in table.iter_mut() {
        match value {
            toml::Value::Table(inner) => {
                if let Some(p) = inner.get_mut("profile") {
                    found.push((format!("{key}.profile"), p));
                }
            }
            _ if key == "profile" => found.push(("profile".to_owned(), value)),
            _ => {}
        }
    }
    let mut file_profile = None;
    for (field, value) in &found {
        let parsed = value.as_str().and_then(Profile::parse).ok_or_else(|| {
            ConfigIssue::new(field, "expected \"local\", \"devnet\" or \"production\"")
        })?;
        match file_profile {
            Some((_, p)) if p != parsed => {
                return Err(ConfigIssue::new(
                    field,
                    format!("conflicts with the profile {p} set elsewhere in the file"),
                ));
            }
            _ => file_profile = Some((field.clone(), parsed)),
        }
    }
    match (profile_override, file_profile) {
        (Some(o), file) => {
            if let Some((field, p)) = file.filter(|(_, p)| *p != o) {
                tracing::warn!(%field, file = %p, profile = %o, "profile overridden on the command line");
            }
            for (_, value) in found {
                *value = toml::Value::String(o.as_str().to_owned());
            }
            Ok(o)
        }
        (None, Some((_, p))) => Ok(p),
        (None, None) => Err(ConfigIssue::new(
            "profile",
            "no profile in the file and none given on the command line",
        )),
    }
}

/// Refuses any profile other than Production when `genesis_hash` is
/// mainnet-beta's.
pub fn check_cluster_profile(profile: Profile, genesis_hash: &[u8; 32]) -> Result<(), ConfigError> {
    if profile != Profile::Production && *genesis_hash == MAINNET_BETA_GENESIS_HASH {
        return Err(ConfigError::MainnetNonProduction(profile));
    }
    Ok(())
}

/// What a binary was built with. Exported as `timescales_build_info`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BuildInfo {
    pub version: &'static str,
    pub git_sha: &'static str,
    pub simulation: bool,
    pub sim_platform: bool,
}

/// Refuses a build with simulation compiled in (the `simulation` feature
/// or the simulated attestation platform) under the production profile.
pub fn refuse_simulation(profile: Profile, build: &BuildInfo) -> Result<(), ConfigError> {
    if profile == Profile::Production && (build.simulation || build.sim_platform) {
        return Err(ConfigError::SimulationBuild);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn table(text: &str) -> toml::Table {
        toml::from_str(text).unwrap()
    }

    #[test]
    fn the_profile_is_found_in_a_section_or_at_the_top() {
        let mut t = table("[node]\nprofile = \"devnet\"\nid = \"n\"\n");
        assert_eq!(settle_profile(&mut t, None), Ok(Profile::Devnet));
        let mut t = table("profile = \"production\"\n[admin]\nx = 1\n");
        assert_eq!(settle_profile(&mut t, None), Ok(Profile::Production));
        let mut t = table("[member]\nindex = 1\n");
        assert_eq!(settle_profile(&mut t, None).unwrap_err().field, "profile");
    }

    #[test]
    fn conflicting_or_unknown_profiles_are_issues() {
        let mut t = table("[member]\nprofile = \"local\"\n[dealer]\nprofile = \"production\"\n");
        let issue = settle_profile(&mut t, None).unwrap_err();
        assert!(issue.message.contains("conflicts"), "{issue}");
        let mut t = table("[node]\nprofile = \"staging\"\n");
        assert_eq!(
            settle_profile(&mut t, None).unwrap_err().field,
            "node.profile"
        );
        let mut t = table("[node]\nprofile = 1\n");
        assert_eq!(
            settle_profile(&mut t, None).unwrap_err().field,
            "node.profile"
        );
        // The same profile twice is fine.
        let mut t = table("[member]\nprofile = \"local\"\n[dealer]\nprofile = \"local\"\n");
        assert_eq!(settle_profile(&mut t, None), Ok(Profile::Local));
    }

    #[test]
    fn an_override_rewrites_the_file_profile() {
        let mut t = table("[node]\nprofile = \"production\"\n");
        assert_eq!(
            settle_profile(&mut t, Some(Profile::Local)),
            Ok(Profile::Local)
        );
        assert_eq!(t["node"]["profile"].as_str(), Some("local"));
        let mut t = table("[admin]\nx = 1\n");
        assert_eq!(
            settle_profile(&mut t, Some(Profile::Devnet)),
            Ok(Profile::Devnet)
        );
        assert!(t["admin"].get("profile").is_none());
    }

    #[test]
    fn profiles_spell_as_in_the_files() {
        for p in [Profile::Local, Profile::Devnet, Profile::Production] {
            assert_eq!(Profile::parse(p.as_str()), Some(p));
            assert_eq!(p.to_string(), p.as_str());
        }
        assert_eq!(Profile::parse("Production"), None);
    }
}
