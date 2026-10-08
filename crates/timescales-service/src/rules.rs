//! Configuration rules every service shares, for its [`Validate`]
//! implementation. **** marks the rules enforced only
//! under `profile = "production"`.
//!
//! Each rule appends what it finds to `issues`, so a service reports every
//! problem of its file at once.
//!
//! [`Validate`]: crate::Validate

use tracing_subscriber::EnvFilter;

use crate::{ConfigIssue, LogFormat, Profile, TelemetryConfig, TlsConfig};

/// An `http` or `https` URL with a host. **** `https` only.
pub fn url(field: &str, url: &str, profile: Profile, issues: &mut Vec<ConfigIssue>) {
    let Some((scheme, rest)) = url.split_once("://") else {
        issues.push(ConfigIssue::new(field, format!("{url:?} is not a URL")));
        return;
    };
    let host = rest.split(['/', '?', '#']).next().unwrap_or("");
    if host.is_empty() {
        issues.push(ConfigIssue::new(field, format!("{url:?} has no host")));
        return;
    }
    match scheme {
        "https" => {}
        "http" if profile != Profile::Production => {}
        "http" => issues.push(ConfigIssue::new(field, "must be https in production")),
        other => issues.push(ConfigIssue::new(
            field,
            format!("unsupported scheme {other:?}"),
        )),
    }
}

/// The `[tls]` section of a service link. Written out but empty
/// (`cert_file = ""`, `key_file = ""`) means no TLS, which only local and
/// devnet allow. When configured it needs both files and at least one
/// pinned peer. **** mutual TLS is required.
pub fn tls(field: &str, tls: Option<&TlsConfig>, profile: Profile, issues: &mut Vec<ConfigIssue>) {
    match tls.filter(|t| t.is_configured()) {
        None if profile == Profile::Production => {
            issues.push(ConfigIssue::new(
                field,
                "mutual TLS is required in production",
            ));
        }
        None => {}
        Some(t) => {
            if t.cert_file.as_os_str().is_empty() {
                issues.push(ConfigIssue::new(format!("{field}.cert_file"), "missing"));
            }
            if t.key_file.as_os_str().is_empty() {
                issues.push(ConfigIssue::new(format!("{field}.key_file"), "missing"));
            }
            if t.peer_spki_sha256.is_empty() {
                issues.push(ConfigIssue::new(
                    format!("{field}.peer_spki_sha256"),
                    "at least one pinned peer is needed",
                ));
            }
        }
    }
}

/// A valid `log_filter`. **** JSON logs.
pub fn telemetry(
    field: &str,
    cfg: &TelemetryConfig,
    profile: Profile,
    issues: &mut Vec<ConfigIssue>,
) {
    if let Err(e) = EnvFilter::try_new(&cfg.log_filter) {
        issues.push(ConfigIssue::new(
            format!("{field}.log_filter"),
            e.to_string(),
        ));
    }
    if profile == Profile::Production && cfg.log_format != LogFormat::Json {
        issues.push(ConfigIssue::new(
            format!("{field}.log_format"),
            "must be json in production",
        ));
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;

    fn run(f: impl FnOnce(&mut Vec<ConfigIssue>)) -> Vec<String> {
        let mut issues = Vec::new();
        f(&mut issues);
        issues.iter().map(ToString::to_string).collect()
    }

    #[test]
    fn urls() {
        for p in [Profile::Local, Profile::Devnet, Profile::Production] {
            assert!(run(|i| url("node_url", "https://node.internal:8081/x", p, i)).is_empty());
        }
        assert!(run(|i| url("node_url", "http://127.0.0.1:8081", Profile::Local, i)).is_empty());
        assert_eq!(
            run(|i| url("node_url", "http://127.0.0.1:8081", Profile::Production, i)),
            ["node_url: must be https in production"]
        );
        assert_eq!(
            run(|i| url("u", "ftp://h", Profile::Local, i)),
            ["u: unsupported scheme \"ftp\""]
        );
        assert_eq!(
            run(|i| url("u", "https:///path", Profile::Local, i)),
            ["u: \"https:///path\" has no host"]
        );
        assert_eq!(
            run(|i| url("u", "localhost:80", Profile::Local, i)),
            ["u: \"localhost:80\" is not a URL"]
        );
    }

    #[test]
    fn tls_sections() {
        let empty = TlsConfig {
            cert_file: PathBuf::new(),
            key_file: PathBuf::new(),
            peer_spki_sha256: Vec::new(),
        };
        let full = TlsConfig {
            cert_file: "/etc/a.crt".into(),
            key_file: "/run/secrets/a.key".into(),
            peer_spki_sha256: vec![[1; 32]],
        };
        for local in [Profile::Local, Profile::Devnet] {
            assert!(run(|i| tls("tls", None, local, i)).is_empty());
            assert!(run(|i| tls("tls", Some(&empty), local, i)).is_empty());
        }
        for absent in [None, Some(&empty)] {
            assert_eq!(
                run(|i| tls("member.tls", absent, Profile::Production, i)),
                ["member.tls: mutual TLS is required in production"]
            );
        }
        assert!(run(|i| tls("tls", Some(&full), Profile::Production, i)).is_empty());
        let half = TlsConfig {
            key_file: PathBuf::new(),
            peer_spki_sha256: Vec::new(),
            ..full.clone()
        };
        assert_eq!(
            run(|i| tls("tls", Some(&half), Profile::Local, i)),
            [
                "tls.key_file: missing",
                "tls.peer_spki_sha256: at least one pinned peer is needed"
            ]
        );
    }

    #[test]
    fn telemetry_tables() {
        let mut cfg = TelemetryConfig {
            log_format: LogFormat::Pretty,
            log_filter: "info,timescales_node=debug".into(),
            otlp_endpoint: String::new(),
            service_name: None,
        };
        assert!(run(|i| telemetry("telemetry", &cfg, Profile::Devnet, i)).is_empty());
        assert_eq!(
            run(|i| telemetry("telemetry", &cfg, Profile::Production, i)),
            ["telemetry.log_format: must be json in production"]
        );
        cfg.log_format = LogFormat::Json;
        cfg.log_filter = "info,timescales_node=loud".into();
        let issues = run(|i| telemetry("telemetry", &cfg, Profile::Production, i));
        assert_eq!(issues.len(), 1);
        assert!(
            issues[0].starts_with("telemetry.log_filter: "),
            "{issues:?}"
        );
    }
}
