//! Keys, envelopes, files and certificates shared by the service tests.

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use rand_core::OsRng;
use timescales_core::crypto::Keypair;
use timescales_service::wire::{MessageKind, ReplayGuard, SignedEnvelope};
use timescales_service::{EnvelopeAuth, TlsConfig};

/// A fixed clock for the extractor.
pub(crate) const NOW: u64 = 1_700_000_000_000;
pub(crate) const SKEW: u64 = 30_000;

pub(crate) fn key(seed: u8) -> Keypair {
    Keypair::from_seed([seed; 32])
}

/// The receiving service (a KRC member, say).
pub(crate) fn member() -> Keypair {
    key(1)
}

/// A sender allowed to deliver shares and query announcements.
pub(crate) fn dealer() -> Keypair {
    key(2)
}

pub(crate) fn auth(capacity: usize) -> EnvelopeAuth {
    let dealer = dealer().public();
    EnvelopeAuth {
        me: member().public(),
        allowed: Arc::new(move |sender: &[u8; 32], kind: MessageKind| {
            *sender == dealer
                && matches!(
                    kind,
                    MessageKind::ShareDelivery | MessageKind::AnnouncementQuery
                )
        }),
        replay: Arc::new(ReplayGuard::new(capacity, 2 * SKEW)),
        skew_ms: SKEW,
        now_ms: Arc::new(|| NOW),
    }
}

pub(crate) fn seal(
    kind: MessageKind,
    signer: &Keypair,
    audience: [u8; 32],
    issued_at_ms: u64,
    body: Vec<u8>,
) -> SignedEnvelope {
    SignedEnvelope::seal(kind, signer, audience, issued_at_ms, &mut OsRng, body)
}

/// Writes `contents` with `mode`.
pub(crate) fn write_file(dir: &Path, name: &str, contents: &[u8], mode: u32) -> PathBuf {
    let path = dir.join(name);
    std::fs::write(&path, contents).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
    path
}

/// A self-signed certificate and its key, written as PEM files.
pub(crate) struct Identity {
    pub(crate) cert_file: PathBuf,
    pub(crate) key_file: PathBuf,
    pub(crate) pin: [u8; 32],
}

impl Identity {
    pub(crate) fn tls(&self, peers: &[&Identity]) -> TlsConfig {
        TlsConfig {
            cert_file: self.cert_file.clone(),
            key_file: self.key_file.clone(),
            peer_spki_sha256: peers.iter().map(|p| p.pin).collect(),
        }
    }
}

pub(crate) fn identity(dir: &Path, name: &str) -> Identity {
    identity_valid(dir, name, (2020, 1, 1), (4000, 1, 1))
}

/// An identity valid from `not_before` to `not_after` (year, month, day).
pub(crate) fn identity_valid(
    dir: &Path,
    name: &str,
    not_before: (i32, u8, u8),
    not_after: (i32, u8, u8),
) -> Identity {
    let key = rcgen::KeyPair::generate().unwrap();
    let mut params = rcgen::CertificateParams::new(vec![format!("{name}.invalid")]).unwrap();
    params.not_before = rcgen::date_time_ymd(not_before.0, not_before.1, not_before.2);
    params.not_after = rcgen::date_time_ymd(not_after.0, not_after.1, not_after.2);
    let cert = params.self_signed(&key).unwrap();
    Identity {
        cert_file: write_file(dir, &format!("{name}.crt"), cert.pem().as_bytes(), 0o644),
        key_file: write_file(
            dir,
            &format!("{name}.key"),
            key.serialize_pem().as_bytes(),
            0o600,
        ),
        pin: timescales_service::tls::spki_sha256(cert.der()).unwrap(),
    }
}
