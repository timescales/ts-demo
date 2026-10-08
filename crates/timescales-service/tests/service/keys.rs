//! Key files: formats and the refusal of files others can read.

use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use timescales_core::crypto::{Keypair, SealSecret};
use timescales_service::{KeyError, keys};

use crate::common::write_file;

const SEED: [u8; 32] = [0x42; 32];

fn solana_json(seed: [u8; 32]) -> String {
    let public = Keypair::from_seed(seed).public();
    let all: Vec<String> = seed
        .iter()
        .chain(public.iter())
        .map(u8::to_string)
        .collect();
    format!("[{}]\n", all.join(","))
}

/// Calls every loader on `path` and reports whether each succeeded.
fn load_all(dir: &Path, mode: u32) -> Vec<(&'static str, Result<(), KeyError>)> {
    let solana = write_file(dir, "relay.json", solana_json(SEED).as_bytes(), mode);
    let seed = write_file(
        dir,
        "service.hex",
        format!("{}\n", hex::encode(SEED)).as_bytes(),
        mode,
    );
    let transport = write_file(
        dir,
        "transport.hex",
        hex::encode([0x24; 32]).as_bytes(),
        mode,
    );
    let kek = write_file(dir, "kek.hex", hex::encode([0x17; 32]).as_bytes(), mode);
    vec![
        (
            "solana_keypair_bytes",
            keys::solana_keypair_bytes(&solana).map(|_| ()),
        ),
        ("ed25519_seed", keys::ed25519_seed(&seed).map(|_| ())),
        ("x25519_secret", keys::x25519_secret(&transport).map(|_| ())),
        ("kek", keys::kek(&kek).map(|_| ())),
    ]
}

#[test]
fn key_file_permissions_enforced() {
    for mode in [0o400, 0o600, 0o700] {
        let dir = tempfile::tempdir().unwrap();
        for (loader, result) in load_all(dir.path(), mode) {
            assert!(result.is_ok(), "{loader} refused mode {mode:o}: {result:?}");
        }
    }
    for mode in [
        0o440, 0o404, 0o640, 0o604, 0o644, 0o620, 0o602, 0o610, 0o601, 0o666,
    ] {
        let dir = tempfile::tempdir().unwrap();
        for (loader, result) in load_all(dir.path(), mode) {
            match result {
                Err(KeyError::Permissions { mode: m, ref path }) => {
                    assert_eq!(m, mode, "{loader}");
                    assert!(path.starts_with(dir.path()));
                }
                other => panic!("{loader} accepted mode {mode:o}: {other:?}"),
            }
        }
    }
    // A symlink is judged by the file it points to.
    let dir = tempfile::tempdir().unwrap();
    let open = write_file(dir.path(), "open.hex", hex::encode(SEED).as_bytes(), 0o644);
    let link = dir.path().join("link.hex");
    std::os::unix::fs::symlink(&open, &link).unwrap();
    assert!(matches!(
        keys::ed25519_seed(&link),
        Err(KeyError::Permissions { .. })
    ));
    std::fs::set_permissions(&open, std::fs::Permissions::from_mode(0o400)).unwrap();
    assert!(keys::ed25519_seed(&link).is_ok());
}

#[test]
fn keys_load_to_the_right_values() {
    let dir = tempfile::tempdir().unwrap();
    let solana = write_file(dir.path(), "k.json", solana_json(SEED).as_bytes(), 0o400);
    let bytes = keys::solana_keypair_bytes(&solana).unwrap();
    assert_eq!(bytes[..32], SEED);
    assert_eq!(bytes[32..], Keypair::from_seed(SEED).public());

    let seed = write_file(
        dir.path(),
        "s.hex",
        format!("  {}\n", hex::encode_upper(SEED)).as_bytes(),
        0o400,
    );
    assert_eq!(
        keys::ed25519_seed(&seed).unwrap().public(),
        Keypair::from_seed(SEED).public()
    );

    let x = write_file(
        dir.path(),
        "x.hex",
        hex::encode([0x24; 32]).as_bytes(),
        0o400,
    );
    assert_eq!(
        keys::x25519_secret(&x).unwrap().public(),
        SealSecret::from_bytes([0x24; 32]).public()
    );

    let k = write_file(
        dir.path(),
        "kek.hex",
        hex::encode([0x17; 32]).as_bytes(),
        0o400,
    );
    let kek = keys::kek(&k).unwrap();
    assert_eq!(kek.as_bytes(), &[0x17; 32]);
    assert_eq!(format!("{kek:?}"), "Kek(..)");
}

#[test]
fn malformed_key_files_are_refused() {
    let dir = tempfile::tempdir().unwrap();
    let format_error = |path: &Path, f: fn(&Path) -> Result<(), KeyError>| match f(path) {
        Err(KeyError::Format { reason, .. }) => reason,
        other => panic!("{}: {other:?}", path.display()),
    };
    let seed = |p: &Path| keys::ed25519_seed(p).map(|_| ());
    let solana = |p: &Path| keys::solana_keypair_bytes(p).map(|_| ());

    for (i, text) in [
        hex::encode([1u8; 31]),
        hex::encode([1u8; 33]),
        format!("{}zz", &hex::encode([1u8; 32])[..62]),
        String::new(),
        format!("0x{}", hex::encode([1u8; 31])),
    ]
    .iter()
    .enumerate()
    {
        let path = write_file(dir.path(), &format!("bad{i}.hex"), text.as_bytes(), 0o600);
        assert_eq!(format_error(&path, seed), "expected 64 hex digits");
    }

    // A keypair whose halves do not belong together.
    let mut mixed: Vec<String> = SEED.iter().map(u8::to_string).collect();
    mixed.extend(
        Keypair::from_seed([0x43; 32])
            .public()
            .iter()
            .map(u8::to_string),
    );
    let path = write_file(
        dir.path(),
        "mixed.json",
        format!("[{}]", mixed.join(",")).as_bytes(),
        0o600,
    );
    assert_eq!(
        format_error(&path, solana),
        "the public half does not match the secret half"
    );
    let path = write_file(
        dir.path(),
        "hex.json",
        hex::encode([1u8; 64]).as_bytes(),
        0o600,
    );
    assert_eq!(
        format_error(&path, solana),
        "expected a JSON array of 64 bytes"
    );

    let big = write_file(dir.path(), "big.hex", &vec![b' '; 5000], 0o600);
    assert_eq!(format_error(&big, seed), "file too large for a key");
    assert_eq!(format_error(dir.path(), seed), "not a regular file");
    assert!(matches!(
        keys::kek(&dir.path().join("missing.hex")),
        Err(KeyError::Io { .. })
    ));
}
