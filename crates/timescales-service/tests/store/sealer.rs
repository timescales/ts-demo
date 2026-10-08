//! At-rest sealing: `KekSealer` and the ratcheting `RatchetSealer`.

use std::os::unix::fs::PermissionsExt;

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use hkdf::Hkdf;
use sha2::Sha256;
use timescales_service::store::{KekSealer, RatchetSealer, SecretSealer, StoreError};
use zeroize::Zeroizing;

use crate::common::{KEK_0, file_contains};

fn hex(key: &[u8; 32]) -> String {
    key.iter().map(|b| format!("{b:02x}")).collect()
}

fn next_key(key: &[u8; 32]) -> [u8; 32] {
    let mut out = [0u8; 32];
    Hkdf::<Sha256>::new(None, key)
        .expand(b"timescales/v1/kek-ratchet", &mut out)
        .unwrap();
    out
}

#[test]
fn kek_sealer_round_trips_and_binds_the_aad() {
    let sealer = KekSealer::new(Zeroizing::new([7; 32]));
    let sealed = sealer.seal(b"market|C", b"carried cover intent").unwrap();
    // generation u32 || nonce12 || ciphertext || tag16
    assert_eq!(sealed.len(), 4 + 12 + 20 + 16);
    assert_eq!(sealed[..4], KekSealer::GENERATION.to_le_bytes());
    assert_eq!(
        &*sealer.open(b"market|C", &sealed).unwrap(),
        b"carried cover intent"
    );

    assert_eq!(
        sealer.open(b"market|D", &sealed).unwrap_err(),
        StoreError::Corrupt("sealed value failed authentication")
    );
    let mut tampered = sealed.clone();
    *tampered.last_mut().unwrap() ^= 1;
    assert!(sealer.open(b"market|C", &tampered).is_err());
    assert_eq!(
        sealer.open(b"market|C", &sealed[..20]).unwrap_err(),
        StoreError::Corrupt("sealed value is truncated")
    );
    let other = KekSealer::new(Zeroizing::new([8; 32]));
    assert!(other.open(b"market|C", &sealed).is_err());
}

#[test]
fn nonces_are_fresh() {
    let sealer = KekSealer::new(Zeroizing::new([7; 32]));
    let a = sealer.seal(b"aad", b"same").unwrap();
    let b = sealer.seal(b"aad", b"same").unwrap();
    assert_ne!(a[4..16], b[4..16]);
    assert_ne!(a, b);
}

#[test]
fn a_value_cannot_move_to_another_generation() {
    let dir = tempfile::tempdir().unwrap();
    let ratchet = RatchetSealer::create(&dir.path().join("k"), 0, Zeroizing::new([7; 32])).unwrap();
    let kek = KekSealer::new(Zeroizing::new([7; 32]));
    // Same key, generation 0 in both: interchangeable.
    let sealed = kek.seal(b"aad", b"x").unwrap();
    assert_eq!(&*ratchet.open(b"aad", &sealed).unwrap(), b"x");
    // Relabelling the generation breaks authentication.
    ratchet.advance().unwrap();
    let mut relabelled = ratchet.seal(b"aad", b"x").unwrap();
    assert_eq!(relabelled[..4], 1u32.to_le_bytes());
    relabelled[..4].copy_from_slice(&0u32.to_le_bytes());
    assert!(ratchet.open(b"aad", &relabelled).is_err());
    assert_eq!(
        kek.open(b"aad", &ratchet.seal(b"aad", b"x").unwrap())
            .unwrap_err(),
        StoreError::Corrupt("sealed under another key")
    );
}

#[test]
fn the_ratchet_derives_each_generation_with_hkdf() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("kek.keys");
    let sealer = RatchetSealer::create(&path, 0, Zeroizing::new(KEK_0)).unwrap();
    assert_eq!(sealer.current_generation(), 0);
    assert_eq!(sealer.advance().unwrap(), 1);
    assert_eq!(sealer.advance().unwrap(), 2);
    assert_eq!(sealer.current_generation(), 2);

    let k1 = next_key(&KEK_0);
    let k2 = next_key(&k1);
    let text = std::fs::read_to_string(&path).unwrap();
    assert_eq!(
        text,
        format!(
            "timescales/v1/kek-ratchet\n0 {}\n1 {}\n2 {}\n",
            hex(&KEK_0),
            hex(&k1),
            hex(&k2)
        )
    );
    // A value sealed under generation 2 opens with the independently derived
    // key, its nonce and AAD = aad || generation.
    let sealed = sealer.seal(b"aad", b"share").unwrap();
    assert_eq!(sealed[..4], 2u32.to_le_bytes());
    let plain = ChaCha20Poly1305::new(Key::from_slice(&k2))
        .decrypt(
            Nonce::from_slice(&sealed[4..16]),
            Payload {
                msg: &sealed[16..],
                aad: b"aad\x02\x00\x00\x00",
            },
        )
        .unwrap();
    assert_eq!(plain, b"share");
    let reloaded = RatchetSealer::load(&path).unwrap();
    assert_eq!(reloaded.current_generation(), 2);
    assert_eq!(&*reloaded.open(b"aad", &sealed).unwrap(), b"share");
}

#[test]
fn ratchet_erases_old_generation() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("kek.keys");
    let sealer = RatchetSealer::create(&path, 0, Zeroizing::new(KEK_0)).unwrap();
    let old = sealer.seal(b"e1", b"old share").unwrap();
    sealer.advance().unwrap();
    let new = sealer.seal(b"e2", b"new share").unwrap();
    assert_eq!(&*sealer.open(b"e1", &old).unwrap(), b"old share");

    // The current generation is never erased.
    assert_eq!(
        sealer.erase(1).unwrap_err(),
        StoreError::Conflict("the current key generation cannot be erased")
    );
    sealer.erase(0).unwrap();
    // Erasing again is a no-op.
    sealer.erase(0).unwrap();

    assert_eq!(
        sealer.open(b"e1", &old).unwrap_err(),
        StoreError::Corrupt("sealed under an erased key generation")
    );
    assert_eq!(&*sealer.open(b"e2", &new).unwrap(), b"new share");
    // Gone from the key file too: a later copy of the disk cannot open it.
    assert!(!file_contains(&path, hex(&KEK_0).as_bytes()));
    assert!(!dir.path().join("kek.keys.tmp").exists());
    let reloaded = RatchetSealer::load(&path).unwrap();
    assert!(reloaded.open(b"e1", &old).is_err());
    assert_eq!(&*reloaded.open(b"e2", &new).unwrap(), b"new share");
    // And the erased key cannot be derived back from what is left.
    assert_eq!(
        std::fs::read_to_string(&path).unwrap(),
        format!("timescales/v1/kek-ratchet\n1 {}\n", hex(&next_key(&KEK_0)))
    );
}

#[test]
fn the_key_file_is_private_and_its_permissions_are_checked() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("kek.keys");
    let sealer = RatchetSealer::create(&path, 5, Zeroizing::new(KEK_0)).unwrap();
    let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600);
    sealer.advance().unwrap();
    let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600, "a rewrite keeps the file private");

    for loose in [0o640, 0o604, 0o644] {
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(loose)).unwrap();
        assert_eq!(
            RatchetSealer::load(&path).unwrap_err(),
            StoreError::Conflict("at-rest key file is accessible by group or others")
        );
    }
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o400)).unwrap();
    assert_eq!(RatchetSealer::load(&path).unwrap().current_generation(), 6);
    assert_eq!(
        RatchetSealer::create(&path, 0, Zeroizing::new(KEK_0)).unwrap_err(),
        StoreError::Conflict("at-rest key file already exists")
    );
}

#[test]
fn malformed_key_files_are_refused() {
    let dir = tempfile::tempdir().unwrap();
    let good = hex(&KEK_0);
    let cases = [
        String::new(),
        "timescales/v1/kek-ratchet\n".to_owned(),
        format!("wrong header\n0 {good}\n"),
        format!("timescales/v1/kek-ratchet\n0 {}\n", &good[..62]),
        format!("timescales/v1/kek-ratchet\n0 {}zz\n", &good[..62]),
        format!("timescales/v1/kek-ratchet\nx {good}\n"),
        format!("timescales/v1/kek-ratchet\n1 {good}\n0 {good}\n"),
        format!("timescales/v1/kek-ratchet\n1 {good}\n1 {good}\n"),
        format!("timescales/v1/kek-ratchet\n0{good}\n"),
    ];
    for (i, text) in cases.iter().enumerate() {
        let path = dir.path().join(format!("k{i}"));
        std::fs::write(&path, text).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(
            RatchetSealer::load(&path).unwrap_err(),
            StoreError::Corrupt("at-rest key file is malformed"),
            "case {i}: {text:?}"
        );
    }
    let missing = RatchetSealer::load(&dir.path().join("missing")).unwrap_err();
    assert!(
        matches!(missing, StoreError::Sqlite(ref m) if m.contains("opening")),
        "{missing:?}"
    );
    let big = dir.path().join("big");
    std::fs::write(&big, vec![b'a'; 70_000]).unwrap();
    std::fs::set_permissions(&big, std::fs::Permissions::from_mode(0o600)).unwrap();
    assert_eq!(
        RatchetSealer::load(&big).unwrap_err(),
        StoreError::Corrupt("at-rest key file is too large")
    );
}

#[test]
fn debug_output_names_no_key() {
    let dir = tempfile::tempdir().unwrap();
    let ratchet = RatchetSealer::create(&dir.path().join("k"), 0, Zeroizing::new(KEK_0)).unwrap();
    let kek = KekSealer::new(Zeroizing::new(KEK_0));
    for text in [format!("{ratchet:?}"), format!("{kek:?}")] {
        assert!(!text.contains(&hex(&KEK_0)), "{text}");
        assert!(!text.contains("23, 23"), "{text}");
    }
}
