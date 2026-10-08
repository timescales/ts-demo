//! `timescales check-envelopes`: the Rust half of the cross-language check.
//! The TypeScript SDK seals random intents with
//! `ts/packages/sdk/scripts/crosscheck.ts`. This opens every envelope with
//! the executor's code path and compares the decrypted intent with the
//! bytes the SDK recorded beside it.
//!
//! File layout (all integers little-endian):
//!
//! ```text
//! "TSXCHK" || version u8 (1) || key-schedule seed32 || market u64 || epoch u64
//! || count u32 || count x (envelope289 || intent_len u16 || PrivateIntent)
//! ```

use std::path::Path;

use anyhow::{Context, Result, bail};
use serde_json::json;
use timescales_core::intent::{ENVELOPE_LEN, IntentBody, PrivateIntent, SealedEnvelope};
use timescales_core::{CommitmentScheme, Decode, Encode, EpochId, MarketId, Reader};
use timescales_executor::{KeyProvider, LocalKeySchedule};

const MAGIC: &[u8; 6] = b"TSXCHK";
const VERSION: u8 = 1;
/// The script refuses more. A larger count is a corrupt header.
const MAX_COUNT: u32 = 1_000_000;

/// The file, parsed but not yet checked.
#[derive(Debug)]
pub(crate) struct CrosscheckFile {
    pub seed: [u8; 32],
    pub market: MarketId,
    pub epoch: EpochId,
    pub records: Vec<(Vec<u8>, Vec<u8>)>,
}

pub(crate) fn parse(bytes: &[u8]) -> Result<CrosscheckFile> {
    let mut r = Reader::new(bytes);
    if r.take(MAGIC.len())? != MAGIC {
        bail!("not a crosscheck file (magic)");
    }
    let version = r.u8()?;
    if version != VERSION {
        bail!("crosscheck file version {version}, expected {VERSION}");
    }
    let seed: [u8; 32] = r.array()?;
    let market = MarketId(r.u64()?);
    let epoch = EpochId(r.u64()?);
    let count = r.u32()?;
    if count > MAX_COUNT {
        bail!("crosscheck file claims {count} records");
    }
    let mut records = Vec::new();
    for i in 0..count {
        let envelope = r
            .take(ENVELOPE_LEN)
            .with_context(|| format!("record {i}: envelope"))?
            .to_vec();
        let len: [u8; 2] = r.array().with_context(|| format!("record {i}: length"))?;
        let intent = r
            .take(usize::from(u16::from_le_bytes(len)))
            .with_context(|| format!("record {i}: intent"))?
            .to_vec();
        records.push((envelope, intent));
    }
    if r.remaining() != 0 {
        bail!("{} trailing bytes after {count} records", r.remaining());
    }
    Ok(CrosscheckFile {
        seed,
        market,
        epoch,
        records,
    })
}

/// Per-kind counts of the records that opened and matched.
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct Tally {
    pub place: usize,
    pub cancel: usize,
    pub noop: usize,
}

/// Opens every record. Returns the tally, or every record that failed.
pub(crate) fn check(file: &CrosscheckFile) -> Result<Tally, Vec<String>> {
    let keys = LocalKeySchedule::new(file.seed);
    let secret = match keys.epoch_key(file.market, file.epoch) {
        Ok(s) => s,
        Err(e) => return Err(vec![format!("epoch key: {e}")]),
    };
    let mut tally = Tally::default();
    let mut failures = Vec::new();
    for (i, (envelope, recorded)) in file.records.iter().enumerate() {
        let result = (|| -> Result<IntentBody> {
            let env = SealedEnvelope::decode_exact(envelope).context("envelope encoding")?;
            if env.market != file.market || env.epoch != file.epoch {
                bail!(
                    "envelope is for market {} epoch {}",
                    env.market.0,
                    env.epoch.0
                );
            }
            let opened = env
                .open_with(&secret, CommitmentScheme::Sha256)
                .context("open")?;
            let expected =
                PrivateIntent::decode_exact(recorded).context("recorded intent encoding")?;
            if opened.to_bytes() != recorded.as_slice() || opened != expected {
                bail!("decrypted intent differs from the recorded one");
            }
            Ok(opened.body)
        })();
        match result {
            Ok(IntentBody::Place(_)) => tally.place += 1,
            Ok(IntentBody::Cancel(_)) => tally.cancel += 1,
            Ok(IntentBody::Noop) => tally.noop += 1,
            Err(e) => failures.push(format!("record {i}: {e:#}")),
        }
    }
    if failures.is_empty() {
        Ok(tally)
    } else {
        Err(failures)
    }
}

pub(crate) fn run(input: &Path) -> Result<()> {
    let bytes = std::fs::read(input).with_context(|| format!("read {}", input.display()))?;
    let file = parse(&bytes)?;
    match check(&file) {
        Ok(t) => {
            println!(
                "{}",
                json!({
                    "ok": true,
                    "market": file.market.0,
                    "epoch": file.epoch.0,
                    "envelopes": file.records.len(),
                    "place": t.place,
                    "cancel": t.cancel,
                    "noop": t.noop,
                })
            );
            Ok(())
        }
        Err(failures) => {
            for f in failures.iter().take(20) {
                eprintln!("{f}");
            }
            bail!(
                "{} of {} envelopes failed the crosscheck",
                failures.len(),
                file.records.len()
            )
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use rand::SeedableRng;
    use timescales_core::identity::TraderKey;
    use timescales_core::intent::Cancel;
    use timescales_core::{Lots, Order, OrderKind, Role, Side, Tick};

    use super::*;

    /// A file as the SDK script writes it, sealed here with the Rust code.
    fn file(count: usize) -> Vec<u8> {
        let seed = [9u8; 32];
        let (market, epoch) = (MarketId(1), EpochId(1));
        let keys = LocalKeySchedule::new(seed);
        let pk = keys.epoch_public(market, epoch).unwrap();
        let mut rng = rand_chacha::ChaCha20Rng::seed_from_u64(5);
        let trader = TraderKey::from_seed([4; 32]);
        let mut out = MAGIC.to_vec();
        out.push(VERSION);
        out.extend_from_slice(&seed);
        out.extend_from_slice(&market.0.to_le_bytes());
        out.extend_from_slice(&epoch.0.to_le_bytes());
        out.extend_from_slice(&u32::try_from(count).unwrap().to_le_bytes());
        for i in 0..count {
            let (intent, c) = match i % 3 {
                0 => PrivateIntent::place(
                    &mut rng,
                    &trader,
                    CommitmentScheme::Sha256,
                    Order {
                        market,
                        trader: trader.id(),
                        nonce: i as u64,
                        side: Side::Buy,
                        role: Role::Maker,
                        kind: OrderKind::Limit,
                        limit: Tick(100),
                        quantity: Lots(5),
                        valid_from: epoch,
                        expires_at: epoch,
                    },
                )
                .unwrap(),
                1 => PrivateIntent::cancel(
                    &mut rng,
                    &trader,
                    CommitmentScheme::Sha256,
                    Cancel {
                        market,
                        trader: trader.id(),
                        nonce: i as u64,
                        target: timescales_core::OrderCommitment([7; 32]),
                        epoch,
                    },
                )
                .unwrap(),
                _ => PrivateIntent::noop(&mut rng, CommitmentScheme::Sha256).unwrap(),
            };
            let env = SealedEnvelope::seal(&mut rng, market, epoch, &pk, c, &intent).unwrap();
            out.extend_from_slice(&env.to_bytes());
            let plain = intent.to_bytes();
            out.extend_from_slice(&u16::try_from(plain.len()).unwrap().to_le_bytes());
            out.extend_from_slice(&plain);
        }
        out
    }

    #[test]
    fn opens_rust_sealed_records() {
        let parsed = parse(&file(6)).unwrap();
        assert_eq!(
            check(&parsed).unwrap(),
            Tally {
                place: 2,
                cancel: 2,
                noop: 2
            }
        );
    }

    #[test]
    fn reports_a_tampered_envelope_and_a_wrong_recorded_intent() {
        let mut parsed = parse(&file(3)).unwrap();
        parsed.records[0].0[ENVELOPE_LEN - 1] ^= 1;
        let last = parsed.records[2].1.len() - 1;
        parsed.records[2].1[last] ^= 1;
        let failures = check(&parsed).unwrap_err();
        assert_eq!(failures.len(), 2, "{failures:?}");
        assert!(failures[0].starts_with("record 0: open"), "{failures:?}");
        assert!(failures[1].starts_with("record 2:"), "{failures:?}");
    }

    #[test]
    fn refuses_malformed_files() {
        let good = file(1);
        let mut magic = good.clone();
        magic[0] = b'X';
        assert!(parse(&magic).is_err());
        let mut version = good.clone();
        version[6] = 2;
        assert!(parse(&version).is_err());
        let mut trailing = good.clone();
        trailing.push(0);
        assert!(parse(&trailing).is_err());
        assert!(parse(&good[..good.len() - 1]).is_err());
    }
}
