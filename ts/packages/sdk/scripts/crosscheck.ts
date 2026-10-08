// Seals random intents to a development epoch key with the built SDK, for
// `timescales check-envelopes` to open in Rust (crosscheck).
//
//   npm run --prefix ts -w @timescales/sdk build
//   node ts/packages/sdk/scripts/crosscheck.ts --count 1000 --out target/crosscheck.bin
//
// Output (all integers little-endian):
//   "TSXCHK" || version u8 (1) || key-schedule seed32 || market u64 || epoch u64 || count u32
//   || count x (envelope289 || intent_len u16 || PrivateIntent[intent_len])
// The epoch secret is the simulation-only LocalKeySchedule key of
// (seed, market, epoch). The reader opens every envelope with it, checks the
// commitment and the intent signature, and compares the plaintext with the
// PrivateIntent bytes recorded beside it.
import { mkdirSync, writeFileSync } from 'node:fs';
import { dirname } from 'node:path';
import { parseArgs } from 'node:util';
import {
  commitment,
  concat,
  ed25519PublicKey,
  ed25519Sign,
  encodePrivateIntent,
  equal,
  hex,
  intentMessage,
  openEnvelope,
  randomBytes,
  randomU64,
  sealEnvelope,
  u32le,
  u64le,
  type IntentBody,
  type PrivateIntent,
} from '@timescales/sdk/core';
import { devEpochKey } from '@timescales/sdk/testing';

const MAGIC = new TextEncoder().encode('TSXCHK');
const VERSION = 1;

const { values } = parseArgs({
  options: {
    count: { type: 'string', default: '1000' },
    out: { type: 'string', default: 'target/crosscheck.bin' },
    seed: { type: 'string' },
    market: { type: 'string', default: '1' },
    epoch: { type: 'string', default: '1' },
    'self-check': { type: 'boolean', default: false },
    help: { type: 'boolean', default: false },
  },
});

if (values.help) {
  console.log(
    'usage: crosscheck.ts [--count N] [--out FILE] [--seed HEX32] [--market N] [--epoch N] [--self-check]',
  );
  process.exit(0);
}

const count = Number(values.count);
if (!Number.isInteger(count) || count < 1 || count > 1_000_000) {
  throw new RangeError('--count must be an integer in 1..=1000000');
}
const market = BigInt(values.market);
const epoch = BigInt(values.epoch);
const seed = values.seed === undefined ? randomBytes(32) : hex.decode(values.seed, 32);
const key = devEpochKey(seed, market, epoch);

function pick<T>(xs: readonly T[]): T {
  return xs[randomBytes(1)[0]! % xs.length]!;
}

/** A random intent: limit and market Places, Cancels and the odd Noop, each Place or Cancel signed by a fresh trader key. */
function randomIntent(): PrivateIntent {
  const salt = randomBytes(32);
  const roll = randomBytes(1)[0]!;
  if (roll < 8) return { body: { kind: 'noop' }, salt, signature: new Uint8Array(64) };
  const traderSeed = randomBytes(32);
  const trader = ed25519PublicKey(traderSeed);
  let body: IntentBody;
  if (roll < 64) {
    body = {
      kind: 'cancel',
      cancel: { market, trader, nonce: randomU64(), target: randomBytes(32), epoch },
    };
  } else {
    const kind = pick([0, 1] as const);
    const life = BigInt(randomBytes(1)[0]! % 9);
    body = {
      kind: 'place',
      order: {
        market,
        trader,
        nonce: randomU64(),
        side: pick([0, 1] as const),
        role: pick([0, 1] as const),
        kind,
        limit: kind === 1 ? 0n : 1n + (randomU64() % 1_000_000n),
        quantity: 1n + (randomU64() % ((1n << 20n) - 1n)),
        validFrom: epoch,
        expiresAt: epoch + life,
      },
    };
  }
  const signature = ed25519Sign(traderSeed, intentMessage(commitment(body, salt)));
  return { body, salt, signature };
}

const records: Uint8Array[] = [];
let checked = 0;
for (let i = 0; i < count; i++) {
  const intent = randomIntent();
  const c = commitment(intent.body, intent.salt);
  const envelope = sealEnvelope({ epochPk: key.publicKey, market, epoch, commitment: c, intent });
  const plain = encodePrivateIntent(intent);
  if (values['self-check']) {
    const opened = openEnvelope(key.secret, envelope);
    if (!equal(encodePrivateIntent(opened), plain))
      throw new Error(`envelope ${i} did not round-trip`);
    checked++;
  }
  const len = new Uint8Array(2);
  new DataView(len.buffer).setUint16(0, plain.length, true);
  records.push(concat(envelope, len, plain));
}

const out = concat(
  MAGIC,
  Uint8Array.of(VERSION),
  seed,
  u64le(market),
  u64le(epoch),
  u32le(count),
  ...records,
);
mkdirSync(dirname(values.out), { recursive: true });
writeFileSync(values.out, out);
console.log(
  `crosscheck: wrote ${count} envelopes (${out.length} bytes) to ${values.out}` +
    ` for market ${market} epoch ${epoch}, key-schedule seed ${hex.encode(seed)}` +
    (values['self-check'] ? `; ${checked} opened again with the SDK` : ''),
);
