import type { Address } from '@solana/kit';
import { ed25519 } from '@noble/curves/ed25519.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { b58 } from '../core/encoding/base58.js';
import { u64le, utf8 } from '../core/encoding/bytes.js';

// Program-derived addresses are computed here rather than with kit's
// `getProgramDerivedAddress`: only three files may import kit's runtime,
// and the verifiers need the derivation synchronously.

const PDA_MARKER = utf8('ProgramDerivedAddress');
const MAX_SEEDS = 16;
const MAX_SEED_LEN = 32;
const SEED_MARKET = utf8('market');
const SEED_TRADER = utf8('trader');
const SEED_BATCH = utf8('batch');

/**
 * Whether 32 bytes decompress to an Edwards point. ZIP-215 decoding matches
 * curve25519-dalek's `decompress`, the check the runtime uses to refuse
 * on-curve program addresses.
 */
function isOnCurve(b: Uint8Array): boolean {
  try {
    ed25519.Point.fromBytes(b, true);
    return true;
  } catch {
    return false;
  }
}

function checkSeeds(seeds: readonly Uint8Array[]): void {
  if (seeds.length > MAX_SEEDS) throw new RangeError(`at most ${MAX_SEEDS} seeds`);
  for (const s of seeds) {
    if (s.length > MAX_SEED_LEN) throw new RangeError(`seed longer than ${MAX_SEED_LEN} bytes`);
  }
}

/** `create_program_address`: the address for these seeds (the bump included), or null when it lies on the curve. */
export function createProgramAddressSync(
  seeds: readonly Uint8Array[],
  program: Address,
): Address | null {
  checkSeeds(seeds);
  const h = sha256.create();
  for (const s of seeds) h.update(s);
  h.update(b58.decode(program, 32));
  h.update(PDA_MARKER);
  const d = h.digest();
  return isOnCurve(d) ? null : (b58.encode(d) as Address);
}

/** `find_program_address`: the canonical (highest) bump and its address. */
export function findProgramAddressSync(
  seeds: readonly Uint8Array[],
  program: Address,
): readonly [Address, number] {
  checkSeeds([...seeds, new Uint8Array(1)]);
  for (let bump = 255; bump >= 0; bump--) {
    const a = createProgramAddressSync([...seeds, Uint8Array.of(bump)], program);
    if (a !== null) return [a, bump] as const;
  }
  throw new Error('no viable bump seed');
}

export function marketSeeds(marketId: bigint): Uint8Array[] {
  return [SEED_MARKET, u64le(marketId)];
}

export function traderSeeds(market: Address, owner: Address): Uint8Array[] {
  return [SEED_TRADER, b58.decode(market, 32), b58.decode(owner, 32)];
}

export function batchSeeds(market: Address, epoch: bigint): Uint8Array[] {
  return [SEED_BATCH, b58.decode(market, 32), u64le(epoch)];
}

/** `["market", market_id u64 LE]`. */
export function marketPda(program: Address, marketId: bigint): Promise<readonly [Address, number]> {
  return Promise.resolve().then(() => findProgramAddressSync(marketSeeds(marketId), program));
}

/** `["trader", market, owner]`. */
export function traderPda(
  program: Address,
  market: Address,
  owner: Address,
): Promise<readonly [Address, number]> {
  return Promise.resolve().then(() => findProgramAddressSync(traderSeeds(market, owner), program));
}

/** `["batch", market, epoch u64 LE]`. */
export function batchPda(
  program: Address,
  market: Address,
  epoch: bigint,
): Promise<readonly [Address, number]> {
  return Promise.resolve().then(() => findProgramAddressSync(batchSeeds(market, epoch), program));
}
