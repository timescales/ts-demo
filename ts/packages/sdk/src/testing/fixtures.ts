import { hkdf } from '@noble/hashes/hkdf.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { concat, u64le, utf8 } from '../core/encoding/bytes.js';
import { x25519PublicKey } from '../core/crypto/x25519.js';
import type { MarketParams } from '../core/protocol/params.js';

/**
 * Market params that pass `validateMarketParams({ onchain: true })`, with
 * overrides (which are not re-validated): single book, lots of 1000 base
 * atoms, ticks of 100 quote atoms, a band of +/-3 ticks, orders up to 2^20 - 1
 * lots and 8 epochs of lifetime, maker 1 bp and taker 5 bp.
 */
export function testMarketParams(overrides?: Partial<MarketParams>): MarketParams {
  return {
    market: 1n,
    baseLotSize: 1000n,
    tickSize: 100n,
    bandHalfWidth: 3,
    maxOrderLotsLog2: 20,
    maxOrdersPerTrader: 16,
    maxBatchEnvelopes: 1024,
    maxOrderLifetime: 8,
    makerFeeBps: 1,
    takerFeeBps: 5,
    flow: 0,
    rationing: 0,
    commitmentScheme: 0,
    ...overrides,
  };
}

const LOCAL_EPOCH_KEY_SALT = utf8('timescales/v1/local-epoch-key');

/**
 * The simulation-only `LocalKeySchedule` epoch key:
 * HKDF-SHA256(salt "timescales/v1/local-epoch-key", seed, market8 || epoch8),
 * as an X25519 secret and its public key. Anyone holding the seed can open
 * every epoch's envelopes.
 */
export function devEpochKey(
  seed: Uint8Array,
  market: bigint,
  epoch: bigint,
): { secret: Uint8Array; publicKey: Uint8Array } {
  if (seed.length !== 32) throw new RangeError('the key-schedule seed must be 32 bytes');
  const secret = hkdf(sha256, seed, LOCAL_EPOCH_KEY_SALT, concat(u64le(market), u64le(epoch)), 32);
  return { secret, publicKey: x25519PublicKey(secret) };
}
