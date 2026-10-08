import { utf8, u64le } from '../encoding/bytes.js';
import { DecodeError, Writer, decodeExact } from '../encoding/codec.js';
import { H } from '../crypto/hash.js';
import { readBand, writeBand, type PriceBand } from './band.js';
import { readMarketParams, writeMarketParams, type MarketParams } from './params.js';

/** Batch header (283 B). Version 2 carries the epoch binding in bytes `[87..119]`. */
export interface BatchHeader {
  version: 1 | 2;
  market: bigint;
  epoch: bigint;
  params: MarketParams;
  band: PriceBand;
  priceCommitmentOrBinding: Uint8Array;
  envelopeCount: number;
  batchRoot: Uint8Array;
  beacon: Uint8Array;
  priorStateRoot: Uint8Array;
  balancesRoot: Uint8Array;
  prevReceipt: Uint8Array;
}

export const HEADER_LEN = 283;

export function decodeHeader(b: Uint8Array): BatchHeader {
  return decodeExact(b, (r) => {
    const version = r.u8();
    if (version !== 1 && version !== 2)
      throw new DecodeError('version', `header version ${version}`);
    const market = r.u64();
    const epoch = r.u64();
    const params = readMarketParams(r);
    if (params.market !== market)
      throw new DecodeError('value', 'header params are for another market');
    return {
      version,
      market,
      epoch,
      params,
      band: readBand(r),
      priceCommitmentOrBinding: r.fixed(32),
      envelopeCount: r.u32(),
      batchRoot: r.fixed(32),
      beacon: r.fixed(32),
      priorStateRoot: r.fixed(32),
      balancesRoot: r.fixed(32),
      prevReceipt: r.fixed(32),
    };
  });
}

export function encodeHeader(h: BatchHeader): Uint8Array {
  if (h.params.market !== h.market) throw new RangeError('header params are for another market');
  const w = new Writer().u8(h.version).u64(h.market).u64(h.epoch);
  writeMarketParams(w, h.params);
  writeBand(w, h.band);
  return w
    .fixed(h.priceCommitmentOrBinding, 32)
    .u32(h.envelopeCount)
    .fixed(h.batchRoot, 32)
    .fixed(h.beacon, 32)
    .fixed(h.priorStateRoot, 32)
    .fixed(h.balancesRoot, 32)
    .fixed(h.prevReceipt, 32)
    .finish();
}

/** `H(BATCH_HEADER, header283)`. */
export function headerDigest(raw: Uint8Array): Uint8Array {
  if (raw.length !== HEADER_LEN) throw new RangeError(`header must be ${HEADER_LEN} bytes`);
  return H('BATCH_HEADER', raw);
}

/** Version 1 priority seed `H(BATCH_SEED, market8 || epoch8 || root || beacon)`. */
export function batchSeed(
  h: Pick<BatchHeader, 'market' | 'epoch' | 'batchRoot' | 'beacon'>,
): Uint8Array {
  return H('BATCH_SEED', u64le(h.market), u64le(h.epoch), h.batchRoot, h.beacon);
}

/** `H(EPOCH_SEED, s32 || market32 || epoch)`. Only holders of the epoch secret `s` can compute it. */
export function epochSeed(secret: Uint8Array, market: Uint8Array, epoch: bigint): Uint8Array {
  if (secret.length !== 32 || market.length !== 32) throw new RangeError('inputs must be 32 bytes');
  return H('EPOCH_SEED', secret, market, u64le(epoch));
}

/** Version 2 priority seed `H(BATCH_SEED, "v2" || market8 || epoch8 || root || beacon || epoch_seed)`. */
export function batchSeedV2(
  h: Pick<BatchHeader, 'market' | 'epoch' | 'batchRoot' | 'beacon'>,
  epochSeedValue: Uint8Array,
): Uint8Array {
  return H(
    'BATCH_SEED',
    utf8('v2'),
    u64le(h.market),
    u64le(h.epoch),
    h.batchRoot,
    h.beacon,
    epochSeedValue,
  );
}

/** `H(PRIORITY_KEY, seed || C)`. Canonical order is ascending key bytes. */
export function priorityKey(seed: Uint8Array, c: Uint8Array): Uint8Array {
  return H('PRIORITY_KEY', seed, c);
}
