import type { Address } from '@solana/kit';
import { b58 } from '../core/encoding/base58.js';
import { isZero } from '../core/encoding/bytes.js';
import { DecodeError, Reader, decodeExact } from '../core/encoding/codec.js';
import { decodeMarketParams, type MarketParams } from '../core/protocol/params.js';

export type PendingChange = { etaSlot: bigint; due: boolean } & (
  | { kind: 'set_relay'; relay: Address }
  | { kind: 'set_executors'; executors: Address[]; quorum: number; quorumDecrease: boolean }
  | { kind: 'set_committee_digest'; digest: Uint8Array }
  | { kind: 'set_admin'; admin: Address }
  | {
      kind: 'set_timings';
      beaconDelaySlots: number;
      execTimeoutSlots: bigint;
      settleTimeoutSlots: bigint;
    }
  | { kind: 'set_timelock'; slots: bigint; decrease: boolean }
);

/** The v2 Market account. */
export interface MarketAccount {
  address: Address;
  marketId: bigint;
  salt: Uint8Array;
  creator: Address;
  admin: Address;
  pendingAdmin: Address | null;
  relay: Address;
  baseMint: Address;
  quoteMint: Address;
  baseVault: Address;
  quoteVault: Address;
  params: MarketParams;
  paramsDigest: Uint8Array;
  committeeDigest: Uint8Array;
  prevCommitteeDigest: Uint8Array | null;
  /** 8 stable slots. A removed executor leaves its slot empty. */
  executors: (Address | null)[];
  receiptQuorum: number;
  halted: boolean;
  beaconDelaySlots: number;
  timelockSlots: bigint;
  execTimeoutSlots: bigint;
  settleTimeoutSlots: bigint;
  lastCommitted: bigint;
  lastSettled: bigint;
  lastProgressSlot: bigint;
  feesAccrued: bigint;
  feesClaimed: bigint;
  prevReceipt: Uint8Array;
  stateRoot: Uint8Array;
  /**
   * The timelocked change, if any. `due` needs the current slot, which the
   * account bytes do not carry: {@link decodeMarketAccount} leaves it false
   * and `TimescalesRpc.market` sets it from the slot it read at.
   */
  pending: PendingChange | null;
}

export interface TraderAccount {
  address: Address;
  market: Address;
  owner: Address;
  base: bigint;
  quote: bigint;
  requestedBase: bigint;
  requestedQuote: bigint;
  requestEpoch: bigint;
  lastLeafEpoch: bigint;
  lastChangeSlot: bigint;
  floorEpoch: bigint;
  floorBase: bigint;
  floorQuote: bigint;
}

export type BatchStatus =
  'committed' | 'beacon_revealed' | 'receipt_posted' | 'verified' | 'settled' | 'aborted';

export type AbortReason =
  | 'admin'
  | 'relay'
  | 'beacon_expired'
  | 'exec_timeout'
  | 'settle_timeout'
  | 'quorum_timeout'
  | 'unknown';

export interface BatchAccount {
  address: Address;
  status: BatchStatus;
  abortReason: AbortReason | null;
  cosignBitmap: number;
  cosignCount: number;
  market: Address;
  epoch: bigint;
  root: Uint8Array;
  count: number;
  termsDigest: Uint8Array;
  commitSlot: bigint;
  beaconSlots: [bigint, bigint] | null;
  beacon: Uint8Array | null;
  revealSlot: bigint | null;
  receiptSlot: bigint | null;
  headerDigest: Uint8Array | null;
  receipt: Uint8Array | null;
  outcomeDigest: Uint8Array | null;
  nextStateRoot: Uint8Array | null;
  settlementRoot: Uint8Array | null;
  settlementCount: number;
  fees: bigint;
  verifiedCount: number;
  appliedCount: number;
}

/** A value read from an RPC, with the slot and commitment it was read at. */
export interface Observed<T> {
  value: T;
  contextSlot: bigint;
  commitment: 'confirmed' | 'finalized';
}

export const MARKET_TAG = 0x21;
export const TRADER_TAG = 0x22;
export const BATCH_TAG = 0x23;
export const LAYOUT_VERSION = 2;
export const MARKET_LEN = 1103;
export const TRADER_LEN = 148;
export const BATCH_LEN = 688;
export const MINT_LEN = 82;
export const MAX_EXECUTORS = 8;
const MAX_PAYLOAD = 262;

const BATCH_STATUS: readonly BatchStatus[] = [
  'committed',
  'beacon_revealed',
  'receipt_posted',
  'verified',
  'settled',
  'aborted',
];
const ABORT_REASONS: readonly AbortReason[] = [
  'admin',
  'relay',
  'beacon_expired',
  'exec_timeout',
  'settle_timeout',
  'quorum_timeout',
];

function key(r: Reader): Address {
  return b58.encode(r.fixed(32)) as Address;
}

function optionalKey(r: Reader): Address | null {
  const k = r.fixed(32);
  return isZero(k) ? null : (b58.encode(k) as Address);
}

function optionalHash(b: Uint8Array): Uint8Array | null {
  return isZero(b) ? null : b;
}

/** Exact length, tag and layout version, as the program's loaders require. */
function header(d: Uint8Array, len: number, tag: number, what: string): Reader {
  if (d.length !== len) throw new DecodeError('length', `${what} account must be ${len} bytes`);
  if (d[0] !== tag) throw new DecodeError('tag', `${what} account tag ${d[0]}`);
  if (d[2] !== LAYOUT_VERSION) throw new DecodeError('version', `${what} layout ${d[2]}`);
  return new Reader(d);
}

/** Governance change kinds in their on-chain numbering. */
export const GOVERNANCE_KINDS = [
  'set_relay',
  'set_executors',
  'set_committee_digest',
  'set_admin',
  'set_timings',
  'set_timelock',
] as const;

/**
 * The governance payload for `kind`, decoded strictly. `quorumDecrease`
 * and `decrease` compare with the market's current values (V-13 warnings).
 */
export function decodePending(
  kind: number,
  etaSlot: bigint,
  payload: Uint8Array,
  current: { receiptQuorum: number; timelockSlots: bigint },
): PendingChange {
  return decodeExact(payload, (r): PendingChange => {
    switch (kind) {
      case 1:
        return { kind: 'set_relay', etaSlot, due: false, relay: key(r) };
      case 2: {
        // `n u8 || key32 x n || quorum u8`
        const n = r.u8();
        if (n > MAX_EXECUTORS) throw new DecodeError('length', `${n} executors`);
        const executors: Address[] = [];
        for (let i = 0; i < n; i++) executors.push(key(r));
        const quorum = r.u8();
        if (executors.length === 0 || quorum === 0 || quorum > executors.length) {
          throw new DecodeError('value', 'executor set');
        }
        return {
          kind: 'set_executors',
          etaSlot,
          due: false,
          executors,
          quorum,
          quorumDecrease: quorum < current.receiptQuorum,
        };
      }
      case 3:
        return { kind: 'set_committee_digest', etaSlot, due: false, digest: r.fixed(32) };
      case 4:
        return { kind: 'set_admin', etaSlot, due: false, admin: key(r) };
      case 5:
        return {
          kind: 'set_timings',
          etaSlot,
          due: false,
          beaconDelaySlots: r.u16(),
          execTimeoutSlots: r.u64(),
          settleTimeoutSlots: r.u64(),
        };
      case 6: {
        const slots = r.u64();
        return {
          kind: 'set_timelock',
          etaSlot,
          due: false,
          slots,
          decrease: slots < current.timelockSlots,
        };
      }
      default:
        throw new DecodeError('tag', `governance kind ${kind}`);
    }
  });
}

/** Decodes a v2 Market account: 1103 bytes, tag 0x21, layout 2. */
export function decodeMarketAccount(address: Address, d: Uint8Array): MarketAccount {
  const r = header(d, MARKET_LEN, MARKET_TAG, 'Market');
  r.fixed(3);
  const flags = r.u8();
  const marketId = r.u64();
  const creator = key(r);
  const admin = key(r);
  const pendingAdmin = optionalKey(r);
  const relay = key(r);
  const baseMint = key(r);
  const quoteMint = key(r);
  const baseVault = key(r);
  const quoteVault = key(r);
  const params = decodeMarketParams(r.fixed(46));
  const paramsDigest = r.fixed(32);
  const committeeDigest = r.fixed(32);
  r.u8(); // executor_count: derived from the slots
  const receiptQuorum = r.u8();
  const executors: (Address | null)[] = [];
  for (let i = 0; i < MAX_EXECUTORS; i++) executors.push(optionalKey(r));
  const beaconDelaySlots = r.u16();
  const timelockSlots = r.u64();
  const execTimeoutSlots = r.u64();
  const settleTimeoutSlots = r.u64();
  const lastCommitted = r.u64();
  const lastSettled = r.u64();
  const lastProgressSlot = r.u64();
  const feesAccrued = r.u64();
  const feesClaimed = r.u64();
  const prevReceipt = r.fixed(32);
  const stateRoot = r.fixed(32);
  const pendingKind = r.u8();
  const pendingEta = r.u64();
  const pendingLen = r.u16();
  const pendingPayload = r.fixed(MAX_PAYLOAD);
  const salt = r.fixed(32);
  const prevCommitteeDigest = optionalHash(r.fixed(32));
  r.finish();
  if (pendingLen > MAX_PAYLOAD) throw new DecodeError('length', 'pending payload length');
  let pending: PendingChange | null = null;
  if (pendingKind !== 0) {
    pending = decodePending(pendingKind, pendingEta, pendingPayload.subarray(0, pendingLen), {
      receiptQuorum,
      timelockSlots,
    });
  }
  return {
    address,
    marketId,
    salt,
    creator,
    admin,
    pendingAdmin,
    relay,
    baseMint,
    quoteMint,
    baseVault,
    quoteVault,
    params,
    paramsDigest,
    committeeDigest,
    prevCommitteeDigest,
    executors,
    receiptQuorum,
    halted: (flags & 1) === 1,
    beaconDelaySlots,
    timelockSlots,
    execTimeoutSlots,
    settleTimeoutSlots,
    lastCommitted,
    lastSettled,
    lastProgressSlot,
    feesAccrued,
    feesClaimed,
    prevReceipt,
    stateRoot,
    pending,
  };
}

/** Decodes a v2 Trader account: 148 bytes, tag 0x22, layout 2. */
export function decodeTraderAccount(address: Address, d: Uint8Array): TraderAccount {
  const r = header(d, TRADER_LEN, TRADER_TAG, 'Trader');
  r.fixed(4);
  const t: TraderAccount = {
    address,
    market: key(r),
    owner: key(r),
    base: r.u64(),
    quote: r.u64(),
    requestedBase: r.u64(),
    requestedQuote: r.u64(),
    requestEpoch: r.u64(),
    lastLeafEpoch: r.u64(),
    lastChangeSlot: r.u64(),
    floorEpoch: r.u64(),
    floorBase: r.u64(),
    floorQuote: r.u64(),
  };
  r.finish();
  return t;
}

/**
 * Decodes a v2 Batch account: 688 bytes, tag 0x23, layout 2. Fields a
 * batch has not reached yet are zero on chain and decode as null.
 */
export function decodeBatchAccount(address: Address, d: Uint8Array): BatchAccount {
  const r = header(d, BATCH_LEN, BATCH_TAG, 'Batch');
  r.fixed(3);
  const statusByte = r.u8();
  const status = BATCH_STATUS[statusByte - 1];
  if (status === undefined) throw new DecodeError('tag', `batch status ${statusByte}`);
  const reasonByte = r.u8();
  const cosignCount = r.u8();
  const cosignBitmap = r.u8();
  r.u8();
  const market = key(r);
  const epoch = r.u64();
  const root = r.fixed(32);
  const count = r.u32();
  const termsDigest = r.fixed(32);
  const commitSlot = r.u64();
  const slotA = r.u64();
  const slotB = r.u64();
  const beacon = optionalHash(r.fixed(32));
  const revealSlot = r.u64();
  const receiptSlot = r.u64();
  const headerDigest = optionalHash(r.fixed(32));
  const receipt = optionalHash(r.fixed(32));
  const outcomeDigest = optionalHash(r.fixed(32));
  const nextStateRoot = optionalHash(r.fixed(32));
  const settlementRoot = optionalHash(r.fixed(32));
  const settlementCount = r.u32();
  const fees = r.u64();
  const verifiedCount = r.u32();
  const appliedCount = r.u32();
  // sum_base, sum_quote (i128), the verified and applied bitmaps and the
  // reserved tail are bookkeeping for the program.
  r.fixed(32 + 128 + 128 + 32);
  r.finish();
  let abortReason: AbortReason | null = null;
  if (reasonByte !== 0) abortReason = ABORT_REASONS[reasonByte - 1] ?? 'unknown';
  return {
    address,
    status,
    abortReason,
    cosignBitmap,
    cosignCount,
    market,
    epoch,
    root,
    count,
    termsDigest,
    commitSlot,
    beaconSlots: slotA === 0n && slotB === 0n ? null : [slotA, slotB],
    beacon,
    revealSlot: revealSlot === 0n ? null : revealSlot,
    receiptSlot: receiptSlot === 0n ? null : receiptSlot,
    headerDigest,
    receipt,
    outcomeDigest,
    nextStateRoot,
    settlementRoot,
    settlementCount,
    fees,
    verifiedCount,
    appliedCount,
  };
}

function cOptionKey(r: Reader, what: string): Address | null {
  const tag = r.u32();
  const k = r.fixed(32);
  if (tag > 1) throw new DecodeError('tag', `${what} COption tag ${tag}`);
  return tag === 1 ? (b58.encode(k) as Address) : null;
}

/** Decodes a classic SPL Token mint (82 bytes). Token-2022 is out of scope. */
export function decodeMint(d: Uint8Array): {
  decimals: number;
  mintAuthority: Address | null;
  freezeAuthority: Address | null;
} {
  return decodeExact(d, (r) => {
    const mintAuthority = cOptionKey(r, 'mint authority');
    r.u64(); // supply
    const decimals = r.u8();
    if (!r.bool()) throw new DecodeError('value', 'mint is not initialized');
    const freezeAuthority = cOptionKey(r, 'freeze authority');
    return { decimals, mintAuthority, freezeAuthority };
  });
}

/** Per side, the part of the balance batch `epoch` may not use: `epoch > request_epoch ? min(requested, balance): 0`. */
export function reservedFor(t: TraderAccount, epoch: bigint): { base: bigint; quote: bigint } {
  if (epoch <= t.requestEpoch) return { base: 0n, quote: 0n };
  const min = (a: bigint, b: bigint): bigint => (a < b ? a : b);
  return { base: min(t.requestedBase, t.base), quote: min(t.requestedQuote, t.quote) };
}

/**: balance minus a pending withdrawal's reservation. */
export function availableFor(t: TraderAccount, epoch: bigint): { base: bigint; quote: bigint } {
  const r = reservedFor(t, epoch);
  return { base: t.base - r.base, quote: t.quote - r.quote };
}

/**
 * A pending request unlocks once the batch in flight at request time is
 * terminal (`last_settled >= request_epoch`) and pays `min(requested, balance)`
 * per side.
 */
export function withdrawStatus(
  m: MarketAccount,
  t: TraderAccount,
): {
  withdrawable: boolean;
  reason: 'unlocked' | 'locked' | 'none';
  unlocksAfterEpoch: bigint;
  payoutUpTo: { base: bigint; quote: bigint };
} {
  if (t.requestedBase === 0n && t.requestedQuote === 0n) {
    return {
      withdrawable: false,
      reason: 'none',
      unlocksAfterEpoch: t.requestEpoch,
      payoutUpTo: { base: 0n, quote: 0n },
    };
  }
  const min = (a: bigint, b: bigint): bigint => (a < b ? a : b);
  const unlocked = m.lastSettled >= t.requestEpoch;
  return {
    withdrawable: unlocked,
    reason: unlocked ? 'unlocked' : 'locked',
    unlocksAfterEpoch: t.requestEpoch,
    payoutUpTo: { base: min(t.requestedBase, t.base), quote: min(t.requestedQuote, t.quote) },
  };
}

/**
 * `CloseTrader` needs zero balances and requests, and no leaf of the batch in
 * flight (`last_committed == last_settled` or `last_leaf_epoch != last_committed`).
 */
export function closeStatus(
  m: MarketAccount,
  t: TraderAccount,
): {
  closable: boolean;
  reason: 'ok' | 'not_empty' | 'leaf_in_flight';
  availableAfterEpoch?: bigint;
} {
  if (t.base !== 0n || t.quote !== 0n || t.requestedBase !== 0n || t.requestedQuote !== 0n) {
    return { closable: false, reason: 'not_empty' };
  }
  if (m.lastCommitted !== m.lastSettled && t.lastLeafEpoch === m.lastCommitted) {
    return { closable: false, reason: 'leaf_in_flight', availableAfterEpoch: m.lastCommitted };
  }
  return { closable: true, reason: 'ok' };
}

/** Bit `i` set for every occupied executor slot. */
export function liveExecutorSlots(m: MarketAccount): number {
  let bits = 0;
  m.executors.forEach((e, i) => {
    if (e !== null) bits |= 1 << i;
  });
  return bits;
}

export function popcount(x: number): number {
  let n = 0;
  for (let v = x >>> 0; v !== 0; v &= v - 1) n++;
  return n;
}
