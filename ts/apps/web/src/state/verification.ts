// Client-side verification of each market the app shows: V-1 market,
// V-2 committee, V-3 the open epoch's key, V-4 its announcement, V-14 the
// enclave label and V-16 the program, through the order service. V-13
// pending governance and the mints' freeze authorities from the verified
// accounts. With a cross-check RPC chosen in Settings, the verified Market
// account's fixed fields are read again through it. A failed check blocks
// trading on that market until the user asks for a re-check. An
// inconclusive one is retried.
import type { CurrentEpoch } from '@timescales/sdk/api';
import type { MarketAccount, PendingChange, TimescalesRpc } from '@timescales/sdk/solana';
import { decodeMint } from '@timescales/sdk/solana';
import type { VerifiedMarketContext } from '@timescales/sdk/verify';
import { decodePendingChange, verifyCommittee, verifyEpochKey } from '@timescales/sdk/verify';
import { TimescalesError } from '@timescales/sdk';
import { equal } from '@timescales/sdk/core';

import type { AppConfig } from '../app/config';
import { pinsFor } from '../app/config';
import type { OrdersController } from './orders';
import type { Store } from './store';
import { createStore } from './store';
import type { Address } from './types';

export type MarketCheck =
  | { status: 'unpinned' }
  | { status: 'checking'; since: number }
  | {
      status: 'ok';
      ctx: VerifiedMarketContext;
      pending: PendingChange | null;
      recentUpgrade: boolean;
      freezeWarnings: readonly ('base' | 'quote')[];
      checkedAtSlot: bigint;
    }
  | { status: 'fail'; check: string; reason: string; atMs: number }
  | { status: 'inconclusive'; reason: string; since: number };

export type KeyCheck =
  { epoch: bigint; status: 'vouched' } | { epoch: bigint; status: 'refused'; reason: string };

export interface VerificationState {
  markets: ReadonlyMap<Address, MarketCheck>;
  /** V-3 for each market's open epoch, re-run whenever a new epoch opens. */
  keys: ReadonlyMap<Address, KeyCheck>;
}

export interface VerificationController {
  readonly state: Store<VerificationState>;
  /** Verifies a market once (and keeps retrying while inconclusive). */
  ensure(market: Address): void;
  /**  "Re-check": runs every check again, lifting an earlier failure if it passes now. */
  recheck(market: Address): Promise<void>;
  /** Checks the open epoch's key (V-3) of a fresh `current` view. */
  checkCurrent(current: CurrentEpoch): void;
  /** A new primary RPC, and the cross-check RPC with it when `crossCheck` is given. */
  setRpc(rpc: TimescalesRpc, crossCheck?: TimescalesRpc | null): void;
  /** The second RPC of Settings > Network, or null for none. */
  setCrossCheck(rpc: TimescalesRpc | null): void;
  dispose(): void;
}

/** The `check` of a market whose two RPCs disagree. */
export const CROSS_CHECK = 'V-1 cross-check';

/**
 * Reads the verified market again through the cross-check RPC, at or after
 * the slot it was verified at, and compares the fields no instruction can
 * change, so a governance change between the two reads is never a
 * disagreement. Returns the disagreement, or null.
 */
async function crossCheckMarket(
  rpc: TimescalesRpc,
  ctx: VerifiedMarketContext,
  genesisHash: string,
): Promise<string | null> {
  if ((await rpc.genesisHash()) !== genesisHash)
    return 'the cross-check RPC serves another cluster';
  let other: MarketAccount;
  try {
    other = (await rpc.market(ctx.market.address, ctx.verifiedAtSlot)).value;
  } catch (e) {
    if (e instanceof TimescalesError && e.code === 'account_missing')
      return 'the cross-check RPC has no such market account';
    throw e;
  }
  const a = ctx.market;
  const same =
    a.marketId === other.marketId &&
    equal(a.salt, other.salt) &&
    a.creator === other.creator &&
    a.baseMint === other.baseMint &&
    a.quoteMint === other.quoteMint &&
    a.baseVault === other.baseVault &&
    a.quoteVault === other.quoteVault &&
    equal(a.paramsDigest, other.paramsDigest);
  return same ? null : 'the cross-check RPC reports other fixed fields for this market';
}

/** Whether orders may be sealed on a market: verified, and the open epoch's key vouched. */
export function canSeal(s: VerificationState, market: Address, openEpoch: bigint | null): boolean {
  const m = s.markets.get(market);
  const k = s.keys.get(market);
  return (
    m?.status === 'ok' &&
    openEpoch !== null &&
    k !== undefined &&
    k.epoch === openEpoch &&
    k.status === 'vouched'
  );
}

const RETRY_MS = 5_000;
const MAX_RETRY_MS = 30_000;

function checkOf(e: unknown): { check: string; reason: string; inconclusive: boolean } | null {
  if (!(e instanceof TimescalesError) || e.kind !== 'verify') return null;
  const d = (e.details ?? {}) as { check?: unknown; reason?: unknown };
  return {
    check: typeof d.check === 'string' ? d.check : 'checklist',
    reason: typeof d.reason === 'string' ? d.reason : e.message,
    inconclusive: e.code === 'verification_inconclusive' || e.retryable,
  };
}

export function createVerificationController(d: {
  config: AppConfig;
  orders: OrdersController;
  rpc: TimescalesRpc;
  crossCheck?: TimescalesRpc | null;
  now?: () => number;
}): VerificationController {
  const now = d.now ?? (() => Date.now());
  let rpc = d.rpc;
  let crossCheck = d.crossCheck ?? null;
  const state = createStore<VerificationState>({ markets: new Map(), keys: new Map() });
  const running = new Map<Address, Promise<void>>();
  const retries = new Map<Address, ReturnType<typeof setTimeout>>();
  const attempts = new Map<Address, number>();
  let disposed = false;
  // Bumped when the RPC changes: a check started on the old RPC never writes
  // its result, since it was read through an endpoint the user replaced.
  let generation = 0;

  const setMarket = (m: Address, check: MarketCheck) => {
    state.set((s) => ({ ...s, markets: new Map(s.markets).set(m, check) }));
  };
  const setKey = (m: Address, key: KeyCheck) => {
    state.set((s) => ({ ...s, keys: new Map(s.keys).set(m, key) }));
  };

  const keyCheck = (ctx: VerifiedMarketContext, current: CurrentEpoch): KeyCheck | null => {
    const open = current.open;
    if (open === null) return null;
    const pins = ctx.pins;
    let committee = ctx.committee;
    if (!equal(open.key.committeeDigest, ctx.market.committeeDigest)) {
      // An epoch dealt before a graceful rotation names the previous committee (V-2).
      const prev = ctx.detail.committee.prevDescriptionBytes;
      if (prev === null) {
        return {
          epoch: open.epoch,
          status: 'refused',
          reason: 'the key names an unknown committee',
        };
      }
      const v = verifyCommittee(prev, ctx.market, open.key.committeeDigest);
      if (v.kind !== 'ok') return { epoch: open.epoch, status: 'refused', reason: v.reason };
      committee = v.value;
    }
    const v = verifyEpochKey(open.key, committee, ctx.market, open.epoch, pins);
    return v.kind === 'ok'
      ? { epoch: open.epoch, status: 'vouched' }
      : { epoch: open.epoch, status: 'refused', reason: v.reason };
  };

  const scheduleRetry = (m: Address, afterMs: number) => {
    const gen = generation;
    const n = (attempts.get(m) ?? 0) + 1;
    attempts.set(m, n);
    const wait = Math.min(MAX_RETRY_MS, Math.max(RETRY_MS, afterMs) * Math.min(n, 6));
    clearTimeout(retries.get(m));
    retries.set(
      m,
      setTimeout(() => {
        retries.delete(m);
        if (!disposed && gen === generation) void run(m);
      }, wait),
    );
  };

  const run = (m: Address): Promise<void> => {
    const inFlight = running.get(m);
    if (inFlight !== undefined) return inFlight;
    const gen = generation;
    const current = () => gen === generation && !disposed;
    const task = (async () => {
      if (pinsFor(d.config, m) === null) {
        setMarket(m, { status: 'unpinned' });
        return;
      }
      if (d.config.genesisHash === '') {
        // Without a pinned cluster no RPC answer can be trusted: fail closed.
        setMarket(m, {
          status: 'fail',
          check: 'pins',
          reason: 'this build pins no genesis hash',
          atMs: now(),
        });
        return;
      }
      const prev = state.get().markets.get(m);
      if (prev === undefined || prev.status === 'unpinned') {
        setMarket(m, { status: 'checking', since: now() });
      }
      try {
        const ctx = await d.orders.verifier().context(m);
        const [slot, base, quote] = await Promise.all([
          rpc.slot(),
          rpc.account(ctx.market.baseMint),
          rpc.account(ctx.market.quoteMint),
        ]);
        if (!current()) return;
        if (crossCheck !== null) {
          const disagreement = await crossCheckMarket(crossCheck, ctx, d.config.genesisHash);
          if (!current()) return;
          if (disagreement !== null) {
            setMarket(m, { status: 'fail', check: CROSS_CHECK, reason: disagreement, atMs: now() });
            return;
          }
        }
        const freezeWarnings: ('base' | 'quote')[] = [];
        if (base !== null && decodeMint(base.value).freezeAuthority !== null)
          freezeWarnings.push('base');
        if (quote !== null && decodeMint(quote.value).freezeAuthority !== null)
          freezeWarnings.push('quote');
        attempts.delete(m);
        setMarket(m, {
          status: 'ok',
          ctx,
          pending: decodePendingChange(ctx.market),
          recentUpgrade: slot < ctx.program.lastDeploySlot + ctx.market.timelockSlots,
          freezeWarnings,
          checkedAtSlot: slot,
        });
      } catch (e) {
        if (!current()) return;
        const c = checkOf(e);
        if (c !== null && !c.inconclusive) {
          setMarket(m, { status: 'fail', check: c.check, reason: c.reason, atMs: now() });
          return;
        }
        const since =
          prev?.status === 'inconclusive'
            ? prev.since
            : prev?.status === 'checking'
              ? prev.since
              : now();
        const reason = c?.reason ?? (e instanceof Error ? e.message : 'the check could not run');
        // A market that verified keeps its verified view while a later check cannot run.
        if (prev?.status !== 'ok') setMarket(m, { status: 'inconclusive', reason, since });
        scheduleRetry(m, e instanceof TimescalesError ? (e.retryAfterMs ?? RETRY_MS) : RETRY_MS);
      }
    })().finally(() => {
      if (running.get(m) === task) running.delete(m);
    });
    running.set(m, task);
    return task;
  };

  // Every market checked so far is checked again through the new RPCs. None
  // is left without a result in between.
  const restart = () => {
    generation += 1;
    for (const t of retries.values()) clearTimeout(t);
    retries.clear();
    attempts.clear();
    running.clear();
    const markets = [...state.get().markets.keys()];
    state.set({ markets: new Map(), keys: new Map() });
    for (const m of markets) void run(m);
  };

  return {
    state,
    ensure(m) {
      const s = state.get().markets.get(m);
      if (s === undefined) void run(m);
    },
    async recheck(m) {
      clearTimeout(retries.get(m));
      retries.delete(m);
      attempts.delete(m);
      await running.get(m);
      setMarket(m, { status: 'checking', since: now() });
      await run(m);
    },
    checkCurrent(current) {
      const m = current.market as Address;
      const check = state.get().markets.get(m);
      if (check?.status !== 'ok' || current.open === null) return;
      const prev = state.get().keys.get(m);
      if (prev !== undefined && prev.epoch === current.open.epoch && prev.status === 'refused')
        return;
      const k = keyCheck(check.ctx, current);
      if (k !== null) setKey(m, k);
    },
    setRpc(next, cross) {
      rpc = next;
      if (cross !== undefined) crossCheck = cross;
      restart();
    },
    setCrossCheck(next) {
      crossCheck = next;
      restart();
    },
    dispose() {
      disposed = true;
      for (const t of retries.values()) clearTimeout(t);
      retries.clear();
    },
  };
}
