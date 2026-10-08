import type { Address } from '@solana/kit';
import type { TimescalesApi } from '../api/client.js';
import type { ServerClock } from '../api/clock.js';
import type { CurrentEpoch, EpochKey } from '../api/schemas.js';
import { equal } from '../core/encoding/bytes.js';
import { DecodeError } from '../core/encoding/codec.js';
import type { EpochKeyBundle } from '../core/protocol/bundle.js';
import type { CommitteeDescription } from '../core/protocol/committee.js';
import { decodePolicyStatement, type ReleasePolicyStatement } from '../core/protocol/policy.js';
import { TimescalesError } from '../errors.js';
import {
  decodeMint,
  type MarketAccount,
  type Observed,
  type TraderAccount,
} from '../solana/accounts.js';
import { traderPda } from '../solana/pdas.js';
import { decodeProgramData, programDataAddress } from '../solana/program.js';
import type { TimescalesRpc } from '../solana/rpc.js';
import { verifyAnnouncement } from '../verify/announcement.js';
import { verifyCommittee } from '../verify/committee.js';
import { verifyEpochKey } from '../verify/epochKey.js';
import { verifyMarket, type AppPins, type VerifiedMarketContext } from '../verify/market.js';
import { verifyPolicies } from '../verify/policy.js';
import { verifyProgram } from '../verify/program.js';
import type { Verdict } from '../verify/verdict.js';

/** A failed or inconclusive  check, as the order service reports it. */
export class CheckError extends TimescalesError {
  readonly check: string;
  readonly reason: string;
  readonly inconclusive: boolean;

  constructor(check: string, v: Exclude<Verdict<unknown>, { kind: 'ok' }>) {
    super({
      kind: 'verify',
      code: v.kind === 'fail' ? 'verification_failed' : 'verification_inconclusive',
      message: `${check}: ${v.reason}`,
      retryable: v.kind === 'inconclusive',
      ...(v.kind === 'inconclusive' ? { retryAfterMs: v.retryAfterMs } : {}),
      details: { check, reason: v.reason },
    });
    this.name = 'CheckError';
    this.check = check;
    this.reason = v.reason;
    this.inconclusive = v.kind === 'inconclusive';
  }
}

/**
 * A program account read from the RPC that does not decode, or does not sit
 * at its owner's program address. The program writes these accounts, so a
 * malformed one is a failed check, not a transport error.
 */
export function malformed(e: unknown): e is Error {
  return e instanceof DecodeError || (e instanceof TimescalesError && e.code === 'account_not_pda');
}

export function malformedReason(what: string, e: Error): string {
  return `the ${what} account is malformed: ${e.message}`;
}

export function ok<T>(check: string, v: Verdict<T>): T {
  if (v.kind === 'ok') return v.value;
  throw new CheckError(check, v);
}

/** An epoch key that passed V-3, with the announcement checks (V-4) once its epoch opened. */
export interface VerifiedKey {
  epoch: bigint;
  epochPk: Uint8Array;
  bundle: EpochKeyBundle;
  committee: CommitteeDescription;
}

/** What the service knows, verified, about one market. */
export interface MarketWatch {
  market: Address;
  pins: AppPins;
  ctx: VerifiedMarketContext | null;
  /** A failed check blocks trading on this market until the app asks for a re-check. */
  failure: { check: string; reason: string } | null;
  current: CurrentEpoch | null;
  keys: Map<bigint, VerifiedKey>;
  /** V-4 for opened epochs: the relay-signed announcement and the terms it implies. */
  terms: Map<bigint, { announcement: Uint8Array; binding: Uint8Array; terms: Uint8Array }>;
  trader: Observed<TraderAccount> | null;
}

export interface ContextDeps {
  api: TimescalesApi;
  rpc: TimescalesRpc;
  clock: ServerClock;
}

export function newWatch(market: Address, pins: AppPins): MarketWatch {
  return {
    market,
    pins,
    ctx: null,
    failure: null,
    current: null,
    keys: new Map(),
    terms: new Map(),
    trader: null,
  };
}

/** The committee whose digest an epoch's bundle names: the current one or, after a graceful rotation, the previous one. */
function committeeFor(
  w: MarketWatch,
  chain: MarketAccount,
  digest: Uint8Array,
): CommitteeDescription {
  const ctx = w.ctx;
  if (ctx === null) throw new TypeError('market not verified');
  if (equal(digest, chain.committeeDigest)) return ctx.committee;
  const prev = ctx.detail.committee.prevDescriptionBytes;
  if (prev !== null) return ok('V-2', verifyCommittee(prev, chain, digest));
  return ctx.committee;
}

/**
 * V-3 for one epoch's key (`epoch`, by default the one the key names),
 * cached per epoch. A key the market's committee did not vouch for is never
 * used.
 */
export function verifyKey(w: MarketWatch, k: EpochKey, epoch: bigint = k.epoch): VerifiedKey {
  const hit = w.keys.get(epoch);
  if (hit !== undefined && k.epoch === epoch && equal(hit.epochPk, k.epochPk)) return hit;
  const ctx = w.ctx;
  if (ctx === null) throw new TypeError('market not verified');
  const committee = committeeFor(w, ctx.market, k.committeeDigest);
  const v = ok('V-3', verifyEpochKey(k, committee, ctx.market, epoch, w.pins));
  const key = { epoch, epochPk: v.epochPk, bundle: v.bundle, committee };
  w.keys.set(epoch, key);
  return key;
}

/**
 * V-1, V-2, V-3, V-14 and V-16 for a market, in that order. The RPC
 * must serve the pinned cluster. The Market account is read at the node's
 * context slot. An inconclusive result is retried a few times before the
 * check reports it. Passing does not lift an earlier failure on the market:
 * only the app's re-check does (`OrderService.context`).
 */
export async function verifyContext(
  d: ContextDeps,
  w: MarketWatch,
  wallet?: Address,
): Promise<VerifiedMarketContext> {
  const pins = w.pins;
  const genesis = await d.rpc.genesisHash();
  if (genesis !== pins.genesisHash) {
    throw new CheckError('V-1', {
      kind: 'fail',
      reason: 'the RPC serves another cluster than the app is pinned to',
    });
  }
  let attempt = 0;
  for (;;) {
    attempt++;
    const detail = await d.api.market(w.market);
    let chain: Observed<MarketAccount>;
    try {
      chain = await d.rpc.market(w.market, detail.chain.contextSlot);
    } catch (e) {
      if (e instanceof TimescalesError && e.retryable && attempt < 4) {
        await sleep(500 * attempt);
        continue;
      }
      if (e instanceof TimescalesError && e.code === 'account_missing') {
        throw new CheckError('V-1', {
          kind: 'fail',
          reason: 'no Market account exists at the pinned address',
        });
      }
      if (malformed(e)) {
        throw new CheckError('V-1', { kind: 'fail', reason: malformedReason('Market', e) });
      }
      throw e;
    }
    const base = await d.rpc.account(chain.value.baseMint);
    const quote = await d.rpc.account(chain.value.quoteMint);
    if (base === null || quote === null) {
      throw new CheckError('V-1', { kind: 'fail', reason: 'a mint account does not exist' });
    }
    const v1 = verifyMarket(detail, chain, { base: base.value, quote: quote.value }, pins);
    if (v1.kind === 'inconclusive' && attempt < 4) {
      await sleep(Math.min(v1.retryAfterMs, 500 * attempt));
      continue;
    }
    ok('V-1', v1);
    const committee = ok('V-2', verifyCommittee(detail.committee.descriptionBytes, chain.value));

    const pd = await d.rpc.account(programDataAddress(pins.programId));
    if (pd === null) {
      throw new CheckError('V-16', {
        kind: 'fail',
        reason: 'the program has no ProgramData account',
      });
    }
    const nowSlot = await d.rpc.slot();
    ok('V-16', verifyProgram(pd.value, pins, chain.value, nowSlot));
    const program = decodeProgramData(pd.value);

    w.ctx = {
      market: chain.value,
      detail,
      committee,
      units: {
        params: chain.value.params,
        baseDecimals: decodeMint(base.value).decimals,
        quoteDecimals: decodeMint(quote.value).decimals,
      },
      policies: [],
      enclaveLabel: 'operator_reported',
      program,
      pins,
      verifiedAtSlot: chain.contextSlot,
    };
    w.keys.clear();
    w.terms.clear();

    const current = await d.api.current(w.market);
    const keyed = current.open?.key ?? current.parkWindow[0];
    if (keyed === undefined) {
      w.ctx = null;
      throw new CheckError('V-3', {
        kind: 'inconclusive',
        reason: 'no epoch key is published yet',
        retryAfterMs: 5_000,
      });
    }
    const key = verifyKey(w, keyed);
    const statements = await d.api.policies(w.market);
    const label = ok('V-14', verifyPolicies(statements, committee, key.bundle));
    const policies: ReleasePolicyStatement[] = [];
    for (const raw of statements) {
      try {
        const s = decodePolicyStatement(raw);
        if (equal(s.market, committee.market)) policies.push(s);
      } catch {
        // verifyPolicies already rejected statements that claim this committee and do not verify.
      }
    }
    w.ctx = { ...w.ctx, policies, enclaveLabel: label.enclaveLabel };
    await refreshCurrent(d, w, current, wallet);
    return w.ctx;
  }
}

/**
 * Takes in a fresh `current` view: the open epoch's key (V-3) and
 * announcement (V-4), every key of the park window (V-3), and the
 * wallet's trader account when it is known.
 */
export async function refreshCurrent(
  d: ContextDeps,
  w: MarketWatch,
  current?: CurrentEpoch,
  wallet?: Address,
): Promise<CurrentEpoch> {
  const ctx = w.ctx;
  if (ctx === null) throw new TypeError('market not verified');
  const c = current ?? (await d.api.current(w.market));
  w.current = c;
  if (c.open !== null) {
    const key = verifyKey(w, c.open.key);
    if (!w.terms.has(c.open.epoch)) {
      const v = ok(
        'V-4',
        verifyAnnouncement(c.open.announcementBytes, ctx.market, ctx.market.params, key.bundle),
      );
      if (!equal(v.binding, c.open.binding) || !equal(v.terms, c.open.termsDigest)) {
        throw new CheckError('V-4', {
          kind: 'fail',
          reason: 'the node reports other terms than its relay announced',
        });
      }
      w.terms.set(c.open.epoch, { announcement: c.open.announcementBytes, ...v });
    }
  }
  for (const k of c.parkWindow) verifyKey(w, k);
  if (wallet !== undefined) {
    const [address] = await traderPda(ctx.pins.programId, w.market, wallet);
    try {
      w.trader = await d.rpc.trader(address);
    } catch (e) {
      if (malformed(e)) {
        throw new CheckError('V-15', { kind: 'fail', reason: malformedReason('Trader', e) });
      }
      throw e;
    }
  }
  return c;
}

/** The first epoch an order signed now can still reach: the open one, unless it closes within `budgetMs`. */
export function firstReachable(c: CurrentEpoch, nowMs: number, budgetMs: number): bigint | null {
  if (c.open === null) return null;
  return c.open.cutoffMs - nowMs > budgetMs ? c.open.epoch : c.open.epoch + 1n;
}

/** The last epoch an envelope can be parked for: open + max_park_ahead_epochs, as far as keys are verified. */
export function parkHorizon(w: MarketWatch): bigint | null {
  const c = w.current;
  const ctx = w.ctx;
  if (c === null || c.open === null || ctx === null) return null;
  let last = c.open.epoch;
  const limit = c.open.epoch + BigInt(ctx.detail.timing.maxParkAheadEpochs);
  while (last < limit && w.keys.has(last + 1n)) last++;
  return last;
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}
