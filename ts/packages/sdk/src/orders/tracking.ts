import type { Address } from '@solana/kit';
import type { TimescalesApi } from '../api/client.js';
import type { Artifacts, EpochDetail } from '../api/schemas.js';
import { b58 } from '../core/encoding/base58.js';
import { equal } from '../core/encoding/bytes.js';
import { decodeArtifacts, type ExecutionArtifacts } from '../core/protocol/artifacts.js';
import { TimescalesError } from '../errors.js';
import type {
  BatchAccount,
  BatchStatus,
  MarketAccount,
  Observed,
  TraderAccount,
} from '../solana/accounts.js';
import { batchPda, traderPda } from '../solana/pdas.js';
import type { TimescalesRpc } from '../solana/rpc.js';
import { checkCommittedTerms, verifyAnnouncement } from '../verify/announcement.js';
import { verifyArtifacts } from '../verify/artifacts.js';
import { verifyOwnBalance } from '../verify/balance.js';
import { committeeKnown } from '../verify/committee.js';
import { evidenceRecord, failureEvidence, type EvidenceRecord } from '../verify/evidence.js';
import { ownFills, type OwnFill } from '../verify/fills.js';
import { checkInclusion, type Inclusion } from '../verify/inclusion.js';
import { verifyReceipt } from '../verify/receipt.js';
import type { Verdict } from '../verify/verdict.js';
import {
  CheckError,
  malformed,
  malformedReason,
  verifyKey,
  type MarketWatch,
  type VerifiedKey,
} from './context.js';
import type { OrderEvent, OrderRecord } from './model.js';
import { IN_FLIGHT, PENDING, type Supplement } from './participation.js';

/** Sealed or parked with a verified promise: the relay holds it (an outbox entry does not count). */
function atRelay(r: OrderRecord, epoch: bigint): boolean {
  const p = r.epochs.get(epoch);
  return p !== undefined && PENDING.has(p.state.kind) && p.promise !== null;
}

/** The last V-6 result recorded for the record's participation in `epoch`. */
function inclusionIn(r: OrderRecord, epoch: bigint): Inclusion['status'] | undefined {
  for (let i = r.history.length - 1; i >= 0; i--) {
    const h = r.history[i]!;
    if (h.kind === 'inclusion' && h.epoch === epoch) return h.inclusion;
  }
  return undefined;
}

/** One reducer step the tracker derived from verified chain and node data. */
export interface Step {
  id: string;
  event: OrderEvent;
  supplement?: Supplement & { fills?: OwnFill[] };
  evidence?: EvidenceRecord;
}

export interface TrackDeps {
  api: TimescalesApi;
  rpc: TimescalesRpc;
  now: () => number;
}

const ORDER: Readonly<Record<BatchStatus, number>> = {
  committed: 1,
  beacon_revealed: 2,
  receipt_posted: 3,
  verified: 4,
  settled: 5,
  aborted: 6,
};

function notYet(e: unknown): boolean {
  return (
    e instanceof TimescalesError &&
    (e.code === 'NOT_YET_AVAILABLE' || e.code === 'NOT_FOUND' || e.code === 'PRUNED')
  );
}

/** Lazily fetched, shared per epoch: the node's detail, leaves and artifacts, and a fresh Market read. */
class EpochData {
  private readonly d: TrackDeps;
  private readonly market: Address;
  private readonly epoch: bigint;
  private detailP: Promise<EpochDetail | null> | null = null;
  private leavesP: Promise<Uint8Array | null> | null = null;
  private artifactsP: Promise<Artifacts | null> | null = null;
  private balancesP: Promise<Uint8Array | null> | null = null;
  private marketP: Promise<Observed<MarketAccount>> | null = null;

  constructor(d: TrackDeps, market: Address, epoch: bigint) {
    this.d = d;
    this.market = market;
    this.epoch = epoch;
  }

  private guard<T>(f: () => Promise<T>): Promise<T | null> {
    return f().catch((e: unknown) => {
      if (notYet(e)) return null;
      throw e;
    });
  }

  detail(): Promise<EpochDetail | null> {
    this.detailP ??= this.guard(() => this.d.api.epoch(this.market, this.epoch));
    return this.detailP;
  }

  leaves(): Promise<Uint8Array | null> {
    this.leavesP ??= this.guard(() => this.d.api.leaves(this.market, this.epoch));
    return this.leavesP;
  }

  artifacts(): Promise<Artifacts | null> {
    this.artifactsP ??= this.guard(() => this.d.api.artifacts(this.market, this.epoch));
    return this.artifactsP;
  }

  balances(): Promise<Uint8Array | null> {
    this.balancesP ??= this.guard(() => this.d.api.balances(this.market, this.epoch));
    return this.balancesP;
  }

  chainMarket(): Promise<Observed<MarketAccount>> {
    this.marketP ??= this.d.rpc.market(this.market);
    return this.marketP;
  }
}

/** What happened to the records' participations in one epoch, as far as it can be verified now. */
export interface EpochReport {
  steps: Step[];
  /** Some check could not be completed yet (RPC behind, data not published). */
  inconclusive: boolean;
  /** Fills attached to own orders by this pass. */
  attached: number;
  /** Fills of this wallet whose commitment no record knows ("Fills from another device"). */
  foreignFills: number;
  /** A failed check that no step carries, because no record had anything in the epoch. */
  failure: { check: string; reason: string } | null;
}

/**
 * A failed check for one record, with its evidence. A record that already
 * failed the same check in an earlier pass gets no second copy of the
 * evidence. The step still blocks the market.
 */
function failStep(
  r: OrderRecord,
  check: string,
  now: number,
  evidence: () => EvidenceRecord | undefined,
): Step {
  const event: OrderEvent = { atMs: now, kind: 'verification_failed', check };
  if (r.state.kind === 'verification_failed' && r.state.check === check) {
    return { id: r.id, event };
  }
  const e = evidence();
  return e === undefined
    ? { id: r.id, event }
    : { id: r.id, event, supplement: { evidenceId: e.id }, evidence: e };
}

function failed(
  w: MarketWatch,
  r: OrderRecord,
  epoch: bigint,
  check: string,
  reason: string,
  inputs: Record<string, Uint8Array>,
  now: number,
): Step {
  return failStep(r, check, now, () => {
    const bytes = failureEvidence({ market: w.market, epoch, check, reason, inputs });
    return evidenceRecord('verification_failed', w.market, epoch, bytes, now);
  });
}

type Announced =
  | { kind: 'ok'; announcement: Uint8Array; terms: Uint8Array }
  | { kind: 'fail'; check: string; reason: string; inputs: Record<string, Uint8Array> }
  | { kind: 'inconclusive' };

/**
 * The terms the relay announced for `epoch` (V-4). The service verified
 * them when it saw the epoch open. For an epoch it did not (it was parked
 * while the app was closed, or the service restarted or re-verified the
 * market since), they come from the node's epoch detail: the key passes V-3
 * for the market's current or previous committee, and the announcement V-4
 * under the relay in force now or the one recorded when submitting to the
 * epoch (a later `SetRelay` does not make it invalid). A key whose
 * committee is neither, after two rotations, cannot be checked any more.
 */
async function announcedTerms(
  w: MarketWatch,
  epoch: bigint,
  relays: readonly Address[],
  data: EpochData,
): Promise<Announced> {
  const cached = w.terms.get(epoch);
  if (cached !== undefined) return { kind: 'ok', ...cached };
  const ctx = w.ctx;
  const detail = await data.detail();
  if (ctx === null || detail === null) return { kind: 'inconclusive' };
  if (!committeeKnown(ctx.market, detail.key.committeeDigest)) return { kind: 'inconclusive' };
  let key: VerifiedKey;
  try {
    key = verifyKey(w, detail.key, epoch);
  } catch (e) {
    if (!(e instanceof CheckError)) throw e;
    if (e.inconclusive) return { kind: 'inconclusive' };
    return {
      kind: 'fail',
      check: e.check,
      reason: e.reason,
      inputs: { bundle: detail.key.bundleBytes },
    };
  }
  let first: Verdict<unknown> | null = null;
  for (const relay of new Set([...relays, ctx.market.relay])) {
    const v = verifyAnnouncement(
      detail.announcementBytes,
      { ...ctx.market, relay },
      ctx.market.params,
      key.bundle,
    );
    if (v.kind === 'ok') {
      const announced = { announcement: detail.announcementBytes, ...v.value };
      w.terms.set(epoch, announced);
      return { kind: 'ok', ...announced };
    }
    first ??= v;
  }
  if (first === null || first.kind !== 'fail') return { kind: 'inconclusive' };
  return {
    kind: 'fail',
    check: 'V-4',
    reason: first.reason,
    inputs: { announcement: detail.announcementBytes },
  };
}

/**
 * Follows one epoch for the records that have something in it, by the
 * checks: committed -> V-4 terms and V-6 inclusion (until it passes,
 * the record stays `locked` and the pass is inconclusive). Revealed. Receipt
 * -> V-7 (provisional below the quorum). Quorum -> V-8, V-15 (the wallet's
 * entry in the published balance sheet) and V-9 (fills and cancel
 * results). Settlement progress. Settled (V-10: the batch is Settled on
 * chain. The account's balance change is shown, not enforced). Aborted.
 * Stream events only say when to look.
 */
export async function trackEpoch(
  d: TrackDeps,
  w: MarketWatch,
  epoch: bigint,
  records: readonly OrderRecord[],
  wallet: Address,
  scanForeign: boolean,
): Promise<EpochReport> {
  const out: EpochReport = {
    steps: [],
    inconclusive: false,
    attached: 0,
    foreignFills: 0,
    failure: null,
  };
  const ctx = w.ctx;
  if (ctx === null) return out;
  const now = Math.floor(d.now());
  const ev = <K extends OrderEvent['kind']>(
    kind: K,
    rest: Omit<Extract<OrderEvent, { kind: K }>, 'kind' | 'atMs'>,
  ): OrderEvent => ({ atMs: now, kind, ...rest }) as OrderEvent;

  const involved = records.filter((r) => {
    const p = r.epochs.get(epoch);
    if (p !== undefined && (PENDING.has(p.state.kind) || IN_FLIGHT.has(p.state.kind))) return true;
    return r.state.kind === 'cancel_pending' && r.state.epoch === epoch;
  });
  if (involved.length === 0 && !scanForeign) return out;
  // A program account that does not decode, or is not at its PDA, fails the check that read it.
  const malformedRead = (check: string, what: string, e: Error): EpochReport => {
    const reason = malformedReason(what, e);
    for (const r of involved) out.steps.push(failed(w, r, epoch, check, reason, {}, now));
    if (involved.length === 0) out.failure = { check, reason };
    return out;
  };

  const data = new EpochData(d, w.market, epoch);
  const [address] = await batchPda(ctx.pins.programId, w.market, epoch);
  let batch: Observed<BatchAccount> | null;
  try {
    batch = await d.rpc.batch(address);
  } catch (e) {
    if (malformed(e)) return malformedRead('V-6', 'Batch', e);
    throw e;
  }
  if (batch === null) {
    const detail = await data.detail();
    if (detail !== null && detail.phase !== 'scheduled' && detail.phase !== 'open') {
      for (const r of involved) {
        if (atRelay(r, epoch)) out.steps.push({ id: r.id, event: ev('epoch_locked', { epoch }) });
      }
      // Closed but not visible on the RPC yet.
      out.inconclusive = involved.length > 0;
    }
    return out;
  }
  const b = batch.value;
  for (const r of involved) {
    if (atRelay(r, epoch)) out.steps.push({ id: r.id, event: ev('epoch_locked', { epoch }) });
  }

  // V-4 after commit: the batch must commit to the terms the relay announced.
  // Until both are known the records are held at `locked`, as for V-6.
  let termsChecked = involved.length === 0;
  if (!termsChecked) {
    const relays = involved.flatMap((r) => r.epochs.get(epoch)?.relayAtSubmission ?? []);
    const announced = await announcedTerms(w, epoch, relays, data);
    if (announced.kind === 'fail') {
      for (const r of involved) {
        out.steps.push(
          failed(w, r, epoch, announced.check, announced.reason, announced.inputs, now),
        );
      }
      return out;
    }
    if (announced.kind === 'inconclusive') {
      out.inconclusive = true;
    } else {
      const v = checkCommittedTerms(announced.announcement, announced.terms, batch);
      if (v.kind === 'fail') {
        const bytes = v.evidence;
        let evidence: EvidenceRecord | undefined;
        const terms = () =>
          bytes === undefined
            ? undefined
            : (evidence ??= evidenceRecord('terms', w.market, epoch, bytes, now));
        for (const r of involved) out.steps.push(failStep(r, 'V-4', now, terms));
        return out;
      }
      termsChecked = v.kind === 'ok';
      if (!termsChecked) out.inconclusive = true;
    }
  }

  // V-6 for every participation holding a promise and no inclusion result
  // yet, whatever state it reached: a node that withholds the leaves until
  // after the reveal must not skip the check. A record moves past `locked`
  // only once V-6 has passed for it.
  const passed = new Set<string>();
  for (const r of involved) {
    const p = r.epochs.get(epoch);
    if (p === undefined || p.promise === null) {
      // No promise: nothing to check, and no participation that later steps move.
      passed.add(r.id);
      continue;
    }
    const prior = inclusionIn(r, epoch);
    if (prior !== undefined) {
      if (prior === 'included') passed.add(r.id);
      continue;
    }
    if (!PENDING.has(p.state.kind) && !IN_FLIGHT.has(p.state.kind)) continue;
    const leaves = await data.leaves();
    if (leaves === null) {
      out.inconclusive = true;
      continue;
    }
    const v = checkInclusion(
      { commitment: r.commitment, envelopeDigest: p.envelopeDigest },
      p.promise,
      p.relayAtSubmission,
      leaves,
      batch,
    );
    if (v.kind === 'inconclusive') {
      out.inconclusive = true;
    } else if (v.kind === 'fail') {
      out.steps.push(failed(w, r, epoch, 'V-6', v.reason, { leaves, promise: p.promise }, now));
    } else if (v.value.status === 'included') {
      passed.add(r.id);
      out.steps.push({ id: r.id, event: ev('inclusion', { epoch, inclusion: 'included' }) });
    } else {
      const kind = v.value.status === 'excluded' ? 'exclusion' : 'substitution';
      const evidence = evidenceRecord(kind, w.market, epoch, v.value.evidence, now);
      out.steps.push({
        id: r.id,
        event: ev('inclusion', { epoch, inclusion: v.value.status }),
        supplement: { evidenceId: evidence.id },
        evidence,
      });
    }
  }

  // Reveal, receipt, fills and settlement move only records whose inclusion and terms are known.
  const advancing = termsChecked ? involved.filter((r) => passed.has(r.id)) : [];

  const status = ORDER[b.status];
  if (b.status === 'aborted') {
    const detail = await data.detail();
    if (detail === null) {
      // Whether the outcome went public is not known yet.
      out.inconclusive = involved.length > 0;
      return out;
    }
    // Null: published, but not readable here, so every commitment counts as named.
    let named: Set<string> | null = new Set();
    if (detail.artifactsPublic) {
      const a = await data.artifacts();
      named = a === null ? null : namedIn(a);
    }
    for (const r of involved) {
      const outcomeWasPublic = named === null || named.has(b58.encode(r.commitment));
      out.steps.push({ id: r.id, event: ev('aborted', { epoch, outcomeWasPublic }) });
    }
    return out;
  }
  if (status >= ORDER.beacon_revealed) {
    for (const r of advancing) out.steps.push({ id: r.id, event: ev('revealed', { epoch }) });
  }
  if (status < ORDER.receipt_posted) return out;

  // V-7
  const detail = await data.detail();
  if (detail === null || detail.headerBytes === null || detail.receiptBytes === null) {
    out.inconclusive = true;
    return out;
  }
  let chain: Observed<MarketAccount>;
  try {
    chain = await data.chainMarket();
  } catch (e) {
    if (malformed(e)) return malformedRead('V-7', 'Market', e);
    throw e;
  }
  const v7 = verifyReceipt(detail.receiptBytes, detail.headerBytes, { market: chain.value, batch });
  if (v7.kind === 'inconclusive') {
    out.inconclusive = true;
    return out;
  }
  if (v7.kind === 'fail') {
    for (const r of involved) {
      out.steps.push(
        failed(
          w,
          r,
          epoch,
          'V-7',
          v7.reason,
          { receipt: detail.receiptBytes, header: detail.headerBytes },
          now,
        ),
      );
    }
    return out;
  }
  const { receipt, quorum } = v7.value;
  if (!quorum.met) {
    for (const r of advancing) {
      out.steps.push({
        id: r.id,
        event: ev('receipt', { epoch, quorumMet: false }),
        supplement: { quorum: { have: quorum.have, need: quorum.need } },
      });
    }
    return out;
  }

  // V-8, V-9
  const art = await data.artifacts();
  if (art === null) {
    out.inconclusive = true;
    return out;
  }
  const v8 = verifyArtifacts(art.artifactsBytes, receipt, ctx.market.params, epoch);
  if (v8.kind !== 'ok') {
    for (const r of involved) {
      out.steps.push(
        failed(
          w,
          r,
          epoch,
          'V-8',
          v8.kind === 'fail' ? v8.reason : 'inconclusive',
          { artifacts: art.artifactsBytes },
          now,
        ),
      );
    }
    return out;
  }
  const artifacts = v8.value;

  // V-15: the relay's balance snapshot of this wallet, once it is public.
  const sheet = involved.length > 0 ? await data.balances() : null;
  if (sheet !== null) {
    const [own] = await traderPda(ctx.pins.programId, w.market, wallet);
    let account: Observed<TraderAccount> | null;
    try {
      account = await d.rpc.trader(own);
    } catch (e) {
      if (malformed(e)) return malformedRead('V-15', 'Trader', e);
      throw e;
    }
    if (account !== null) {
      const v15 = verifyOwnBalance(sheet, account, b, epoch);
      if (v15.kind === 'fail') {
        for (const r of involved) {
          out.steps.push(failed(w, r, epoch, 'V-15', v15.reason, { balances: sheet }, now));
        }
        return out;
      }
    }
  }

  for (const r of advancing) {
    const p = r.epochs.get(epoch);
    if (
      p !== undefined &&
      (PENDING.has(p.state.kind) ||
        ['locked', 'included', 'clearing', 'provisional'].includes(p.state.kind))
    ) {
      if (r.body.kind === 'place') {
        const v9 = ownFills(
          artifacts,
          receipt,
          [{ commitment: r.commitment, order: r.body.order, filledBefore: r.filled }],
          ctx.market.params,
        );
        if (v9.kind !== 'ok') {
          out.steps.push(
            failed(
              w,
              r,
              epoch,
              'V-9',
              v9.kind === 'fail' ? v9.reason : 'inconclusive',
              { artifacts: art.artifactsBytes },
              now,
            ),
          );
          continue;
        }
        const filled = v9.value.fills.reduce((s, f) => s + f.quantity, 0n);
        out.steps.push({
          id: r.id,
          event: ev('fills', { epoch, filled }),
          supplement: { fills: v9.value.fills },
        });
        if (v9.value.fills.length > 0) out.attached++;
      } else {
        out.steps.push({ id: r.id, event: ev('fills', { epoch, filled: 0n }) });
      }
    }
  }
  // Cancel results: the placement is in `cancelled` when the Cancel took effect.
  for (const r of involved) {
    if (r.state.kind !== 'cancel_pending' || r.state.epoch !== epoch) continue;
    const answered = r.history.findLastIndex((h) => h.kind === 'cancel_result');
    if (answered > r.history.findLastIndex((h) => h.kind === 'cancel_submitted')) continue;
    const target = r.body.kind === 'cancel' ? r.body.cancel.target : r.commitment;
    const cancelled = artifacts.cancelled.some((c) => equal(c, target));
    out.steps.push({
      id: r.id,
      event: ev('cancel_result', { result: cancelled ? 'cancelled' : 'too_late' }),
    });
  }
  if (scanForeign) {
    const own = new Set(records.map((r) => b58.encode(r.commitment)));
    const me = b58.decode(wallet, 32);
    out.foreignFills = artifacts.fills.filter(
      (f) => equal(f.trader, me) && !own.has(b58.encode(f.commitment)),
    ).length;
  }

  if (b.status === 'receipt_posted' && b.verifiedCount > 0) {
    for (const r of advancing) {
      out.steps.push({
        id: r.id,
        event: ev('settlement', { epoch, done: b.verifiedCount, total: b.settlementCount }),
      });
    }
  } else if (b.status === 'verified') {
    for (const r of advancing) {
      out.steps.push({
        id: r.id,
        event: ev('settlement', { epoch, done: b.appliedCount, total: b.settlementCount }),
      });
    }
  }
  // V-10: the batch is Settled on chain. The balance change itself is shown, not enforced.
  if (b.status === 'settled') {
    for (const r of advancing) out.steps.push({ id: r.id, event: ev('settled', { epoch }) });
  }
  return out;
}

/**
 * Commitments the published artifacts of a voided epoch name, or null when
 * they do not decode. Whatever was published is public, so the artifacts
 * count whether or not they verify (V-7, V-8), and unreadable ones make
 * every commitment of the epoch count as named.
 */
function namedIn(a: Artifacts): Set<string> | null {
  let artifacts: ExecutionArtifacts;
  try {
    artifacts = decodeArtifacts(a.artifactsBytes);
  } catch {
    return null;
  }
  const out = new Set<string>();
  for (const f of artifacts.fills) out.add(b58.encode(f.commitment));
  for (const c of artifacts.cancelled) out.add(b58.encode(c));
  return out;
}
