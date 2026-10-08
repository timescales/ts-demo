// What /verify accepts and the checks it runs, all in the browser: evidence
// files the SDK writes (exclusion, substitution, terms, refusal, recorded
// failures), raw receipts, and epochs named as market/epoch.
import type { TimescalesApi } from '@timescales/sdk/api';
import {
  b58,
  b64,
  batchRootV2,
  decodeAnnouncement,
  decodeLeaves,
  decodePromiseV2,
  decodeReceipt,
  decodeRelayRefusal,
  epochAnnouncementDigest,
  epochBinding,
  equal,
  hex,
  promiseV2Digest,
  receiptDigest,
  relayRefusalDigest,
  termsDigest,
  verifyStrict,
} from '@timescales/sdk/core';
import type { BatchAccount, TimescalesRpc } from '@timescales/sdk/solana';
import { batchPda } from '@timescales/sdk/solana';

import type { Address } from '../../state/types';
import { parseAddress, parseU64 } from '../../state/types';
import type { MarketCheck } from '../../state/verification';
import type { CheckResult } from '../epochs/checks';
import { checkReceipt, checkRoot, checkTerms, readBatch } from '../epochs/checks';
import type { CheckRow } from '../epochs/CheckList';
import { epochsCopy } from '../epochs/copy';
import { verifyCopy } from './copy';

type Json = Record<string, unknown>;

export type Parsed =
  | { kind: 'evidence'; doc: Json }
  | { kind: 'receipt'; bytes: Uint8Array }
  | { kind: 'epoch'; market: Address; epoch: bigint }
  | { kind: 'unreadable' };

export type ReportKind = keyof typeof verifyCopy.report.kinds;

export interface Report {
  kind: ReportKind;
  market: string | null;
  epoch: string | null;
  rows: CheckRow[];
}

export interface VerifyDeps {
  api: TimescalesApi;
  rpc: TimescalesRpc;
  programId: Address | null;
  markets: ReadonlyMap<Address, MarketCheck>;
}

const EVIDENCE_KINDS = ['exclusion', 'substitution', 'terms', 'refusal', 'verification_failed'];

export function parseInput(text: string): Parsed {
  const t = text.trim();
  if (t.length === 0) return { kind: 'unreadable' };
  if (t.startsWith('{')) {
    try {
      const doc = JSON.parse(t) as unknown;
      if (
        doc !== null &&
        typeof doc === 'object' &&
        EVIDENCE_KINDS.includes(String((doc as Json).kind))
      ) {
        return { kind: 'evidence', doc: doc as Json };
      }
    } catch {
      return { kind: 'unreadable' };
    }
    return { kind: 'unreadable' };
  }
  const path = t.replace(/^.*\/epochs\//, '').split('/');
  if (path.length === 2) {
    const market = parseAddress(path[0]);
    const epoch = parseU64(path[1]);
    if (market !== null && epoch !== null) return { kind: 'epoch', market, epoch };
  }
  try {
    const bytes = b64.decode(t);
    if (bytes.length > 0 && bytes[0] === 1) {
      decodeReceipt(bytes);
      return { kind: 'receipt', bytes };
    }
  } catch {
    // not a receipt
  }
  return { kind: 'unreadable' };
}

const ok: CheckResult = { status: 'ok' };
const fail = (reason: string): CheckResult => ({ status: 'fail', reason });

function str(doc: Json, key: string): string {
  const v = doc[key];
  if (typeof v !== 'string') throw new TypeError(`missing ${key}`);
  return v;
}

function bytesOf(doc: Json, key: string): Uint8Array {
  return key.endsWith('_b64') ? b64.decode(str(doc, key)) : hex.decode(str(doc, key));
}

function attempt(f: () => boolean, reasonIfFalse: string): CheckResult {
  try {
    return f() ? ok : fail(reasonIfFalse);
  } catch (e) {
    return fail(e instanceof Error ? e.message : reasonIfFalse);
  }
}

/** The market and epoch the evidence is about. Every signed object in it must name the same. */
function subjectOf(doc: Json): { market: Address; epoch: bigint } {
  const market = parseAddress(str(doc, 'market'));
  const epoch = parseU64(str(doc, 'epoch'));
  if (market === null || epoch === null)
    throw new TypeError('the evidence names no market and epoch');
  return { market, epoch };
}

/**
 * The signing key belongs to the market's relay. Only a market this build
 * pins and this app verified has a relay key to compare with. Anything else
 * is "not checked", never ok. The app sees only the market's current relay,
 * so a key the relay held before a governance rotation reads as a mismatch.
 */
function relayRow(deps: VerifyDeps, market: Address, key: Uint8Array | null): CheckRow {
  const c = verifyCopy.checks;
  const check = deps.markets.get(market);
  let result: CheckResult;
  if (key === null) result = { status: 'skipped', reason: c.relayUnread };
  else if (check?.status === 'ok')
    result = equal(key, b58.decode(check.ctx.market.relay, 32)) ? ok : fail(c.relayOther);
  else if (check?.status === 'checking' || check?.status === 'inconclusive')
    result = { status: 'pending', reason: c.relayNotChecked(c.relayChecking) };
  else if (check?.status === 'fail')
    result = { status: 'skipped', reason: c.relayNotChecked(c.relayFailed) };
  else result = { status: 'skipped', reason: c.relayNotChecked(c.relayUnpinned) };
  return { id: 'relay', label: c.relayIsMarket, result };
}

/**
 * The Batch account of (market, epoch), at the address the program derives
 * for it rather than one the evidence names, and holding that market and epoch.
 */
async function chainBatch(
  deps: VerifyDeps,
  doc: Json,
  market: Address,
  epoch: bigint,
): Promise<{ batch: BatchAccount } | CheckResult> {
  if (deps.programId === null) return { status: 'skipped', reason: verifyCopy.noProgram };
  const named = (doc.batch ?? {}) as Json;
  if (
    (named.market !== undefined && named.market !== market) ||
    (named.epoch !== undefined && named.epoch !== String(epoch))
  ) {
    return fail('the evidence names a batch of another market or epoch');
  }
  try {
    const [address] = await batchPda(deps.programId, market, epoch);
    if (named.address !== undefined && named.address !== address) {
      return fail('the evidence names another account than the Batch account of this epoch');
    }
    const b = await deps.rpc.batch(address);
    if (b === null) return { status: 'pending', reason: 'the Batch account is not visible' };
    if (b.value.market !== market || b.value.epoch !== epoch) {
      return fail('the Batch account holds another market or epoch');
    }
    return { batch: b.value };
  } catch (e) {
    return { status: 'pending', reason: e instanceof Error ? e.message : verifyCopy.noRpc };
  }
}

async function exclusionRows(doc: Json, deps: VerifyDeps): Promise<CheckRow[]> {
  const c = verifyCopy.checks;
  const { market, epoch } = subjectOf(doc);
  const commitment = bytesOf(doc, 'commitment');
  const digest = bytesOf(doc, 'envelope_digest');
  const batch = (doc.batch ?? {}) as Json;
  let relay: Uint8Array | null = null;
  const promise = attempt(() => {
    const p = decodePromiseV2(bytesOf(doc, 'promise_b64'));
    // Promises verify against the relay key recorded at submission (F-11),
    // which must be the key the promise itself names.
    const atSubmission = b58.decode(str(doc, 'relay_at_submission'), 32);
    if (!equal(p.relay, atSubmission)) return false;
    relay = p.relay;
    return (
      equal(p.market, b58.decode(market, 32)) &&
      p.epoch === epoch &&
      equal(p.commitment, commitment) &&
      equal(p.envelopeDigest, digest) &&
      verifyStrict(p.relay, promiseV2Digest(p), p.signature)
    );
  }, 'the promise does not verify for this order, market and epoch');
  let leaves: { commitment: Uint8Array; envelopeDigest: Uint8Array }[] = [];
  const leavesRoot = attempt(() => {
    leaves = decodeLeaves(bytesOf(doc, 'leaves_b64'));
    return (
      equal(batchRootV2(leaves), hex.decode(String(batch.root))) &&
      leaves.length === Number(batch.count)
    );
  }, 'the leaves do not hash to the batch root');
  const sameC = leaves.filter((l) => equal(l.commitment, commitment));
  const substitution = doc.kind === 'substitution';
  const membership = substitution
    ? sameC.length > 0 && sameC.every((l) => !equal(l.envelopeDigest, digest))
      ? ok
      : fail('the commitment is not in the batch with another envelope')
    : sameC.some((l) => equal(l.envelopeDigest, digest))
      ? fail('the order is in the batch')
      : ok;
  const onChain = await chainBatch(deps, doc, market, epoch);
  const chainRoot: CheckResult = !('batch' in onChain)
    ? onChain
    : equal(onChain.batch.root, hex.decode(String(batch.root))) &&
        onChain.batch.count === Number(batch.count)
      ? ok
      : fail('the Batch account holds another root or count');
  return [
    { id: 'promise', label: c.promise, result: promise },
    relayRow(deps, market, promise.status === 'ok' ? relay : null),
    { id: 'leaves', label: c.leavesRoot, result: leavesRoot },
    {
      id: 'membership',
      label: substitution ? c.substituted : c.absent,
      result:
        leavesRoot.status === 'ok'
          ? membership
          : { status: 'skipped', reason: 'leaves unverified' },
    },
    { id: 'chain', label: c.chainRoot, result: chainRoot },
  ];
}

async function termsRows(doc: Json, deps: VerifyDeps): Promise<CheckRow[]> {
  const c = verifyCopy.checks;
  const { market, epoch } = subjectOf(doc);
  let relay: Uint8Array | null = null;
  const announcement = attempt(() => {
    const a = decodeAnnouncement(bytesOf(doc, 'announcement_b64'));
    relay = a.relay;
    return (
      equal(a.market, b58.decode(market, 32)) &&
      a.epoch === epoch &&
      verifyStrict(a.relay, epochAnnouncementDigest(a), a.signature)
    );
  }, 'the announcement does not verify for this market and epoch');
  const expected = attempt(() => {
    const a = decodeAnnouncement(bytesOf(doc, 'announcement_b64'));
    const terms = termsDigest(
      a.band,
      epochBinding(a.priceCommitment, a.keyDigest, a.committeeDigest),
    );
    return equal(terms, bytesOf(doc, 'expected_terms_digest'));
  }, 'the announced terms give another digest');
  const onChain = await chainBatch(deps, doc, market, epoch);
  const chainTerms: CheckResult = !('batch' in onChain)
    ? onChain
    : !equal(onChain.batch.termsDigest, bytesOf(doc, 'expected_terms_digest'))
      ? ok
      : fail('the batch committed the announced terms');
  return [
    { id: 'announcement', label: c.announcement, result: announcement },
    relayRow(deps, market, announcement.status === 'ok' ? relay : null),
    { id: 'expected', label: c.expectedTerms, result: expected },
    { id: 'chain', label: c.chainTerms, result: chainTerms },
  ];
}

function refusalRows(doc: Json, deps: VerifyDeps): CheckRow[] {
  const { market, epoch } = subjectOf(doc);
  let relay: Uint8Array | null = null;
  const refusal = attempt(() => {
    const r = decodeRelayRefusal(bytesOf(doc, 'refusal_b64'));
    const named = b58.decode(str(doc, 'relay'), 32);
    if (!equal(r.relay, named)) return false;
    relay = r.relay;
    return (
      equal(r.market, b58.decode(market, 32)) &&
      r.epoch === epoch &&
      verifyStrict(r.relay, relayRefusalDigest(r), r.signature)
    );
  }, 'the refusal does not verify for this market and epoch under the named relay');
  return [
    { id: 'refusal', label: verifyCopy.checks.refusal, result: refusal },
    relayRow(deps, market, refusal.status === 'ok' ? relay : null),
  ];
}

export async function epochRows(
  deps: VerifyDeps,
  market: Address,
  epoch: bigint,
  receipt?: Uint8Array,
): Promise<CheckRow[]> {
  const e = epochsCopy;
  const detail = await deps.api.epoch(market, epoch);
  const check = deps.markets.get(market);
  const verified = check?.status === 'ok' ? check.ctx.market : null;
  const batch =
    verified !== null && deps.programId !== null
      ? await readBatch(deps.rpc, deps.programId, market, epoch).catch(() => null)
      : undefined;
  const root = await checkRoot({ api: deps.api, detail, batch });
  const terms = checkTerms({ detail, market: verified, batch });
  const rows: CheckRow[] = [
    { id: 'leaves', label: e.root.leaves, result: root.leaves },
    { id: 'chainRoot', label: e.root.chain, result: root.chain },
    { id: 'announcement', label: e.terms.announcement, result: terms.announcement },
    { id: 'chainTerms', label: e.terms.chain, result: terms.chain },
  ];
  if (receipt !== undefined) {
    rows.push({
      id: 'posted',
      label: verifyCopy.checks.receiptPosted,
      result:
        batch === undefined
          ? { status: 'skipped', reason: e.terms.needsMarket }
          : batch === null || batch.value.receipt === null
            ? { status: 'pending', reason: 'no receipt is posted on chain' }
            : equal(batch.value.receipt, receiptDigest(receipt))
              ? ok
              : fail('another receipt is posted for this epoch'),
    });
  }
  if (verified !== null && batch !== undefined) {
    const r = await checkReceipt({ api: deps.api, detail, market: verified, batch });
    rows.push({ id: 'v7', label: e.receipt.v7, result: r.receipt });
    rows.push({ id: 'v8', label: e.receipt.v8, result: r.artifacts });
  }
  return rows;
}

export async function runVerify(parsed: Parsed, deps: VerifyDeps): Promise<Report | null> {
  if (parsed.kind === 'unreadable') return null;
  if (parsed.kind === 'epoch') {
    return {
      kind: 'epoch',
      market: parsed.market,
      epoch: String(parsed.epoch),
      rows: await epochRows(deps, parsed.market, parsed.epoch),
    };
  }
  if (parsed.kind === 'receipt') {
    const c = verifyCopy.checks;
    const r = decodeReceipt(parsed.bytes);
    const signed = attempt(
      () => verifyStrict(r.executor, receiptDigest(parsed.bytes), r.signature),
      'the executor signature does not verify',
    );
    const match = [...deps.markets.entries()].find(
      ([, m]) => m.status === 'ok' && m.ctx.market.marketId === r.outcome.market,
    );
    const rows: CheckRow[] = [
      { id: 'decodes', label: c.receiptDecodes, result: signed },
      {
        id: 'market',
        label: c.receiptMarket,
        result: match ? ok : { status: 'skipped', reason: `market id ${r.outcome.market}` },
      },
    ];
    if (match) rows.push(...(await epochRows(deps, match[0], r.outcome.epoch, parsed.bytes)));
    return {
      kind: 'receipt',
      market: match ? match[0] : null,
      epoch: String(r.outcome.epoch),
      rows,
    };
  }
  const doc = parsed.doc;
  const kind = String(doc.kind) as ReportKind;
  const subject = {
    market: typeof doc.market === 'string' ? doc.market : null,
    epoch: typeof doc.epoch === 'string' ? doc.epoch : null,
  };
  let rows: CheckRow[];
  try {
    if (kind === 'exclusion' || kind === 'substitution') rows = await exclusionRows(doc, deps);
    else if (kind === 'terms') rows = await termsRows(doc, deps);
    else if (kind === 'refusal') rows = refusalRows(doc, deps);
    else {
      rows = [
        {
          id: 'recorded',
          label: verifyCopy.checks.recorded(String(doc.check ?? ''), String(doc.reason ?? '')),
          result: { status: 'skipped', reason: verifyCopy.checks.recordedNote },
        },
      ];
    }
  } catch (e) {
    rows = [
      {
        id: 'format',
        label: verifyCopy.report.kinds[kind],
        result: fail(e instanceof Error ? e.message : 'malformed evidence'),
      },
    ];
  }
  return { kind, ...subject, rows };
}
