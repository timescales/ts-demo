// Client-side checks of one epoch's public data (V-4, V-6 root part,
// V-7, V-8), shared by the epoch detail and the Verify screen. Each returns
// a result the UI renders as a row. None of them throws on bad input.
import type { EpochDetail, TimescalesApi } from '@timescales/sdk/api';
import { batchRootV2, decodeBundle, decodeLeaves, equal, hex } from '@timescales/sdk/core';
import type { BatchAccount, MarketAccount, Observed, TimescalesRpc } from '@timescales/sdk/solana';
import { batchPda } from '@timescales/sdk/solana';
import type { Verdict } from '@timescales/sdk/verify';
import { verifyAnnouncement, verifyArtifacts, verifyReceipt } from '@timescales/sdk/verify';
import type { ExecutionArtifacts } from '@timescales/sdk/core';

import type { Address } from '../../state/types';

export type CheckResult =
  | { status: 'ok'; note?: string }
  | { status: 'fail'; reason: string }
  | { status: 'pending'; reason: string }
  | { status: 'skipped'; reason: string };

export function fromVerdict<T>(v: Verdict<T>): CheckResult {
  if (v.kind === 'ok') return { status: 'ok' };
  if (v.kind === 'fail') return { status: 'fail', reason: v.reason };
  return { status: 'pending', reason: v.reason };
}

function message(e: unknown): string {
  return e instanceof Error ? e.message : 'the check could not run';
}

export async function readBatch(
  rpc: TimescalesRpc,
  program: Address,
  market: Address,
  epoch: bigint,
): Promise<Observed<BatchAccount> | null> {
  const [address] = await batchPda(program, market, epoch);
  return rpc.batch(address);
}

/** The committed leaves hash to the reported root, and to the Batch account's root. */
export async function checkRoot(a: {
  api: TimescalesApi;
  detail: EpochDetail;
  batch: Observed<BatchAccount> | null | undefined;
}): Promise<{ leaves: CheckResult; chain: CheckResult }> {
  const b = a.detail.batch;
  if (b === null) {
    const pending = { status: 'pending', reason: 'not committed yet' } as const;
    return { leaves: pending, chain: pending };
  }
  let root: Uint8Array;
  let count: number;
  try {
    const leaves = decodeLeaves(await a.api.leaves(a.detail.market, a.detail.epoch));
    root = batchRootV2(leaves);
    count = leaves.length;
  } catch (e) {
    const r = { status: 'pending', reason: message(e) } as const;
    return { leaves: r, chain: { status: 'skipped', reason: 'no leaves' } };
  }
  const leavesResult: CheckResult =
    equal(root, b.root) && count === b.count
      ? { status: 'ok' }
      : { status: 'fail', reason: 'the leaves do not hash to the reported root' };
  let chain: CheckResult;
  if (a.batch === undefined) chain = { status: 'skipped', reason: 'no verified program to read' };
  else if (a.batch === null)
    chain = { status: 'pending', reason: 'the Batch account is not visible yet' };
  else
    chain =
      equal(root, a.batch.value.root) && count === a.batch.value.count
        ? { status: 'ok' }
        : { status: 'fail', reason: 'the leaves do not hash to the root on Solana' };
  return { leaves: leavesResult, chain };
}

/** V-4: the relay's announcement and binding, and the terms committed on chain. */
export function checkTerms(a: {
  detail: EpochDetail;
  market: MarketAccount | null;
  batch: Observed<BatchAccount> | null | undefined;
}): { announcement: CheckResult; chain: CheckResult } {
  if (a.market === null) {
    const skipped = { status: 'skipped', reason: 'market not verified' } as const;
    return { announcement: skipped, chain: skipped };
  }
  let announcement: CheckResult;
  let terms: Uint8Array | null = null;
  try {
    const bundle = decodeBundle(a.detail.key.bundleBytes);
    const v = verifyAnnouncement(a.detail.announcementBytes, a.market, a.market.params, bundle);
    if (v.kind === 'ok') {
      terms = v.value.terms;
      announcement = equal(v.value.terms, a.detail.termsDigest)
        ? { status: 'ok' }
        : { status: 'fail', reason: 'the node reports other terms than its relay announced' };
    } else announcement = fromVerdict(v);
  } catch (e) {
    announcement = { status: 'fail', reason: message(e) };
  }
  let chain: CheckResult;
  if (terms === null) chain = { status: 'skipped', reason: 'announcement not verified' };
  else if (a.batch === null || a.batch === undefined)
    chain = { status: 'pending', reason: 'not committed yet' };
  else
    chain = equal(terms, a.batch.value.termsDigest)
      ? { status: 'ok' }
      : {
          status: 'fail',
          reason: `the batch committed terms ${hex.encode(a.batch.value.termsDigest).slice(0, 8)}...`,
        };
  return { announcement, chain };
}

export interface ReceiptChecks {
  receipt: CheckResult;
  quorum: { have: number; need: number; met: boolean } | null;
  artifacts: CheckResult;
  verified: ExecutionArtifacts | null;
}

/** V-7 and V-8, run locally. */
export async function checkReceipt(a: {
  api: TimescalesApi;
  detail: EpochDetail;
  market: MarketAccount;
  batch: Observed<BatchAccount> | null;
}): Promise<ReceiptChecks> {
  const none: ReceiptChecks = {
    receipt: { status: 'pending', reason: 'no receipt yet' },
    quorum: null,
    artifacts: { status: 'skipped', reason: 'no receipt' },
    verified: null,
  };
  const { receiptBytes, headerBytes } = a.detail;
  if (receiptBytes === null || headerBytes === null) return none;
  if (a.batch === null) {
    return {
      ...none,
      receipt: { status: 'pending', reason: 'the Batch account is not visible yet' },
    };
  }
  const v7 = verifyReceipt(receiptBytes, headerBytes, { market: a.market, batch: a.batch });
  if (v7.kind !== 'ok') return { ...none, receipt: fromVerdict(v7) };
  if (!a.detail.artifactsPublic) {
    return {
      receipt: { status: 'ok' },
      quorum: v7.value.quorum,
      artifacts: { status: 'pending', reason: 'artifacts are public once the quorum is on chain' },
      verified: null,
    };
  }
  try {
    const artifacts = await a.api.artifacts(a.detail.market, a.detail.epoch);
    const v8 = verifyArtifacts(
      artifacts.artifactsBytes,
      v7.value.receipt,
      a.market.params,
      a.detail.epoch,
    );
    return {
      receipt: { status: 'ok' },
      quorum: v7.value.quorum,
      artifacts: fromVerdict(v8),
      verified: v8.kind === 'ok' ? v8.value : null,
    };
  } catch (e) {
    return {
      receipt: { status: 'ok' },
      quorum: v7.value.quorum,
      artifacts: { status: 'pending', reason: message(e) },
      verified: null,
    };
  }
}

/**: enclaves reveal at commit_slot + 2d + reveal_backstop_slots (default 8). */
const REVEAL_BACKSTOP_SLOTS = 8n;
/**: the beacon expires after commit_slot + d + REVEAL_WINDOW. */
const REVEAL_WINDOW = 400n;
/**: the bounds of the beacon delay d. */
const MIN_BEACON_DELAY = 4n;
const MAX_BEACON_DELAY = 64n;

/**
 * Whether the manual Reveal is due: past the enclaves' backstop and before
 * the beacon expires. d comes from the verified Market account only. A node
 * that misreported it could otherwise hide the action. Without it, the
 * bounds give the earliest the reveal can be overdue and the latest it
 * can expire.
 */
export function revealDue(slot: bigint, commitSlot: bigint, verifiedDelay: bigint | null): boolean {
  const overdueAfter = 2n * (verifiedDelay ?? MIN_BEACON_DELAY) + REVEAL_BACKSTOP_SLOTS;
  const expiresAfter = (verifiedDelay ?? MAX_BEACON_DELAY) + REVEAL_WINDOW;
  return slot > commitSlot + overdueAfter && slot <= commitSlot + expiresAfter;
}
