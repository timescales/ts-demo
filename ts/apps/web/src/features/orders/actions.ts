// Inputs for the order actions the Trade and Orders screens offer.
import type { CurrentEpoch } from '@timescales/sdk/api';
import type { MarketParams } from '@timescales/sdk/core';
import type { OrderDraft, OrderRecord } from '@timescales/sdk/orders';

import { DEFAULT_SIGN_BUDGET_MS } from '../trade/presets';

/**
 * The epoch a cancel signed now would name: the open epoch while the signing
 * budget still fits before its cutoff, else the next one, never before the
 * order's own window. The SDK makes the final choice.
 */
export function cancelEpochFor(
  record: OrderRecord,
  current: CurrentEpoch | undefined,
  nowMs: number,
  signBudgetMs = DEFAULT_SIGN_BUDGET_MS,
): bigint | null {
  const open = current?.open;
  if (open === undefined || open === null || record.body.kind !== 'place') return null;
  const first = open.cutoffMs - nowMs > signBudgetMs ? open.epoch : open.epoch + 1n;
  const from = record.body.order.validFrom;
  return first > from ? first : from;
}

/**
 * A fresh order for what is left of one whose details became public in a
 * voided epoch: same side, role, type and limit, the unfilled quantity and
 * the rest of its window. Signing it gives a new commitment.
 */
export function replacementDraft(
  record: OrderRecord,
  openEpoch: bigint,
  params: MarketParams,
): OrderDraft | null {
  if (record.body.kind !== 'place') return null;
  const o = record.body.order;
  const quantity = o.quantity - record.filled;
  if (quantity <= 0n || o.expiresAt < openEpoch) return null;
  const left = Number(o.expiresAt - openEpoch + 1n);
  const lifetimeEpochs = Math.max(1, Math.min(params.maxOrderLifetime + 1, left));
  return {
    market: record.market,
    side: o.side,
    role: o.role,
    kind: o.kind,
    ...(o.kind === 0 ? { limitTick: o.limit } : {}),
    quantityLots: quantity,
    lifetimeEpochs,
  };
}
