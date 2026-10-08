import { equal } from '../core/encoding/bytes.js';
import { decodeSubmission } from '../core/protocol/submission.js';
import type { OutboxItem } from './model.js';

/**
 * Outbox items grouped per order in epoch order. Each group is re-sent as
 * one batched request with the exact bytes that were journalled, so
 * the relay answers `duplicate: true` with the original promise for what it
 * already holds.
 */
export function outboxGroups(items: readonly OutboxItem[]): Map<string, OutboxItem[]> {
  const out = new Map<string, OutboxItem[]>();
  for (const i of items) {
    const group = out.get(i.orderId) ?? [];
    group.push(i);
    out.set(i.orderId, group);
  }
  for (const group of out.values()) {
    group.sort((a, b) => (a.epoch < b.epoch ? -1 : a.epoch > b.epoch ? 1 : 0));
  }
  return out;
}

/**
 * Whether a journalled submission was signed by `sessionKey`. One signed by
 * an earlier session (renewed after expiry or eviction) must be wrapped
 * again: the envelope, and so its promise, stays the same.
 */
export function signedBy(submission: Uint8Array, sessionKey: Uint8Array): boolean {
  try {
    return equal(decodeSubmission(submission).trader, sessionKey);
  } catch {
    return false;
  }
}
