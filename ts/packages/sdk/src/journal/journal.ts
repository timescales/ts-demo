import type { Address } from '@solana/kit';
import { TimescalesError } from '../errors.js';
import type { OrderRecord, OutboxItem } from '../orders/model.js';
import type { EvidenceRecord } from '../verify/evidence.js';
import { openIndexedDbJournal } from './idb.js';
import { createMemoryJournal } from './memory.js';

/** Local encrypted order journal. */
export interface Journal {
  readonly available: 'indexeddb' | 'memory';
  readonly persisted: boolean | 'unknown';
  /** One IndexedDB transaction. Rejects with VersionConflict when `expectedVersion` is stale. Resolves to the new version. */
  put(r: OrderRecord, expectedVersion: number): Promise<number>;
  get(id: string): Promise<OrderRecord | undefined>;
  list(f?: { market?: Address }): Promise<OrderRecord[]>;
  putEvidence(e: EvidenceRecord): Promise<void>;
  outbox(): Promise<OutboxItem[]>;
  hide(): void;
  wipe(): Promise<void>;
}

/** A session key kept for `TradingSession.resume`. Only non-extractable WebCrypto keys are stored. */
export interface StoredSession {
  wallet: Address;
  sessionKey: Uint8Array;
  privateKey: CryptoKey;
  expiresAtMs: number;
  market: Address | null;
  lastTs: number;
}

/** What the journal implementations offer beyond the frozen {@link Journal}. */
export interface JournalInternals {
  readonly scope: { cluster: string; program: Address; wallet: Address };
  listEvidence(): Promise<EvidenceRecord[]>;
  saveSession(s: StoredSession): Promise<void>;
  loadSession(): Promise<StoredSession | undefined>;
  deleteSession(): Promise<void>;
  close(): void;
}

export const JOURNAL_INTERNALS: unique symbol = Symbol('timescales.journal');

export function journalInternals(j: Journal): JournalInternals | null {
  return (j as { [JOURNAL_INTERNALS]?: JournalInternals })[JOURNAL_INTERNALS] ?? null;
}

/** `put` with a stale `expectedVersion`: re-read the record and apply the change again. */
export function versionConflict(id: string, expected: number, actual: number): TimescalesError {
  return new TimescalesError({
    kind: 'storage',
    code: 'version_conflict',
    message: `record ${id} is at version ${actual}, not ${expected}`,
    details: { id, expected, actual },
  });
}

export function storageError(code: string, message: string, cause?: unknown): TimescalesError {
  return new TimescalesError({ kind: 'storage', code, message, cause });
}

/**
 * The outbox a record implies: the exact submission bytes of every
 * participation that holds no verified promise yet and was not refused.
 * Writing a record rewrites its outbox in the same transaction.
 */
export function outboxOf(r: OrderRecord): { epoch: bigint; submission: Uint8Array }[] {
  const out: { epoch: bigint; submission: Uint8Array }[] = [];
  for (const p of r.epochs.values()) {
    if (p.promise === null && (p.state.kind === 'sealed' || p.state.kind === 'parked')) {
      out.push({ epoch: p.epoch, submission: p.submission });
    }
  }
  return out.sort((a, b) => (a.epoch < b.epoch ? -1 : a.epoch > b.epoch ? 1 : 0));
}

/**
 * Opens the wallet's journal. The database name derives from
 * H(device salt || cluster || program || wallet). Without IndexedDB or
 * WebCrypto it falls back to memory: details are then lost when the tab
 * closes, which the app must say.
 */
export async function openJournal(a: {
  cluster: string;
  program: Address;
  wallet: Address;
}): Promise<Journal> {
  const hasIdb = typeof indexedDB !== 'undefined';
  const hasSubtle = typeof globalThis.crypto?.subtle?.generateKey === 'function';
  if (hasIdb && hasSubtle) {
    try {
      return await openIndexedDbJournal(a);
    } catch (e) {
      if (!(e instanceof TimescalesError) || e.code !== 'indexeddb_unavailable') throw e;
    }
  }
  return createMemoryJournal(a);
}
