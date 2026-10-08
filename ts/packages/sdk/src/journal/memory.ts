import type { Address } from '@solana/kit';
import type { OrderRecord, OutboxItem } from '../orders/model.js';
import type { EvidenceRecord } from '../verify/evidence.js';
import {
  JOURNAL_INTERNALS,
  outboxOf,
  versionConflict,
  type Journal,
  type JournalInternals,
  type StoredSession,
} from './journal.js';

/**
 * Fallback when IndexedDB or WebCrypto is unavailable. Details are lost when
 * the tab closes. Same versioning and outbox rules as the IndexedDB journal.
 * Values are stored as copies, never shared with the caller.
 */
export function createMemoryJournal(scope: {
  cluster: string;
  program: Address;
  wallet: Address;
}): Journal {
  const orders = new Map<string, OrderRecord>();
  const outbox = new Map<
    string,
    { epoch: bigint; submission: Uint8Array; createdAtMs: number }[]
  >();
  const evidence = new Map<string, EvidenceRecord>();
  let session: StoredSession | undefined;

  const internals: JournalInternals = {
    scope,
    listEvidence: () => Promise.resolve([...evidence.values()].map((e) => structuredClone(e))),
    saveSession(s) {
      session = s;
      return Promise.resolve();
    },
    loadSession: () => Promise.resolve(session),
    deleteSession() {
      session = undefined;
      return Promise.resolve();
    },
    close() {
      // Nothing to release.
    },
  };

  const journal: Journal & { [JOURNAL_INTERNALS]: JournalInternals } = {
    available: 'memory',
    persisted: false,
    [JOURNAL_INTERNALS]: internals,
    async put(r, expectedVersion) {
      const actual = orders.get(r.id)?.version ?? 0;
      if (actual !== expectedVersion) throw versionConflict(r.id, expectedVersion, actual);
      const version = expectedVersion + 1;
      const record = structuredClone({ ...r, version });
      const known = new Map((outbox.get(r.id) ?? []).map((e) => [e.epoch, e.createdAtMs]));
      const items = outboxOf(record).map((o) => ({
        ...o,
        createdAtMs: known.get(o.epoch) ?? Date.now(),
      }));
      orders.set(r.id, record);
      if (items.length > 0) outbox.set(r.id, items);
      else outbox.delete(r.id);
      return Promise.resolve(version);
    },
    get(id) {
      const r = orders.get(id);
      return Promise.resolve(r === undefined ? undefined : structuredClone(r));
    },
    list(f) {
      return Promise.resolve(
        [...orders.values()]
          .filter((r) => f?.market === undefined || r.market === f.market)
          .map((r) => structuredClone(r)),
      );
    },
    putEvidence(e) {
      evidence.set(e.id, structuredClone(e));
      return Promise.resolve();
    },
    outbox() {
      const out: OutboxItem[] = [];
      for (const [orderId, items] of outbox) {
        for (const i of items) out.push({ orderId, ...structuredClone(i) });
      }
      return Promise.resolve(out);
    },
    hide() {
      // Nothing is cached apart from the records themselves, which must stay.
    },
    wipe() {
      orders.clear();
      outbox.clear();
      evidence.clear();
      session = undefined;
      return Promise.resolve();
    },
  };
  return journal;
}
