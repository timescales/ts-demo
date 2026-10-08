import type { Address } from '@solana/kit';
import { deleteDB, openDB, type IDBPDatabase } from 'idb';
import { randomBytes } from '../core/crypto/random.js';
import { TimescalesError } from '../errors.js';
import type { OrderRecord, OutboxItem } from '../orders/model.js';
import type { EvidenceRecord } from '../verify/evidence.js';
import { generateDeviceKey, openRecord, sealRecord } from './crypto.js';
import { decodeJson, encodeJson } from './json.js';
import {
  JOURNAL_INTERNALS,
  outboxOf,
  storageError,
  versionConflict,
  type Journal,
  type JournalInternals,
  type StoredSession,
} from './journal.js';
import { DEVICE_DB, journalDatabaseName } from './naming.js';
import { persistedState } from './persist.js';

const SCHEMA_VERSION = 2;
const DB_VERSION = 1;
const STORES = ['orders', 'outbox', 'evidence', 'activity'] as const;

/** A sealed row: only a random id and a version are in the clear. */
interface SealedRow {
  id: string;
  version: number;
  iv: Uint8Array;
  ct: Uint8Array;
}

interface SessionRow {
  privateKey: CryptoKey;
  iv: Uint8Array;
  ct: Uint8Array;
}

type OutboxEntry = { epoch: bigint; submission: Uint8Array; createdAtMs: number };

function writeError(e: unknown): TimescalesError {
  if (e instanceof TimescalesError) return e;
  const name = (e as { name?: unknown } | null)?.name;
  if (name === 'QuotaExceededError') {
    return storageError('quota_exceeded', 'this device is out of storage, nothing was sent', e);
  }
  return storageError('write_failed', 'the journal could not be written, nothing was sent', e);
}

async function open<T>(f: () => Promise<T>): Promise<T> {
  try {
    return await f();
  } catch (e) {
    throw storageError('indexeddb_unavailable', 'IndexedDB cannot be opened here', e);
  }
}

/** The 16 random bytes in `timescales-device` that keep wallets out of database names. */
async function deviceSalt(): Promise<Uint8Array> {
  const db = await open(() =>
    openDB(DEVICE_DB, 1, {
      upgrade(d) {
        d.createObjectStore('device');
      },
    }),
  );
  try {
    const tx = db.transaction('device', 'readwrite');
    let salt = (await tx.store.get('salt')) as Uint8Array | undefined;
    if (salt === undefined) {
      salt = randomBytes(16);
      await tx.store.put(salt, 'salt');
    }
    await tx.done;
    return salt;
  } finally {
    db.close();
  }
}

async function deviceKey(db: IDBPDatabase): Promise<CryptoKey> {
  const existing = (await db.get('meta', 'deviceKey')) as CryptoKey | undefined;
  if (existing !== undefined) return existing;
  let fresh: CryptoKey;
  try {
    fresh = await generateDeviceKey();
  } catch (e) {
    throw storageError('indexeddb_unavailable', 'WebCrypto AES-GCM is not available here', e);
  }
  // Another tab may have stored a key meanwhile. The first one stored wins.
  const tx = db.transaction('meta', 'readwrite');
  const raced = (await tx.store.get('deviceKey')) as CryptoKey | undefined;
  if (raced === undefined) {
    await tx.store.put(fresh, 'deviceKey');
    await tx.store.put(SCHEMA_VERSION, 'schema');
  }
  await tx.done;
  return raced ?? fresh;
}

export async function openIndexedDbJournal(a: {
  cluster: string;
  program: Address;
  wallet: Address;
}): Promise<Journal> {
  const name = journalDatabaseName(await deviceSalt(), a.cluster, a.program, a.wallet);
  const db = await open(() =>
    openDB(name, DB_VERSION, {
      upgrade(d) {
        d.createObjectStore('meta');
        d.createObjectStore('session');
        for (const s of STORES) d.createObjectStore(s, { keyPath: 'id' });
      },
    }),
  );
  const schema = (await db.get('meta', 'schema')) as number | undefined;
  if (schema !== undefined && schema !== SCHEMA_VERSION) {
    db.close();
    throw storageError('future_schema', `journal schema ${schema} is not supported here`);
  }
  const key = await deviceKey(db);
  const persisted = await persistedState();
  // Decrypted records, dropped by hide.
  const cache = new Map<string, { version: number; record: OrderRecord }>();

  async function openRow<T>(store: string, row: SealedRow): Promise<T> {
    return decodeJson(await openRecord(key, store, row.id, row.version, row.iv, row.ct)) as T;
  }

  async function seal(
    store: string,
    id: string,
    version: number,
    value: unknown,
  ): Promise<SealedRow> {
    return { id, version, ...(await sealRecord(key, store, id, version, encodeJson(value))) };
  }

  async function readOrder(row: SealedRow): Promise<OrderRecord> {
    const hit = cache.get(row.id);
    if (hit !== undefined && hit.version === row.version) return structuredClone(hit.record);
    const record = await openRow<OrderRecord>('orders', row);
    if (record.id !== row.id || record.version !== row.version) {
      throw storageError('corrupt', `record ${row.id} does not match its row`);
    }
    cache.set(row.id, { version: row.version, record });
    return structuredClone(record);
  }

  async function currentOutbox(id: string): Promise<OutboxEntry[]> {
    const row = (await db.get('outbox', id)) as SealedRow | undefined;
    if (row === undefined) return [];
    try {
      return await openRow<OutboxEntry[]>('outbox', row);
    } catch {
      return [];
    }
  }

  const internals: JournalInternals = {
    scope: { cluster: a.cluster, program: a.program, wallet: a.wallet },
    async listEvidence() {
      const rows = (await db.getAll('evidence')) as SealedRow[];
      const out: EvidenceRecord[] = [];
      for (const row of rows) {
        try {
          out.push(await openRow<EvidenceRecord>('evidence', row));
        } catch {
          // A record this device cannot decrypt is skipped ("can't be read").
        }
      }
      return out;
    },
    async saveSession(s: StoredSession) {
      const { privateKey, ...meta } = s;
      const sealed = await sealRecord(key, 'session', 'current', 1, encodeJson(meta));
      try {
        await db.put('session', { privateKey, ...sealed } satisfies SessionRow, 'current');
      } catch (e) {
        throw writeError(e);
      }
    },
    async loadSession() {
      const row = (await db.get('session', 'current')) as SessionRow | undefined;
      if (row === undefined) return undefined;
      try {
        const meta = decodeJson(
          await openRecord(key, 'session', 'current', 1, row.iv, row.ct),
        ) as Omit<StoredSession, 'privateKey'>;
        return { ...meta, privateKey: row.privateKey };
      } catch {
        return undefined;
      }
    },
    async deleteSession() {
      await db.delete('session', 'current');
    },
    close() {
      cache.clear();
      db.close();
    },
  };

  const journal: Journal & { [JOURNAL_INTERNALS]: JournalInternals } = {
    available: 'indexeddb',
    persisted,
    [JOURNAL_INTERNALS]: internals,
    async put(r, expectedVersion) {
      const version = expectedVersion + 1;
      const record: OrderRecord = { ...r, version };
      let sealed: SealedRow;
      let outbox: SealedRow | null = null;
      try {
        sealed = await seal('orders', r.id, version, record);
        const known = new Map((await currentOutbox(r.id)).map((e) => [e.epoch, e.createdAtMs]));
        const items: OutboxEntry[] = outboxOf(record).map((o) => ({
          ...o,
          createdAtMs: known.get(o.epoch) ?? Date.now(),
        }));
        if (items.length > 0) outbox = await seal('outbox', r.id, version, items);
      } catch (e) {
        throw writeError(e);
      }
      try {
        const tx = db.transaction(['orders', 'outbox'], 'readwrite');
        const done = tx.done;
        done.catch(() => undefined);
        const current = (await tx.objectStore('orders').get(r.id)) as SealedRow | undefined;
        const actual = current?.version ?? 0;
        if (actual !== expectedVersion) {
          tx.abort();
          throw versionConflict(r.id, expectedVersion, actual);
        }
        await tx.objectStore('orders').put(sealed);
        if (outbox !== null) await tx.objectStore('outbox').put(outbox);
        else await tx.objectStore('outbox').delete(r.id);
        await done;
      } catch (e) {
        throw writeError(e);
      }
      cache.set(r.id, { version, record: structuredClone(record) });
      return version;
    },
    async get(id) {
      const row = (await db.get('orders', id)) as SealedRow | undefined;
      return row === undefined ? undefined : readOrder(row);
    },
    async list(f) {
      const rows = (await db.getAll('orders')) as SealedRow[];
      const out: OrderRecord[] = [];
      for (const row of rows) {
        let r: OrderRecord;
        try {
          r = await readOrder(row);
        } catch {
          continue;
        }
        if (f?.market === undefined || r.market === f.market) out.push(r);
      }
      return out;
    },
    async putEvidence(e) {
      try {
        await db.put('evidence', await seal('evidence', e.id, 1, e));
      } catch (err) {
        throw writeError(err);
      }
    },
    async outbox() {
      const rows = (await db.getAll('outbox')) as SealedRow[];
      const out: OutboxItem[] = [];
      for (const row of rows) {
        let items: OutboxEntry[];
        try {
          items = await openRow<OutboxEntry[]>('outbox', row);
        } catch {
          continue;
        }
        for (const i of items) {
          out.push({
            orderId: row.id,
            epoch: i.epoch,
            submission: i.submission,
            createdAtMs: i.createdAtMs,
          });
        }
      }
      return out;
    },
    hide() {
      cache.clear();
    },
    async wipe() {
      cache.clear();
      db.close();
      await deleteDB(name);
    },
  };
  return journal;
}
