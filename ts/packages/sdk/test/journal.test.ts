// The local journal on fake-indexeddb: encryption at rest, versioned
// writes and the outbox, the passphrase export, the memory fallback, and a
// failed write blocking an order before anything is sent.
import 'fake-indexeddb/auto';
import type { Address } from '@solana/kit';
import { openDB } from 'idb';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { ServerClock, TimescalesStream } from '../src/api/index.js';
import { b58, equal, hex, utf8 } from '../src/core/index.js';
import {
  exportJournal,
  importJournal,
  openJournal,
  requestPersistence,
  type Journal,
} from '../src/journal/index.js';
import { generateDeviceKey, openRecord, recordAad, sealRecord } from '../src/journal/crypto.js';
import { journalInternals } from '../src/journal/journal.js';
import { DEVICE_DB, JOURNAL_DB_PREFIX, journalDatabaseName } from '../src/journal/naming.js';
import { OrderService, type OrderRecord } from '../src/orders/index.js';
import type { OrderServiceDeps } from '../src/orders/service.js';
import { createTestRng, createTestWallet } from '../src/testing/index.js';
import { createFakeNode } from '../src/testing/node.js';
import { evidenceRecord } from '../src/verify/evidence.js';
import { TradingSession } from '../src/wallet/index.js';

const PROGRAM = b58.encode(new Uint8Array(32).fill(3)) as Address;
let counter = 0;

function wallet(): Address {
  counter++;
  return b58.encode(new Uint8Array(32).fill(counter + 0x40)) as Address;
}

function record(id: string, market: Address, c: number): OrderRecord {
  return {
    id,
    version: 0,
    market,
    body: {
      kind: 'place',
      order: {
        market: 7n,
        trader: new Uint8Array(32).fill(1),
        nonce: 2n ** 63n + 5n,
        side: 1,
        role: 0,
        kind: 0,
        limit: 1234n,
        quantity: 9n,
        validFrom: 3n,
        expiresAt: 4n,
      },
    },
    salt: new Uint8Array(32).fill(0xa5),
    signature: new Uint8Array(64).fill(0x5a),
    commitment: new Uint8Array(32).fill(c),
    state: { kind: 'working' },
    epochs: new Map([
      [
        3n,
        {
          epoch: 3n,
          envelopeDigest: new Uint8Array(32).fill(4),
          submission: new Uint8Array(386).fill(6),
          promise: null,
          relayAtSubmission: PROGRAM,
          state: { kind: 'sealed' },
        },
      ],
    ]),
    filled: 0n,
    fills: [],
    history: [{ atMs: 1, kind: 'prepared' }],
    evidence: [],
  };
}

/** The journal database of `w` on this device. */
async function dbName(w: Address): Promise<string> {
  const device = await openDB(DEVICE_DB);
  const salt = (await device.get('device', 'salt')) as Uint8Array;
  device.close();
  return journalDatabaseName(salt, 'devnet', PROGRAM, w);
}

async function fresh(): Promise<{ j: Journal; w: Address }> {
  const w = wallet();
  return { j: await openJournal({ cluster: 'devnet', program: PROGRAM, wallet: w }), w };
}

afterEach(() => {
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

describe('journal', () => {
  it('round-trips records, bigints, bytes and maps through encryption', async () => {
    const { j, w } = await fresh();
    expect(j.available).toBe('indexeddb');
    const r = record('a1', w, 1);
    expect(await j.put(r, 0)).toBe(1);
    expect(await j.get('a1')).toEqual({ ...r, version: 1 });
    j.hide();
    expect(await j.get('a1')).toEqual({ ...r, version: 1 });
    expect((await j.list({ market: w })).map((x) => x.id)).toEqual(['a1']);
    expect(await j.list({ market: PROGRAM })).toEqual([]);
  });

  it('keeps nothing but random ids and versions in the clear', async () => {
    const { j, w } = await fresh();
    await j.put(record('b1', w, 0x77), 0);
    const names = (await indexedDB.databases()).map((d) => d.name ?? '');
    expect(names).toContain(DEVICE_DB);
    for (const name of names) {
      expect(name).not.toContain(w);
      expect(name).not.toContain(hex.encode(b58.decode(w, 32)).slice(0, 16));
    }
    const name = await dbName(w);
    expect(names).toContain(name);
    expect(name.slice(JOURNAL_DB_PREFIX.length)).toMatch(/^[0-9a-f]{16}$/);
    const db = await openDB(name);
    const rows = (await db.getAll('orders')) as Record<string, unknown>[];
    db.close();
    const row = rows.find((x) => x.id === 'b1')!;
    expect(Object.keys(row).sort()).toEqual(['ct', 'id', 'iv', 'version']);
    const ct = row.ct as Uint8Array;
    const needle = new Uint8Array(32).fill(0x77);
    for (let i = 0; i + 32 <= ct.length; i++)
      expect(equal(ct.subarray(i, i + 32), needle)).toBe(false);
  });

  it('names databases from a device salt, never from the wallet', () => {
    const salt = new Uint8Array(16).fill(9);
    const w = wallet();
    const a = journalDatabaseName(salt, 'devnet', PROGRAM, w);
    expect(a).not.toContain(w);
    expect(journalDatabaseName(new Uint8Array(16).fill(8), 'devnet', PROGRAM, w)).not.toBe(a);
    expect(journalDatabaseName(salt, 'localnet', PROGRAM, w)).not.toBe(a);
    expect(() => journalDatabaseName(new Uint8Array(15), 'devnet', PROGRAM, w)).toThrow();
  });

  it('refuses ciphertexts moved to another store, record or version (AAD)', async () => {
    const key = await generateDeviceKey();
    expect(key.extractable).toBe(false);
    const plain = utf8('{"x":1}');
    const sealed = await sealRecord(key, 'orders', 'id1', 3, plain);
    expect(await openRecord(key, 'orders', 'id1', 3, sealed.iv, sealed.ct)).toEqual(plain);
    for (const [store, id, version] of [
      ['outbox', 'id1', 3],
      ['orders', 'id2', 3],
      ['orders', 'id1', 4],
    ] as const) {
      await expect(openRecord(key, store, id, version, sealed.iv, sealed.ct)).rejects.toThrow();
    }
    expect(recordAad('orders', 'a', 1)).not.toEqual(recordAad('order', 'sa', 1));

    // Swapping two rows in the database: neither decrypts any more.
    const { j, w } = await fresh();
    await j.put(record('s1', w, 1), 0);
    await j.put(record('s2', w, 2), 0);
    const db = await openDB(await dbName(w));
    const r1 = (await db.get('orders', 's1')) as { iv: Uint8Array; ct: Uint8Array };
    const r2 = (await db.get('orders', 's2')) as { iv: Uint8Array; ct: Uint8Array };
    await db.put('orders', { ...r1, iv: r2.iv, ct: r2.ct });
    await db.put('orders', { ...r2, iv: r1.iv, ct: r1.ct });
    db.close();
    j.hide();
    await expect(j.get('s1')).rejects.toThrow();
    expect(await j.list()).toEqual([]);
  });

  it('refuses a stale version and rewrites the outbox with each record', async () => {
    const { j, w } = await fresh();
    const r = record('v1', w, 1);
    await j.put(r, 0);
    await expect(j.put(r, 0)).rejects.toMatchObject({ kind: 'storage', code: 'version_conflict' });
    const outbox = await j.outbox();
    expect(outbox.map((o) => [o.orderId, o.epoch])).toEqual([['v1', 3n]]);
    expect(outbox[0]!.submission).toEqual(new Uint8Array(386).fill(6));
    const created = outbox[0]!.createdAtMs;
    const p = r.epochs.get(3n)!;
    const promised = { ...r, epochs: new Map([[3n, { ...p, promise: new Uint8Array(201) }]]) };
    expect(await j.put(promised, 1)).toBe(2);
    expect(await j.outbox()).toEqual([]);
    expect(await j.put(r, 2)).toBe(3);
    expect((await j.outbox())[0]!.createdAtMs).toBeGreaterThanOrEqual(created);
  });

  it('keeps evidence and a non-extractable session key', async () => {
    const { j, w } = await fresh();
    const e = evidenceRecord('exclusion', w, 3n, utf8('{"kind":"exclusion"}'), 5);
    await j.putEvidence(e);
    const internals = journalInternals(j)!;
    expect(await internals.listEvidence()).toEqual([e]);
    const pair = (await crypto.subtle.generateKey({ name: 'Ed25519' }, false, [
      'sign',
    ])) as CryptoKeyPair;
    await internals.saveSession({
      wallet: w,
      sessionKey: new Uint8Array(32).fill(1),
      privateKey: pair.privateKey,
      expiresAtMs: 99,
      market: null,
      lastTs: 7,
    });
    const s = await internals.loadSession();
    expect(s?.privateKey.extractable).toBe(false);
    expect(s?.lastTs).toBe(7);
    const sig = await crypto.subtle.sign({ name: 'Ed25519' }, s!.privateKey, new Uint8Array(1));
    expect(sig.byteLength).toBe(64);
  });

  it('wipes its database', async () => {
    const { j, w } = await fresh();
    await j.put(record('w1', w, 1), 0);
    await j.wipe();
    const again = await openJournal({ cluster: 'devnet', program: PROGRAM, wallet: w });
    expect(await again.list()).toEqual([]);
  });

  it('falls back to memory without IndexedDB', async () => {
    vi.stubGlobal('indexedDB', undefined);
    const w = wallet();
    const j = await openJournal({ cluster: 'devnet', program: PROGRAM, wallet: w });
    expect(j.available).toBe('memory');
    expect(j.persisted).toBe(false);
    const r = record('m1', w, 1);
    expect(await j.put(r, 0)).toBe(1);
    await expect(j.put(r, 0)).rejects.toMatchObject({ code: 'version_conflict' });
    const back = (await j.get('m1'))!;
    back.epochs.clear();
    expect((await j.get('m1'))!.epochs.size).toBe(1);
    expect(await j.outbox()).toHaveLength(1);
  });

  it('asks the browser to persist storage', async () => {
    vi.stubGlobal('navigator', { storage: { persist: () => Promise.resolve(true) } });
    expect(await requestPersistence()).toBe(true);
    vi.stubGlobal('navigator', { storage: { persist: () => Promise.reject(new Error('no')) } });
    expect(await requestPersistence()).toBe(false);
    vi.stubGlobal('navigator', {});
    expect(await requestPersistence()).toBe(false);
  });
});

describe('journal export', () => {
  const PASS = 'correct horse battery staple';

  it('round-trips through the passphrase export and merges by commitment', async () => {
    const { j, w } = await fresh();
    await j.put(record('e1', w, 1), 0);
    await j.put(record('e2', w, 2), 0);
    await j.putEvidence(evidenceRecord('refusal', w, 3n, utf8('{}'), 1));
    const bundle = await exportJournal(j, PASS, { log2N: 15 });
    expect(new TextDecoder().decode(bundle.subarray(0, 6))).toBe('TSJNL2');
    expect([...bundle.subarray(6, 10)]).toEqual([2, 15, 8, 1]);

    await j.wipe();
    const into = await openJournal({ cluster: 'devnet', program: PROGRAM, wallet: w });
    expect(await importJournal(bundle, PASS, into)).toEqual({ imported: 2, skipped: 0 });
    const back = await into.list();
    expect(back.map((r) => hex.encode(r.commitment)).sort()).toEqual(
      [record('', w, 1), record('', w, 2)].map((r) => hex.encode(r.commitment)),
    );
    expect(await journalInternals(into)!.listEvidence()).toHaveLength(1);
    expect(await importJournal(bundle, PASS, into)).toEqual({ imported: 0, skipped: 2 });
  });

  it('refuses a wrong passphrase, a tampered header and another wallet', async () => {
    const { j, w } = await fresh();
    await j.put(record('t1', w, 1), 0);
    const bundle = await exportJournal(j, PASS, { log2N: 15 });
    await expect(importJournal(bundle, `${PASS}!`, j)).rejects.toMatchObject({
      code: 'bad_passphrase',
    });
    const tampered = bundle.slice();
    tampered[12]! ^= 1; // inside the salt: authenticated as AAD
    await expect(importJournal(tampered, PASS, j)).rejects.toMatchObject({
      code: 'bad_passphrase',
    });
    const other = await openJournal({ cluster: 'devnet', program: PROGRAM, wallet: wallet() });
    await expect(importJournal(bundle, PASS, other)).rejects.toMatchObject({
      code: 'other_wallet',
    });
    await expect(exportJournal(j, 'short')).rejects.toMatchObject({ code: 'passphrase_too_short' });
  });

  it('refuses unsupported key-derivation parameters before running scrypt', async () => {
    const { j, w } = await fresh();
    await j.put(record('k1', w, 1), 0);
    const bundle = await exportJournal(j, PASS, { log2N: 15 });
    // log2N = 30 would need 128 GiB of memory: a refusal here proves scrypt never ran.
    for (const [at, value] of [
      [7, 30],
      [7, 14],
      [8, 9],
      [9, 2],
      [6, 3],
    ] as const) {
      const bad = bundle.slice();
      bad[at] = value;
      await expect(importJournal(bad, PASS, j)).rejects.toMatchObject({
        code: 'unsupported_export',
      });
    }
    await expect(importJournal(bundle.subarray(0, 40), PASS, j)).rejects.toMatchObject({
      code: 'unsupported_export',
    });
  });
});

describe('a failed journal write', () => {
  it('blocks sealing: nothing is sent', async () => {
    const rng = createTestRng(new Uint8Array([0xfa]));
    const node = createFakeNode({ seed: rng.bytes(32) });
    const w = createTestWallet({ seed: rng.bytes(32) });
    node.fund(w.address, 10n ** 12n, 10n ** 12n);
    const clock = new ServerClock();
    await clock.sync(node.api);
    const session = await TradingSession.open({
      api: node.api,
      wallet: w,
      info: await node.api.info(),
      clock,
      market: node.market,
    });
    const journal = await openJournal({
      cluster: 'devnet',
      program: node.program,
      wallet: w.address,
    });
    const stream = new TimescalesStream({ url: node.streamUrl, WebSocketImpl: node.WebSocket });
    const deps: OrderServiceDeps = {
      api: node.api,
      rpc: node.rpc,
      journal,
      stream,
      clock,
      pins: node.pins,
    };
    const svc = new OrderService(deps);
    try {
      await svc.start(w, session);
      await svc.context(node.market);
      const p = svc.prepare({
        market: node.market,
        side: 0,
        role: 0,
        kind: 0,
        limitTick: node.band.reference,
        quantityLots: 1n,
        lifetimeEpochs: 1,
      });
      vi.spyOn(IDBObjectStore.prototype, 'put').mockImplementation(() => {
        throw new DOMException('the disk is full', 'QuotaExceededError');
      });
      await expect(svc.submit(p)).rejects.toMatchObject({
        kind: 'storage',
        code: 'quota_exceeded',
      });
      expect(w.calls.filter((c) => c.method === 'signMessage')).toEqual([]);
      expect(node.submitted).toEqual([]);
    } finally {
      svc.dispose();
      stream.close();
    }
  });
});
