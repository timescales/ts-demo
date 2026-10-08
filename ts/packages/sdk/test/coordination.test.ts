// Two tabs of one wallet: two OrderServices on one IndexedDB (fake-indexeddb),
// coordinated by Web Locks and BroadcastChannel (Node 24 provides both).
import 'fake-indexeddb/auto';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { ServerClock, TimescalesStream } from '../src/api/index.js';
import { openJournal, type Journal } from '../src/journal/index.js';
import { OrderService, reduce, type OrderEvent, type OrderRecord } from '../src/orders/index.js';
import type { OrderServiceDeps } from '../src/orders/service.js';
import { updateRecord } from '../src/orders/store.js';
import { createTestRng, createTestWallet, type TestWallet } from '../src/testing/index.js';
import { createFakeNode, type FakeNode } from '../src/testing/node.js';
import { TradingSession } from '../src/wallet/index.js';

const cleanups: (() => void)[] = [];
afterEach(() => {
  for (const f of cleanups.splice(0).reverse()) f();
});

let counter = 0;

interface Tab {
  svc: OrderService;
  wallet: TestWallet;
  journal: Journal;
  deps: OrderServiceDeps;
}

async function twoTabs(): Promise<{ node: FakeNode; a: Tab; b: Tab; session: TradingSession }> {
  counter++;
  const rng = createTestRng(new Uint8Array([counter, 0xc0]));
  const node = createFakeNode({ seed: rng.bytes(32) });
  const seed = rng.bytes(32);
  const clock = new ServerClock();
  await clock.sync(node.api);
  const first = createTestWallet({ seed });
  node.fund(first.address, 10n ** 12n, 10n ** 12n);
  const session = await TradingSession.open({
    api: node.api,
    wallet: first,
    info: await node.api.info(),
    clock,
    market: node.market,
  });
  const tab = async (wallet: TestWallet): Promise<Tab> => {
    const journal = await openJournal({
      cluster: 'devnet',
      program: node.program,
      wallet: wallet.address,
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
    cleanups.push(() => {
      svc.dispose();
      stream.close();
    });
    return { svc, wallet, journal, deps };
  };
  const a = await tab(first);
  const b = await tab(createTestWallet({ seed }));
  return { node, a, b, session };
}

function list(svc: OrderService): readonly OrderRecord[] {
  let out: readonly OrderRecord[] = [];
  svc.subscribe((x) => (out = x))();
  return out;
}

function batchPosts(node: FakeNode): number {
  return node.fake.requests.filter(
    (r) => r.method === 'POST' && r.path.endsWith('/submissions/batch'),
  ).length;
}

describe('two tabs of one wallet', () => {
  it('elect one leader, and a follower takes over when the leader goes away', async () => {
    const { node, a, b, session } = await twoTabs();
    expect(await a.svc.start(a.wallet, session)).toEqual({ role: 'leader' });
    expect(await b.svc.start(b.wallet, session)).toEqual({ role: 'follower' });
    await a.svc.context(node.market);
    const r = await a.svc.submit(
      a.svc.prepare({
        market: node.market,
        side: 0,
        role: 0,
        kind: 0,
        limitTick: node.band.reference,
        quantityLots: 1n,
        lifetimeEpochs: 1,
      }),
    );
    // The follower mirrors the leader's records.
    await vi.waitFor(() => expect(list(b.svc).map((x) => x.id)).toEqual([r.id]));
    const topic = `market:${node.market}`;
    await vi.waitFor(() => expect(node.subscribers(topic)).toBe(1));
    a.svc.dispose();
    expect(node.subscribers(topic)).toBe(0);
    // The follower now leads: it subscribes to the market and moves the order.
    await vi.waitFor(() => expect(node.subscribers(topic)).toBe(1));
    const n = node.open;
    node.closeEpoch();
    await vi.waitFor(() =>
      expect(
        list(b.svc)
          .find((x) => x.id === r.id)
          ?.epochs.get(n)?.state.kind,
      ).toBe('locked'),
    );
  });

  it('forward a follower’s order to the leader, which seals and submits it once', async () => {
    const { node, a, b, session } = await twoTabs();
    await a.svc.start(a.wallet, session);
    await b.svc.start(b.wallet, session);
    await b.svc.context(node.market);
    const p = b.svc.prepare({
      market: node.market,
      side: 1,
      role: 0,
      kind: 0,
      limitTick: node.band.reference,
      quantityLots: 2n,
      lifetimeEpochs: 2,
    });
    expect(p.blockers).toEqual([]);
    const r = await b.svc.submit(p);
    expect(r.state.kind).toBe('working');
    // The follower's wallet signed. The leader sealed and posted.
    expect(b.wallet.calls.map((c) => c.method)).toEqual(['signMessage']);
    expect(a.wallet.calls.filter((c) => c.method === 'signMessage')).toEqual([]);
    expect(batchPosts(node)).toBe(1);
    expect(node.held(node.open).length + node.held(node.open + 1n).length).toBe(2);
    await vi.waitFor(() =>
      expect(list(a.svc).find((x) => x.id === r.id)?.state.kind).toBe('working'),
    );

    const cancelled = await b.svc.cancel(r);
    expect(cancelled.state).toEqual({ kind: 'cancel_pending', epoch: node.open });
    expect(b.wallet.calls.map((c) => c.method)).toEqual(['signMessage', 'signMessage']);
    expect(batchPosts(node)).toBe(2);
  });

  it('lose no update when both tabs write one record at once (version check)', async () => {
    const { node, a, b, session } = await twoTabs();
    await a.svc.start(a.wallet, session);
    await a.svc.context(node.market);
    const r = await a.svc.submit(
      a.svc.prepare({
        market: node.market,
        side: 0,
        role: 0,
        kind: 0,
        limitTick: node.band.reference,
        quantityLots: 1n,
        lifetimeEpochs: 1,
      }),
    );
    a.svc.dispose();
    const stale = (await a.journal.get(r.id))!;
    const e1: OrderEvent = { atMs: 1, kind: 'governance_applied', change: 'set_relay' };
    const e2: OrderEvent = { atMs: 2, kind: 'governance_applied', change: 'set_timings' };
    // A blind write with a stale version is refused.
    await a.journal.put(reduce(stale, e1), stale.version);
    await expect(b.journal.put(reduce(stale, e2), stale.version)).rejects.toMatchObject({
      code: 'version_conflict',
    });
    // Both tabs' read-modify-write loops land, in some order.
    const results = await Promise.all([
      updateRecord(a.journal, r.id, (x) => reduce(x, { ...e1, atMs: 3 })),
      updateRecord(b.journal, r.id, (x) => reduce(x, { ...e2, atMs: 4 })),
    ]);
    expect(results.every((x) => x.written)).toBe(true);
    const final = (await b.journal.get(r.id))!;
    expect(final.version).toBe(stale.version + 3);
    const changes = final.history.flatMap((h) =>
      h.kind === 'governance_applied' ? [`${h.change}@${h.atMs}`] : [],
    );
    expect(changes.sort()).toEqual(['set_relay@1', 'set_relay@3', 'set_timings@4']);
  });
});
