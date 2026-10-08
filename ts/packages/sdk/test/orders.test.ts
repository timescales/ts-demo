// The order service against the in-memory node (src/testing/node.ts): real
// keys, promises, batches, receipts and artifacts, so every verifier check runs.
import 'fake-indexeddb/auto';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { ServerClock, TimescalesStream, type TimescalesApi } from '../src/api/index.js';
import {
  DecodeError,
  b58,
  b64,
  decodeArtifacts,
  decodeEnvelope,
  decodeSubmission,
  ed25519Sign,
  encodeArtifacts,
  encodeBalanceSheet,
  encodePromiseV2,
  envelopeDigest,
  equal,
  fromUtf8,
  hex,
  promiseV2Digest,
} from '../src/core/index.js';
import { TimescalesError } from '../src/errors.js';
import { openJournal, type Journal } from '../src/journal/index.js';
import { journalInternals } from '../src/journal/journal.js';
import {
  OrderService,
  badge,
  lifetimePresets,
  type OrderDraft,
  type OrderRecord,
} from '../src/orders/index.js';
import type { OrderServiceDeps } from '../src/orders/service.js';
import {
  createTestRng,
  createTestWallet,
  testMarketParams,
  type TestWallet,
  type TestWalletBehaviour,
} from '../src/testing/index.js';
import {
  createFakeNode,
  type FakeFill,
  type FakeNode,
  type FakeNodeOptions,
} from '../src/testing/node.js';
import { batchPda, traderPda, type TimescalesRpc } from '../src/solana/index.js';
import { TradingSession } from '../src/wallet/index.js';
import { rememberSession } from '../src/wallet/session.js';

const cleanups: (() => void)[] = [];
afterEach(() => {
  for (const f of cleanups.splice(0)) f();
});

let counter = 0;

interface Setup {
  node: FakeNode;
  seed: Uint8Array;
  wallet: TestWallet;
  session: TradingSession;
  svc: OrderService;
  journal: Journal;
  clock: ServerClock;
  deps: OrderServiceDeps;
}

async function setup(
  o: FakeNodeOptions & { behaviour?: TestWalletBehaviour; lateMs?: number; funded?: boolean } = {},
): Promise<Setup> {
  counter++;
  const rng = createTestRng(new Uint8Array([counter, 0x0d]));
  const node = createFakeNode({ seed: rng.bytes(32), ...o });
  const seed = rng.bytes(32);
  const wallet = createTestWallet({
    seed,
    behaviour: o.behaviour ?? 'honest',
    ...(o.lateMs !== undefined ? { lateMs: o.lateMs } : {}),
  });
  if (o.funded !== false) node.fund(wallet.address, 10n ** 12n, 10n ** 12n);
  const clock = new ServerClock();
  await clock.sync(node.api);
  // The session grant is signed by an honest wallet holding the same key, so
  // a misbehaving wallet's quirks show only where a test exercises them.
  const session = await TradingSession.open({
    api: node.api,
    wallet: createTestWallet({ seed }),
    info: await node.api.info(),
    clock,
    market: node.market,
  });
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
  await svc.start(wallet, session);
  await svc.context(node.market);
  return { node, seed, wallet, session, svc, journal, clock, deps };
}

function list(svc: OrderService): readonly OrderRecord[] {
  let out: readonly OrderRecord[] = [];
  svc.subscribe((x) => (out = x))();
  return out;
}

function get(svc: OrderService, id: string): OrderRecord {
  const r = list(svc).find((x) => x.id === id);
  if (r === undefined) throw new Error(`no record ${id}`);
  return r;
}

function draft(node: FakeNode, d: Partial<OrderDraft> = {}): OrderDraft {
  return {
    market: node.market,
    side: 0,
    role: 0,
    kind: 0,
    limitTick: node.band.reference,
    quantityLots: 5n,
    lifetimeEpochs: 2,
    ...d,
  };
}

function prompts(w: TestWallet): number {
  return w.calls.filter((c) => c.method === 'signMessage').length;
}

function batchPosts(node: FakeNode): readonly { body: Uint8Array | null }[] {
  return node.fake.requests.filter(
    (r) => r.method === 'POST' && r.path.endsWith('/submissions/batch'),
  );
}

async function evidence(j: Journal): Promise<{ kind: string; doc: Record<string, unknown> }[]> {
  return (await journalInternals(j)!.listEvidence()).map((e) => ({
    kind: e.kind,
    doc: JSON.parse(fromUtf8(e.bytes)) as Record<string, unknown>,
  }));
}

const COUNTERPARTY = new Uint8Array(32).fill(8);

/** An own buy filled against a counterparty's sell at the reference tick. */
function fillsFor(node: FakeNode, wallet: TestWallet, c: Uint8Array, quantity: bigint): FakeFill[] {
  const tick = node.band.reference;
  return [
    { commitment: c, trader: b58.decode(wallet.address, 32), side: 0, role: 0, quantity, tick },
    {
      commitment: new Uint8Array(32).fill(9),
      trader: COUNTERPARTY,
      side: 1,
      role: 1,
      quantity,
      tick,
    },
  ];
}

/** Runs the epoch through commit, reveal, receipt and settlement. */
function clear(node: FakeNode, epoch: bigint, fills: FakeFill[], cancelled: Uint8Array[] = []) {
  node.commit(epoch);
  node.reveal(epoch);
  node.post(epoch, { fills, cancelled });
  node.settle(epoch);
}

describe('test fixtures', () => {
  it('offers lifetime presets within max_order_lifetime + 1 and no single epoch under 30 s', () => {
    const p = testMarketParams({ maxOrderLifetime: 8 });
    expect(lifetimePresets(p, 10_000, 17_000).map((x) => x.epochs)).toEqual([2, 4, 9]);
    expect(lifetimePresets(p, 60_000, 17_000).map((x) => x.epochs)).toEqual([1, 2, 4, 9]);
    expect(lifetimePresets(p, 30_000, 40_000).map((x) => x.epochs)).toEqual([2, 4, 9]);
    expect(lifetimePresets(testMarketParams({ maxOrderLifetime: 1 }), 60_000, 17_000)).toEqual([
      { epochs: 1, label: 'This epoch' },
      { epochs: 2, label: 'Max: 2 epochs' },
    ]);
    expect(lifetimePresets(testMarketParams({ maxOrderLifetime: 0 }), 10_000, 17_000)).toEqual([
      { epochs: 1, label: 'Max: 1 epoch' },
    ]);
  });
});

describe('OrderService', () => {
  it('seals the open epoch and parks the rest in one batched request, with one prompt', async () => {
    const { node, wallet, svc } = await setup();
    const n = node.open;
    const p = svc.prepare(draft(node, { lifetimeEpochs: 3 }));
    expect(p.blockers).toEqual([]);
    expect(p.epochs).toEqual({ from: n, to: n + 2n, parkedTo: n + 2n });
    expect(p.warnings).toContain('long_rest_linkable');
    expect(p.collateral.shortfall).toBe(false);
    const steps: string[] = [];
    const r = await svc.submit(p, { onStep: (s) => steps.push(s) });
    expect(steps).toEqual([
      'validating',
      'awaiting_wallet',
      'sealing',
      'submitting',
      'verifying_promise',
      'done',
    ]);
    expect(r.state.kind).toBe('working');
    expect(prompts(wallet)).toBe(1);
    expect(batchPosts(node)).toHaveLength(1);
    expect([...r.epochs.values()].map((x) => [x.epoch, x.state.kind])).toEqual([
      [n, 'sealed'],
      [n + 1n, 'parked'],
      [n + 2n, 'parked'],
    ]);
    for (const x of r.epochs.values()) expect(x.promise).not.toBeNull();
    expect(badge(r)).toEqual({ state: 'sealed', epoch: n });
  });

  it('follows an epoch to settlement and retracts the parked rest after a full fill', async () => {
    const { node, wallet, svc, journal } = await setup();
    const r = await svc.submit(svc.prepare(draft(node, { lifetimeEpochs: 3 })));
    const n = node.open;
    node.closeEpoch();
    clear(node, n, fillsFor(node, wallet, r.commitment, 5n));
    const report = await svc.reconcile(n);
    expect(report).toMatchObject({ attached: 1, inconclusive: 0 });
    const after = get(svc, r.id);
    expect(after.epochs.get(n)?.state).toEqual({ kind: 'settled', filled: 5n });
    expect(after.state.kind).toBe('filled');
    expect(after.filled).toBe(5n);
    expect(after.fills).toHaveLength(1);
    expect(badge(after).state).toBe('filled');
    expect(after.epochs.get(n + 2n)?.state).toEqual({
      kind: 'not_submitted',
      reason: 'invalidated',
    });
    await vi.waitFor(() => {
      expect(node.held(n + 2n).some((h) => equal(h.commitment, r.commitment))).toBe(false);
    });
    expect(await journal.outbox()).toEqual([]);
  });

  it('moves on stream events alone, re-reading the node and the chain', async () => {
    const { node, wallet, svc } = await setup();
    const r = await svc.submit(svc.prepare(draft(node, { lifetimeEpochs: 1 })));
    const n = node.open;
    const state = () => get(svc, r.id).epochs.get(n)?.state;
    node.closeEpoch();
    await vi.waitFor(() => expect(state()?.kind).toBe('locked'));
    node.commit(n);
    await vi.waitFor(() => expect(state()?.kind).toBe('included'));
    node.reveal(n);
    await vi.waitFor(() => expect(state()?.kind).toBe('clearing'));
    node.post(n, { fills: fillsFor(node, wallet, r.commitment, 2n) });
    await vi.waitFor(() => expect(state()).toEqual({ kind: 'verified', filled: 2n }));
    expect(badge(get(svc, r.id))).toEqual({ state: 'verified', epoch: n });
    node.settle(n);
    await vi.waitFor(() => expect(get(svc, r.id).state.kind).toBe('expired'));
    expect(state()).toEqual({ kind: 'settled', filled: 2n });
  });

  it('stays provisional until the receipt quorum co-signs', async () => {
    const { node, wallet, svc } = await setup({ receiptQuorum: 2 });
    const r = await svc.submit(svc.prepare(draft(node, { lifetimeEpochs: 1 })));
    const n = node.open;
    node.closeEpoch();
    node.commit(n);
    node.reveal(n);
    node.post(n, { fills: fillsFor(node, wallet, r.commitment, 5n) });
    await svc.reconcile(n);
    expect(get(svc, r.id).epochs.get(n)?.state).toEqual({ kind: 'provisional', have: 1, need: 2 });
    expect(get(svc, r.id).fills).toEqual([]);
    node.cosign(n);
    await svc.reconcile(n);
    expect(get(svc, r.id).epochs.get(n)?.state).toEqual({ kind: 'verified', filled: 5n });
  });

  it('reuses a parked N+1 participation when epoch N closes before the relay receives it', async () => {
    const { node, svc, journal } = await setup();
    const n = node.open;
    node.onNextSubmission(() => node.closeEpoch());
    const r = await svc.submit(svc.prepare(draft(node, { lifetimeEpochs: 2 })));
    expect(r.state.kind).toBe('working');
    expect(r.epochs.get(n)?.state).toEqual({ kind: 'not_submitted', reason: 'invalidated' });
    expect(r.epochs.get(n + 1n)?.state.kind).toBe('sealed');
    expect(node.submitted.filter((s) => s.epoch === n + 1n)).toHaveLength(1);
    expect(batchPosts(node)).toHaveLength(1);
    const refusals = (await evidence(journal)).filter((e) => e.kind === 'refusal');
    expect(refusals).toHaveLength(1);
    expect(refusals[0]!.doc.code).toBe('EPOCH_CLOSED');
  });

  it('seals N+1 when N closes in flight and N+1 was not parked but is in the signed window', async () => {
    const { node, svc } = await setup({ maxParkAheadEpochs: 0 });
    const n = node.open;
    node.onNextSubmission(() => node.closeEpoch());
    const r = await svc.submit(svc.prepare(draft(node, { lifetimeEpochs: 2 })));
    expect(r.state.kind).toBe('working');
    expect(r.epochs.get(n)?.state.kind).toBe('not_submitted');
    expect(r.epochs.get(n + 1n)?.state.kind).toBe('sealed');
    expect(batchPosts(node)).toHaveLength(2);
  });

  it('records signed_too_late when the signature arrives after the whole window', async () => {
    const { node, wallet, svc } = await setup({ behaviour: 'late_resolving', lateMs: 500 });
    const pending = svc.submit(svc.prepare(draft(node, { lifetimeEpochs: 1 })));
    await vi.waitFor(() => expect(prompts(wallet)).toBe(1), { interval: 2 });
    node.closeEpoch();
    const r = await pending;
    expect(r.state.kind).toBe('signed_too_late');
    expect(r.epochs.size).toBe(0);
    expect(node.submitted).toEqual([]);
    expect(badge(r).state).toBe('signed_too_late');
  });

  it('drops a signature that arrives after the caller gave up', async () => {
    const { node, wallet, svc } = await setup({ behaviour: 'late_resolving', lateMs: 500 });
    const ac = new AbortController();
    const pending = svc.submit(svc.prepare(draft(node)), { signal: ac.signal });
    await vi.waitFor(() => expect(prompts(wallet)).toBe(1), { interval: 2 });
    ac.abort();
    const r = await pending;
    expect(r.state.kind).toBe('abandoned');
    await new Promise((resolve) => setTimeout(resolve, 600));
    expect(get(svc, r.id).signature).toHaveLength(0);
    expect(node.submitted).toEqual([]);
  });

  it('gives up on a wallet that never answers when the caller aborts', async () => {
    const { node, wallet, svc } = await setup({ behaviour: 'never_resolving' });
    const ac = new AbortController();
    const pending = svc.submit(svc.prepare(draft(node)), { signal: ac.signal });
    await vi.waitFor(() => expect(prompts(wallet)).toBe(1), { interval: 2 });
    ac.abort();
    expect((await pending).state.kind).toBe('abandoned');
    expect(node.submitted).toEqual([]);
  });

  it('refuses wallets that prefix what they sign (V-11) and records declines', async () => {
    const prefixing = await setup({ behaviour: 'prefixing' });
    const r1 = await prefixing.svc.submit(prefixing.svc.prepare(draft(prefixing.node)));
    expect(r1.state.kind).toBe('unsupported_wallet');
    expect(prefixing.node.submitted).toEqual([]);
    for (const behaviour of ['phantom_errors', 'solflare_errors', 'backpack_errors'] as const) {
      const declining = await setup({ behaviour });
      const r2 = await declining.svc.submit(declining.svc.prepare(draft(declining.node)));
      expect(r2.state.kind).toBe('wallet_rejected');
      expect(declining.node.submitted).toEqual([]);
    }
  });

  it('accepts randomized signatures, verifying them rather than re-deriving them', async () => {
    const { node, svc } = await setup({ behaviour: 'randomized' });
    const r = await svc.submit(svc.prepare(draft(node)));
    expect(r.state.kind).toBe('working');
  });

  it('cancels with a sealed Cancel in the placement’s epoch and retracts the parked rest', async () => {
    const { node, wallet, svc } = await setup();
    const placement = await svc.submit(svc.prepare(draft(node, { lifetimeEpochs: 4 })));
    const n = node.open;
    const after = await svc.cancel(placement);
    expect(after.state).toEqual({ kind: 'cancel_pending', epoch: n });
    expect(prompts(wallet)).toBe(2);
    const cancel = list(svc).find((x) => x.body.kind === 'cancel')!;
    expect(
      cancel.body.kind === 'cancel' && equal(cancel.body.cancel.target, placement.commitment),
    ).toBe(true);
    const held = node.held(n);
    expect(held.some((h) => equal(h.commitment, placement.commitment))).toBe(true);
    expect(held.some((h) => equal(h.commitment, cancel.commitment))).toBe(true);
    for (let e = n + 1n; e <= n + 3n; e++) {
      expect(node.held(e).some((h) => equal(h.commitment, placement.commitment))).toBe(false);
      expect(get(svc, placement.id).epochs.get(e)?.state.kind).toBe('not_submitted');
    }
    node.closeEpoch();
    clear(node, n, [], [placement.commitment]);
    await svc.reconcile(n);
    expect(get(svc, placement.id).state.kind).toBe('cancelled');
    expect(get(svc, cancel.id).state.kind).toBe('cancelled');
  });

  it('asks before a second cancel prompt when the cancel epoch closes while signing', async () => {
    for (const agree of [true, false]) {
      const { node, wallet, svc } = await setup({ behaviour: 'late_resolving', lateMs: 500 });
      const placement = await svc.submit(svc.prepare(draft(node, { lifetimeEpochs: 4 })));
      const n = node.open;
      let asked = 0;
      const pending = svc.cancel(placement, {
        confirmSecondPrompt: () => {
          asked++;
          return Promise.resolve(agree);
        },
      });
      await vi.waitFor(() => expect(prompts(wallet)).toBe(2), { interval: 2 });
      node.closeEpoch();
      if (agree) {
        const after = await pending;
        expect(asked).toBe(1);
        expect(prompts(wallet)).toBe(3);
        expect(after.state).toEqual({ kind: 'cancel_pending', epoch: n + 1n });
      } else {
        await expect(pending).rejects.toMatchObject({ code: 'EPOCH_CLOSED' });
        expect(asked).toBe(1);
        expect(prompts(wallet)).toBe(2);
        expect(get(svc, placement.id).state.kind).toBe('working');
      }
    }
  });

  it('saves exclusion and substitution evidence for a promised but missing leaf (V-6)', async () => {
    for (const how of ['omit', 'substitute'] as const) {
      const { node, svc, journal } = await setup();
      const r = await svc.submit(svc.prepare(draft(node, { lifetimeEpochs: 1 })));
      const n = node.open;
      node.closeEpoch();
      node.commit(n, how === 'omit' ? { omit: [r.commitment] } : { substitute: [r.commitment] });
      await svc.reconcile(n);
      const after = get(svc, r.id);
      expect(after.epochs.get(n)?.state.kind).toBe('excluded');
      expect(badge(after)).toEqual({ state: 'excluded', epoch: n });
      const kind = how === 'omit' ? 'exclusion' : 'substitution';
      const saved = (await evidence(journal)).find((e) => e.kind === kind);
      expect(saved?.doc.commitment).toBe(hex.encode(r.commitment));
      expect(after.evidence).toHaveLength(1);
    }
  });

  it('holds an order at locked while the node withholds the leaves, then finds the exclusion (V-6)', async () => {
    const { node, svc, journal } = await setup();
    const r = await svc.submit(svc.prepare(draft(node, { lifetimeEpochs: 1 })));
    const n = node.open;
    node.withholdLeaves(n, true);
    node.closeEpoch();
    node.commit(n, { omit: [r.commitment] });
    node.reveal(n);
    node.post(n, { fills: [] });
    node.settle(n);
    const held = await svc.reconcile(n);
    expect(held.inconclusive).toBeGreaterThan(0);
    let now = get(svc, r.id);
    expect(now.epochs.get(n)?.state.kind).toBe('locked');
    expect(now.history.some((h) => h.kind === 'revealed' || h.kind === 'settled')).toBe(false);
    expect(now.state.kind).toBe('working');

    node.withholdLeaves(n, false);
    await svc.reconcile(n);
    now = get(svc, r.id);
    expect(now.epochs.get(n)?.state.kind).toBe('excluded');
    expect(badge(now)).toEqual({ state: 'excluded', epoch: n });
    const saved = (await evidence(journal)).find((e) => e.kind === 'exclusion');
    expect(saved?.doc.commitment).toBe(hex.encode(r.commitment));
    expect(now.evidence).toHaveLength(1);
  });

  it('adopts the relay’s promise for an envelope this journal sealed earlier (DUPLICATE_COMMITMENT)', async () => {
    const { node, svc, journal } = await setup();
    const r = await svc.submit(svc.prepare(draft(node, { lifetimeEpochs: 3 })));
    const n = node.open;
    const before = r.epochs.get(n + 1n)!;
    // A relay that reports an invalidation but keeps the parked envelopes:
    // the re-sealed bytes meet the earlier ones there.
    node.emit({ kind: 'parked.invalidated', market: node.market, epochs: [n + 1n] });
    // The re-seal is journalled without a promise. The relay's answer brings one.
    await vi.waitFor(() => {
      const p = get(svc, r.id).epochs.get(n + 1n)!;
      expect(equal(p.submission, before.submission)).toBe(false);
      expect(p.promise).not.toBeNull();
    });
    const now = get(svc, r.id);
    const p = now.epochs.get(n + 1n)!;
    const held = node.held(n + 1n).find((h) => equal(h.commitment, r.commitment))!;
    expect(p.state.kind).toBe('parked');
    expect(equal(p.envelopeDigest, before.envelopeDigest)).toBe(true);
    expect(equal(p.promise!, held.promise)).toBe(true);
    expect(now.state.kind).toBe('working');
    expect(await evidence(journal)).toEqual([]);
    // V-6 finds the envelope the relay held.
    node.closeEpoch();
    clear(node, n, []);
    node.closeEpoch();
    node.commit(n + 1n);
    await svc.reconcile(n);
    expect(get(svc, r.id).epochs.get(n + 1n)?.state.kind).toBe('included');
    expect(await evidence(journal)).toEqual([]);
  });

  it('fails V-5 on a DUPLICATE_COMMITMENT promise for an envelope this journal never sealed', async () => {
    const { node, svc, journal, deps, wallet, session } = await setup();
    svc.dispose();
    const garbage = new Uint8Array(32).fill(0x66);
    // The relay answers the first submission as if it held other bytes for the commitment.
    const submitBatch: TimescalesApi['submitBatch'] = (market, submissions) =>
      Promise.resolve(
        submissions.map((bytes) => {
          const env = decodeEnvelope(decodeSubmission(bytes).envelope);
          const unsigned = {
            market: b58.decode(market, 32),
            epoch: env.epoch,
            commitment: env.commitment,
            envelopeDigest: garbage,
            relay: b58.decode(node.relay, 32),
            signature: new Uint8Array(64),
          };
          const promise = encodePromiseV2({
            ...unsigned,
            signature: ed25519Sign(node.secrets.relay, promiseV2Digest(unsigned)),
          });
          return {
            error: {
              type: 'urn:timescales:error:duplicate_commitment',
              title: 'DUPLICATE_COMMITMENT',
              status: 409,
              code: 'DUPLICATE_COMMITMENT' as const,
              detail: 'same commitment, other bytes',
              retryable: false,
              requestId: 'forged',
              details: { promise_b64: b64.encode(promise) },
            },
          };
        }),
      );
    const api = new Proxy(node.api, {
      get(target, prop) {
        if (prop === 'submitBatch') return submitBatch;
        const v = Reflect.get(target, prop, target) as unknown;
        return typeof v === 'function' ? (v as (...a: unknown[]) => unknown).bind(target) : v;
      },
    });
    const forged = new OrderService({ ...deps, api });
    cleanups.push(() => forged.dispose());
    await forged.start(wallet, session);
    await forged.context(node.market);
    const r = await forged.submit(forged.prepare(draft(node, { lifetimeEpochs: 1 })));
    const n = node.open;
    expect(r.state).toEqual({ kind: 'verification_failed', check: 'V-5' });
    const p = r.epochs.get(n)!;
    const own = decodeSubmission(p.submission).envelope;
    expect(equal(p.envelopeDigest, envelopeDigest(own))).toBe(true);
    expect(p.promise).toBeNull();
    const saved = (await evidence(journal)).filter((e) => e.kind === 'verification_failed');
    expect(saved).toHaveLength(1);
    const inputs = saved[0]!.doc.inputs as Record<string, string>;
    expect(saved[0]!.doc.check).toBe('V-5');
    expect(inputs.envelope_b64).toBe(b64.encode(own));
    expect(b64.decode(inputs.promise_b64!).subarray(73, 105)).toEqual(garbage);
    expect(forged.prepare(draft(node)).blockers).toContain('unverified');
  });

  it('follows the promised epoch when the relay answers with a status it does not know', async () => {
    const { node, svc, deps, wallet, session } = await setup();
    svc.dispose();
    const submitBatch: TimescalesApi['submitBatch'] = async (market, submissions, s) =>
      (await node.api.submitBatch(market, submissions, s)).map((item) =>
        'ok' in item ? { ok: { ...item.ok, status: 'unknown' as const } } : item,
      );
    const api = new Proxy(node.api, {
      get(target, prop) {
        if (prop === 'submitBatch') return submitBatch;
        const v = Reflect.get(target, prop, target) as unknown;
        return typeof v === 'function' ? (v as (...a: unknown[]) => unknown).bind(target) : v;
      },
    });
    const later = new OrderService({ ...deps, api });
    cleanups.push(() => later.dispose());
    await later.start(wallet, session);
    await later.context(node.market);
    const r = await later.submit(later.prepare(draft(node, { lifetimeEpochs: 3 })));
    const n = node.open;
    expect(r.state.kind).toBe('working');
    expect(r.epochs.get(n)?.state.kind).toBe('sealed');
    expect(r.epochs.get(n + 1n)?.state.kind).toBe('parked');
    expect(r.epochs.get(n + 2n)?.state.kind).toBe('parked');
    expect([...r.epochs.values()].every((p) => p.promise !== null)).toBe(true);
  });

  it('parks what the quota allows and seals the rest once its epoch opens', async () => {
    const { node, wallet, svc, journal } = await setup({ maxParkedPerWallet: 1 });
    const r = await svc.submit(svc.prepare(draft(node, { lifetimeEpochs: 3 })));
    const n = node.open;
    expect(r.state.kind).toBe('working');
    expect(r.epochs.get(n + 1n)?.state.kind).toBe('parked');
    expect(r.epochs.get(n + 2n)?.state).toEqual({ kind: 'not_submitted', reason: 'quota' });
    expect(batchPosts(node)).toHaveLength(1);
    const refusal = (await evidence(journal)).find((e) => e.kind === 'refusal');
    expect(refusal?.doc.code).toBe('QUOTA_EXCEEDED');
    node.closeEpoch();
    node.closeEpoch();
    await vi.waitFor(() => expect(get(svc, r.id).epochs.get(n + 2n)?.state.kind).toBe('sealed'));
    expect(node.held(n + 2n).some((h) => equal(h.commitment, r.commitment))).toBe(true);
    expect(prompts(wallet)).toBe(1);
  });

  it('seals invalidated parked epochs again for their new keys without a prompt', async () => {
    const { node, wallet, svc } = await setup();
    const r = await svc.submit(svc.prepare(draft(node, { lifetimeEpochs: 3 })));
    const n = node.open;
    const before = node.held(n + 2n).find((h) => equal(h.commitment, r.commitment))!;
    node.invalidateParked([n + 1n, n + 2n]);
    await vi.waitFor(() => {
      const again = node.held(n + 2n).find((h) => equal(h.commitment, r.commitment));
      expect(again).toBeDefined();
      expect(equal(again!.envelopeDigest, before.envelopeDigest)).toBe(false);
    });
    await vi.waitFor(() => expect(get(svc, r.id).epochs.get(n + 1n)?.state.kind).toBe('parked'));
    expect(node.held(n + 1n).some((h) => equal(h.commitment, r.commitment))).toBe(true);
    expect(get(svc, r.id).history.some((h) => h.kind === 'parked_invalidated')).toBe(true);
    expect(prompts(wallet)).toBe(1);
  });

  it('continues after a voided epoch without a prompt', async () => {
    const { node, wallet, svc } = await setup({ maxParkAheadEpochs: 0 });
    const r = await svc.submit(svc.prepare(draft(node, { lifetimeEpochs: 2 })));
    const n = node.open;
    node.closeEpoch();
    node.commit(n);
    node.abort(n, 'exec_timeout');
    await svc.reconcile(n);
    const after = get(svc, r.id);
    expect(after.epochs.get(n)?.state).toEqual({ kind: 'voided', outcomeWasPublic: false });
    expect(after.epochs.get(n + 1n)?.state.kind).toBe('sealed');
    expect(after.state.kind).toBe('working');
    expect(prompts(wallet)).toBe(1);
  });

  it('asks before re-placing an order whose details a voided epoch made public', async () => {
    const { node, wallet, svc } = await setup({ maxParkAheadEpochs: 0 });
    const r = await svc.submit(svc.prepare(draft(node, { lifetimeEpochs: 3 })));
    const n = node.open;
    node.closeEpoch();
    node.commit(n);
    node.reveal(n);
    node.post(n, { fills: fillsFor(node, wallet, r.commitment, 1n) });
    node.abort(n, 'admin');
    await svc.reconcile(n);
    const after = get(svc, r.id);
    expect(after.epochs.get(n)?.state).toEqual({ kind: 'voided', outcomeWasPublic: true });
    expect(after.state).toEqual({ kind: 'reseal_needs_consent', epoch: n });
    expect(badge(after)).toEqual({ state: 'reseal_needs_consent', epoch: n });
    expect(after.fills).toEqual([]);
    // Not sealed again silently: its side, size and price are public.
    expect(node.held(n + 1n).some((h) => equal(h.commitment, r.commitment))).toBe(false);
    expect(prompts(wallet)).toBe(1);
  });

  it('counts a voided epoch’s published artifacts as public even when they do not verify', async () => {
    for (const how of ['tampered', 'garbled'] as const) {
      const { node, wallet, svc } = await setup({ maxParkAheadEpochs: 0 });
      const r = await svc.submit(svc.prepare(draft(node, { lifetimeEpochs: 2 })));
      const n = node.open;
      node.closeEpoch();
      node.commit(n);
      node.reveal(n);
      node.post(n, { fills: fillsFor(node, wallet, r.commitment, 1n) });
      const real = await node.api.artifacts(node.market, n);
      // An extra cancelled entry breaks V-8 and still decodes. Random bytes do not decode.
      const decoded = decodeArtifacts(real.artifactsBytes);
      const published =
        how === 'tampered'
          ? encodeArtifacts({ ...decoded, cancelled: [...decoded.cancelled, new Uint8Array(32)] })
          : new Uint8Array(40).fill(7);
      node.fake.respond('GET', `/v1/markets/${node.market}/epochs/${n}/artifacts`, 200, {
        market: node.market,
        epoch: n,
        header_b64: b64.encode(real.headerBytes),
        receipt_b64: b64.encode(real.receiptBytes),
        artifacts_b64: b64.encode(published),
        attestation_b64: null,
        attestation_platform: 'simulated',
        cosignatures: [],
      });
      node.abort(n, 'admin');
      await svc.reconcile(n);
      const after = get(svc, r.id);
      expect(after.epochs.get(n)?.state).toEqual({ kind: 'voided', outcomeWasPublic: true });
      expect(after.state).toEqual({ kind: 'reseal_needs_consent', epoch: n });
    }
  });

  it('withdraws the parked epochs of an order whose details a voided epoch made public', async () => {
    const { node, wallet, svc } = await setup({ maxParkAheadEpochs: 3 });
    const r = await svc.submit(svc.prepare(draft(node, { lifetimeEpochs: 4 })));
    const n = node.open;
    for (const e of [n + 1n, n + 2n, n + 3n]) expect(r.epochs.get(e)?.state.kind).toBe('parked');
    node.closeEpoch();
    node.commit(n);
    node.reveal(n);
    node.post(n, { fills: fillsFor(node, wallet, r.commitment, 1n) });
    node.abort(n, 'admin');
    await svc.reconcile(n);
    const after = get(svc, r.id);
    expect(after.state).toEqual({ kind: 'reseal_needs_consent', epoch: n });
    for (const e of [n + 2n, n + 3n]) {
      expect(after.epochs.get(e)?.state).toEqual({ kind: 'not_submitted', reason: 'invalidated' });
      expect(node.held(e).some((h) => equal(h.commitment, r.commitment))).toBe(false);
    }
    // The open epoch's envelope is in its batch already. The relay keeps it.
    expect(after.epochs.get(n + 1n)?.state.kind).toBe('parked');
    expect(node.held(n + 1n).some((h) => equal(h.commitment, r.commitment))).toBe(true);
    // Nothing is sealed again without consent.
    await svc.reconcile(n);
    expect(node.held(n + 2n).some((h) => equal(h.commitment, r.commitment))).toBe(false);
    expect(prompts(wallet)).toBe(1);
  });

  it('fails V-4 when a batch commits to other terms than its relay announced, also after a reload', async () => {
    for (const reload of [false, true]) {
      const { node, svc, journal, deps, wallet, session } = await setup();
      const r = await svc.submit(svc.prepare(draft(node, { lifetimeEpochs: 3 })));
      const n = node.open;
      expect(r.epochs.get(n + 1n)?.state.kind).toBe('parked');
      let tab = svc;
      // Closed before N + 1 opens, the tab never sees its announcement.
      if (reload) svc.dispose();
      node.closeEpoch();
      clear(node, n, []);
      node.closeEpoch();
      node.commit(n + 1n, { terms: new Uint8Array(32).fill(0xee) });
      if (reload) {
        tab = new OrderService(deps);
        cleanups.push(() => tab.dispose());
        await tab.start(wallet, session);
        await tab.context(node.market);
        // Without the epoch's detail the terms cannot be checked: the order is held.
        node.withholdDetail(n + 1n, true);
        node.reveal(n + 1n);
        const held = await tab.reconcile(n);
        expect(held.inconclusive).toBeGreaterThan(0);
        const now = get(tab, r.id);
        expect(now.state.kind).toBe('working');
        expect(now.epochs.get(n + 1n)?.state.kind).toBe('included');
        expect(now.history.some((h) => h.kind === 'revealed' && h.epoch === n + 1n)).toBe(false);
        node.withholdDetail(n + 1n, false);
      }
      await tab.reconcile(n);
      const after = get(tab, r.id);
      expect(after.state).toEqual({ kind: 'verification_failed', check: 'V-4' });
      const saved = (await evidence(journal)).filter((e) => e.kind === 'terms');
      expect(saved).toHaveLength(1);
      expect(saved[0]?.doc.epoch).toBe(String(n + 1n));
      expect(after.evidence).toHaveLength(1);
    }
  });

  it('stops trading on the market when the published balance sheet under-reports the wallet (V-15)', async () => {
    const { node, wallet, svc, journal, deps } = await setup();
    const r = await svc.submit(svc.prepare(draft(node, { lifetimeEpochs: 1 })));
    const n = node.open;
    node.closeEpoch();
    node.overrideBalances(
      n,
      encodeBalanceSheet([{ trader: b58.decode(wallet.address, 32), base: 0n, quote: 0n }]),
    );
    clear(node, n, fillsFor(node, wallet, r.commitment, 1n));
    await svc.reconcile(n);
    expect(get(svc, r.id).state).toEqual({ kind: 'verification_failed', check: 'V-15' });
    const saved = (await evidence(journal)).find((e) => e.kind === 'verification_failed');
    expect(saved?.doc.check).toBe('V-15');
    expect(badge(get(svc, r.id))).toEqual({ state: 'verification_failed' });
    // Blocked until the app asks for a re-check, whatever runs in the background.
    expect(svc.prepare(draft(node)).blockers).toContain('unverified');
    await svc.reconcile(n);
    expect(svc.prepare(draft(node)).blockers).toContain('unverified');
    // Stream events that re-verify a market do not lift the failure either,
    // even once the node serves an honest sheet again.
    node.overrideBalances(n, null);
    const seen = new Set<string>();
    const off = deps.stream.on('event', (e) => seen.add(e.kind));
    node.invalidateParked([node.open + 1n]);
    node.emit({ kind: 'governance.applied', market: node.market, change: 'set_relay', slot: 1n });
    node.emit({ kind: 'program.upgraded', slot: 1n });
    await vi.waitFor(() =>
      expect([...seen].sort()).toEqual([
        'governance.applied',
        'parked.invalidated',
        'program.upgraded',
      ]),
    );
    off();
    // Leader jobs run in order: this reconcile settles after the ones those events queued.
    await svc.reconcile(n);
    expect(svc.prepare(draft(node)).blockers).toContain('unverified');
    await svc.context(node.market);
    expect(svc.prepare(draft(node)).blockers).not.toContain('unverified');
  });

  it('fails the reading check on a program account that does not decode or is not at its PDA', async () => {
    const { node, svc, wallet, session, journal, deps } = await setup();
    const r = await svc.submit(svc.prepare(draft(node, { lifetimeEpochs: 1 })));
    const n = node.open;
    svc.dispose();
    let market: Error | null = null;
    let batch: Error | null = null;
    const rpc: TimescalesRpc = {
      ...node.rpc,
      market: (a, slot) => (market === null ? node.rpc.market(a, slot) : Promise.reject(market)),
      batch: (a, slot) => (batch === null ? node.rpc.batch(a, slot) : Promise.reject(batch)),
    };
    const withRpc: OrderServiceDeps = { ...deps, rpc };
    const again = new OrderService(withRpc);
    cleanups.push(() => again.dispose());
    batch = new DecodeError('tag', 'not a Batch account');
    node.closeEpoch();
    node.commit(n);
    await again.start(wallet, session);
    await again.reconcile(n);
    expect(get(again, r.id).state).toEqual({ kind: 'verification_failed', check: 'V-6' });
    expect(again.prepare(draft(node)).blockers).toContain('unverified');

    market = new TimescalesError({
      kind: 'verify',
      code: 'account_not_pda',
      message: 'market is not its owner’s program address',
    });
    await expect(again.context(node.market)).rejects.toMatchObject({
      check: 'V-1',
      code: 'verification_failed',
    });
    market = new DecodeError('length', 'Market');
    await expect(again.context(node.market)).rejects.toMatchObject({ check: 'V-1' });
    const checks = (await evidence(journal))
      .filter((e) => e.kind === 'verification_failed')
      .map((e) => e.doc.check);
    expect(checks).toEqual(expect.arrayContaining(['V-6', 'V-1']));
    // A market-level record names the epoch its portable document names.
    for (const e of await journalInternals(journal)!.listEvidence()) {
      expect(String(e.epoch)).toBe(JSON.parse(fromUtf8(e.bytes)).epoch);
    }
    expect(again.prepare(draft(node)).blockers).toContain('unverified');
  });

  it('reads lamports sent to an uncreated Batch or Trader address as no account', async () => {
    const { node, svc, wallet, journal } = await setup();
    const r = await svc.submit(svc.prepare(draft(node, { lifetimeEpochs: 1 })));
    const n = node.open;
    node.prefund((await batchPda(node.program, node.market, n))[0]);
    await svc.reconcile(n);
    expect(get(svc, r.id).state.kind).toBe('working');
    expect(get(svc, r.id).epochs.get(n)?.state.kind).toBe('sealed');
    expect(await evidence(journal)).toEqual([]);
    expect(svc.prepare(draft(node)).blockers).not.toContain('unverified');
    // The program adopts the account when it commits, and the order follows the epoch.
    node.closeEpoch();
    clear(node, n, fillsFor(node, wallet, r.commitment, 5n));
    await svc.reconcile(n);
    expect(get(svc, r.id).state.kind).toBe('filled');
    expect(await evidence(journal)).toEqual([]);

    const fresh = await setup({ funded: false });
    const [trader] = await traderPda(fresh.node.program, fresh.node.market, fresh.wallet.address);
    fresh.node.prefund(trader);
    // Reconciling re-reads the open epoch and the wallet's Trader account.
    await fresh.svc.reconcile(fresh.node.open);
    expect(fresh.svc.prepare(draft(fresh.node)).blockers).not.toContain('unverified');
    expect(await evidence(fresh.journal)).toEqual([]);
  });

  it('blocks an order that would self-trade in the same derived book', async () => {
    const single = await setup();
    await single.svc.submit(single.svc.prepare(draft(single.node, { side: 0, role: 0 })));
    expect(single.svc.prepare(draft(single.node, { side: 1, role: 1 })).blockers).toContain(
      'self_trade',
    );
    expect(single.svc.prepare(draft(single.node, { side: 0, role: 1 })).blockers).not.toContain(
      'self_trade',
    );

    const dual = await setup({ params: { flow: 1 } });
    await dual.svc.submit(dual.svc.prepare(draft(dual.node, { side: 0, role: 0 })));
    // A maker buy meets taker sells in MakerBidTakerAsk. Maker sells rest in the other book.
    expect(dual.svc.prepare(draft(dual.node, { side: 1, role: 1 })).blockers).toContain(
      'self_trade',
    );
    expect(dual.svc.prepare(draft(dual.node, { side: 1, role: 0 })).blockers).not.toContain(
      'self_trade',
    );
  });

  it('resends the outbox bytes after a crash between POST and promise storage', async () => {
    const { node, svc, journal, deps, wallet, session } = await setup();
    node.failSubmissions(3);
    const r = await svc.submit(svc.prepare(draft(node, { lifetimeEpochs: 1 })));
    expect(r.state).toEqual({ kind: 'submit_failed', code: 'OVERLOADED', retryable: true });
    const outbox = await journal.outbox();
    expect(outbox).toHaveLength(1);
    const held = node.held(node.open);
    expect(held).toHaveLength(1);
    expect(equal(held[0]!.submission, outbox[0]!.submission)).toBe(true);

    // The tab reloads: a new service on the same journal leads and resends.
    svc.dispose();
    const again = new OrderService(deps);
    cleanups.push(() => again.dispose());
    expect(await again.start(wallet, session)).toEqual({ role: 'leader' });
    await vi.waitFor(() => expect(get(again, r.id).state.kind).toBe('working'));
    expect(node.submitted.at(-1)?.duplicate).toBe(true);
    expect(get(again, r.id).epochs.get(node.open)?.promise).not.toBeNull();
    expect(await journal.outbox()).toEqual([]);
  });

  it('keeps the signed bytes when the node drops the session and sends them with the next one', async () => {
    const { node, seed, svc, journal, wallet, session, clock } = await setup();
    await node.api.revokeSession(session);
    const r = await svc.submit(svc.prepare(draft(node, { lifetimeEpochs: 1 })));
    expect(r.state).toEqual({ kind: 'submit_failed', code: 'SESSION_REVOKED', retryable: true });
    const n = node.open;
    expect(r.epochs.get(n)).toMatchObject({ state: { kind: 'sealed' }, promise: null });
    const [queued] = await journal.outbox();
    expect(queued?.epoch).toBe(n);
    expect(node.held(n)).toEqual([]);

    // Nothing is re-sent with the refused session.
    expect((await svc.reconcile(n)).outboxResent).toBe(0);

    const renewed = await TradingSession.open({
      api: node.api,
      wallet: createTestWallet({ seed }),
      info: await node.api.info(),
      clock,
      market: node.market,
    });
    expect(await svc.start(wallet, renewed)).toEqual({ role: 'leader' });
    await vi.waitFor(() => expect(get(svc, r.id).state.kind).toBe('working'));
    const held = node.held(n);
    expect(held).toHaveLength(1);
    // The same envelope, wrapped for the new session, so the same commitment and digest.
    const p = get(svc, r.id).epochs.get(n)!;
    expect(equal(held[0]!.envelopeDigest, r.epochs.get(n)!.envelopeDigest)).toBe(true);
    expect(equal(held[0]!.envelopeDigest, p.envelopeDigest)).toBe(true);
    expect(equal(held[0]!.submission, queued!.submission)).toBe(false);
    expect(p.promise).not.toBeNull();
    expect(equal(p.promise!, held[0]!.promise)).toBe(true);
    expect(await journal.outbox()).toEqual([]);
    expect(prompts(wallet)).toBe(1);
  });

  it('scans at most the last BATCH_RETENTION closed epochs when reconciling', async () => {
    const { node, svc } = await setup({ firstEpoch: 1500n });
    const before = node.fake.requests.length;
    await svc.reconcile(0n);
    const scanned = node.fake.requests
      .slice(before)
      .map((r) => /\/epochs\/(\d+)$/.exec(r.path)?.[1])
      .filter((x) => x !== undefined)
      .map(BigInt);
    const last = node.open - 1n;
    expect(scanned).toContain(last);
    expect(scanned).toContain(last - 1023n);
    expect(scanned.every((e) => e > last - 1024n)).toBe(true);
  });

  it('flags a wallet that switches accounts while signing, sending nothing', async () => {
    const { node, svc } = await setup({ behaviour: 'account_switching' });
    await expect(svc.submit(svc.prepare(draft(node)))).rejects.toMatchObject({
      kind: 'wallet',
      code: 'account_changed',
    });
    expect(node.submitted).toEqual([]);
  });

  it('tears down on an account switch and re-resolves the journal and session', async () => {
    const { node, seed, wallet, svc, session, journal, clock } = await setup();
    const r = await svc.submit(svc.prepare(draft(node)));
    expect(await rememberSession(session, journal)).toBe(true);
    wallet.switchAccount(new Uint8Array(32).fill(0x42));
    await vi.waitFor(() => expect(list(svc)).toEqual([]));
    expect(() => svc.prepare(draft(node))).toThrow(/start/);

    node.fund(wallet.address, 10n ** 12n, 10n ** 12n);
    const info = await node.api.info();
    const other = await TradingSession.open({
      api: node.api,
      wallet,
      info,
      clock,
      market: node.market,
    });
    expect(await svc.start(wallet, other)).toEqual({ role: 'leader' });
    expect(list(svc)).toEqual([]);

    wallet.switchAccount(seed);
    await vi.waitFor(() => expect(list(svc).map((x) => x.id)).toEqual([r.id]));
    await vi.waitFor(() => expect(() => svc.prepare(draft(node))).not.toThrow());
  });
});
