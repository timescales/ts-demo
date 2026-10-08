// The verifier checks one by one, on consistent objects from the in-memory node
// and on tampered copies re-signed with its keys. Every verifier returns a
// Verdict and never throws, including on random bytes.
import type { Address } from '@solana/kit';
import { ed25519 } from '@noble/curves/ed25519.js';
import fc from 'fast-check';
import { describe, expect, it } from 'vitest';
import type { EpochKey, MarketDetail } from '../src/api/index.js';
import {
  ackDigest,
  announcementDigest,
  b58,
  band as bandOf,
  batchRootV2,
  committeeDigest,
  decodeAnnouncement,
  decodeArtifacts,
  decodeBundle,
  decodeReceipt,
  ed25519PublicKey,
  ed25519Sign,
  encodeAnnouncement,
  encodeArtifacts,
  encodeBalanceSheet,
  encodeBundle,
  encodeCommittee,
  encodeLeaves,
  encodePolicyStatement,
  encodePromiseV2,
  encodeReceipt,
  encodeRelayRefusal,
  envelopeDigest,
  epochAnnouncementDigest,
  fromUtf8,
  hex,
  policyDigest,
  promiseV2Digest,
  receiptDigest,
  relayRefusalDigest,
  Writer,
  type BatchLeaf,
  type EpochKeyBundle,
} from '../src/core/index.js';
import {
  decodePending,
  type BatchAccount,
  type MarketAccount,
  type Observed,
  type TraderAccount,
} from '../src/solana/accounts.js';
import { batchPda } from '../src/solana/index.js';
import { createTestRng } from '../src/testing/index.js';
import { createFakeNode, type FakeNode } from '../src/testing/node.js';
import {
  checkInclusion,
  decodePendingChange,
  ownFills,
  verifyAnnouncement,
  verifyArtifacts,
  verifyCommittee,
  verifyEpochKey,
  verifyMarket,
  verifyOwnBalance,
  verifyPolicies,
  verifyProgram,
  verifyPromise,
  verifyReceipt,
  type AppPins,
  type Verdict,
} from '../src/verify/index.js';
import { checkCommittedTerms } from '../src/verify/announcement.js';
import { canonicalJson, parseEvidence } from '../src/verify/evidence.js';
import { verifyPromiseDigest, verifyRefusal } from '../src/verify/promise.js';

let counter = 0;

async function fixture(o: Parameters<typeof createFakeNode>[0] = {}) {
  counter++;
  const node = createFakeNode({
    seed: createTestRng(new Uint8Array([counter, 0x5e])).bytes(32),
    ...o,
  });
  const detail = await node.api.market(node.market);
  const chain = await node.rpc.market(node.market, detail.chain.contextSlot);
  const mint = (await node.rpc.account(chain.value.baseMint))!.value;
  const current = await node.api.current(node.market);
  const v2 = verifyCommittee(detail.committee.descriptionBytes, chain.value);
  if (v2.kind !== 'ok') throw new Error(`fixture committee: ${v2.kind}`);
  const committee = v2.value;
  return {
    node,
    detail,
    chain,
    mints: { base: mint, quote: mint },
    current,
    committee,
    pins: node.pins,
  };
}

function kindOf(v: Verdict<unknown>): string {
  return v.kind;
}

function reasonOf(v: Verdict<unknown>): string {
  return v.kind === 'ok' ? '' : v.reason;
}

const otherAddress = b58.encode(new Uint8Array(32).fill(0x31)) as Address;

/** Re-signs a bundle's acks with the committee members' keys, keeping their policy digests. */
function resign(node: FakeNode, b: EpochKeyBundle, members = node.secrets.members): Uint8Array {
  const digest = announcementDigest(b.announcement);
  const acks = members.map((m) => {
    const pd = b.acks.find((a) => a.member === m.index)?.policyDigest ?? new Uint8Array(32);
    return {
      member: m.index,
      policyDigest: pd,
      signature: ed25519Sign(m.seed, ackDigest(digest, pd)),
    };
  });
  return encodeBundle({ announcement: b.announcement, acks });
}

describe('V-1 market', () => {
  it('accepts the node and the RPC agreeing at one slot', async () => {
    const f = await fixture();
    const v = verifyMarket(f.detail, f.chain, f.mints, f.pins);
    expect(v).toEqual({ kind: 'ok', value: { freezeWarnings: [] } });
  });

  it('fails on any immutable difference', async () => {
    const f = await fixture();
    const d = (patch: Partial<MarketDetail>) =>
      verifyMarket({ ...f.detail, ...patch }, f.chain, f.mints, f.pins);
    expect(reasonOf(d({ creator: otherAddress }))).toMatch(/creator/);
    expect(reasonOf(d({ marketIdSalt: new Uint8Array(32) }))).toMatch(/salt/);
    expect(reasonOf(d({ baseVault: otherAddress }))).toMatch(/vaults/);
    expect(reasonOf(d({ paramsBytes: new Uint8Array(46) }))).toMatch(/params/);
    expect(reasonOf(d({ baseDecimals: 9 }))).toMatch(/decimals/);
    expect(
      reasonOf(verifyMarket(f.detail, f.chain, f.mints, { ...f.pins, market: otherAddress })),
    ).toMatch(/pinned market/);
    const chain = { ...f.chain, value: { ...f.chain.value, salt: new Uint8Array(32).fill(1) } };
    expect(reasonOf(verifyMarket(f.detail, chain, f.mints, f.pins))).toMatch(/market id/);
    expect(
      reasonOf(verifyMarket(f.detail, f.chain, f.mints, { ...f.pins, programId: otherAddress })),
    ).toMatch(/market id/);
  });

  it('treats slow fields slot-aware and volatile fields as monotone', async () => {
    const f = await fixture();
    const later = { ...f.chain, contextSlot: f.chain.contextSlot + 5n };
    const relayed = { ...f.detail, relay: otherAddress };
    expect(kindOf(verifyMarket(relayed, f.chain, f.mints, f.pins))).toBe('fail');
    expect(kindOf(verifyMarket(relayed, later, f.mints, f.pins))).toBe('inconclusive');
    const behind = { ...f.chain, contextSlot: f.chain.contextSlot - 1n };
    expect(kindOf(verifyMarket(f.detail, behind, f.mints, f.pins))).toBe('inconclusive');
    const progressed = {
      ...later,
      value: { ...later.value, lastCommitted: later.value.lastCommitted + 1n },
    };
    expect(kindOf(verifyMarket(f.detail, progressed, f.mints, f.pins))).toBe('ok');
    const back = {
      ...f.detail,
      chain: { ...f.detail.chain, lastCommitted: f.detail.chain.lastCommitted + 1n },
    };
    expect(reasonOf(verifyMarket(back, later, f.mints, f.pins))).toMatch(/backwards/);
    expect(reasonOf(verifyMarket(back, f.chain, f.mints, f.pins))).toMatch(/same slot/);
  });

  it('reports a freeze authority on a mint and holds the node to the mints’ authorities', async () => {
    const f = await fixture();
    const freezer = b58.encode(new Uint8Array(32).fill(7)) as Address;
    const frozen = new Writer()
      .u32(0)
      .fixed(new Uint8Array(32), 32)
      .u64(1n)
      .u8(6)
      .bool(true)
      .u32(1)
      .fixed(b58.decode(freezer, 32), 32)
      .finish();
    const mints = { base: f.mints.base, quote: frozen };
    const reported = {
      ...f.detail,
      mintAuthorities: { ...f.detail.mintAuthorities, quote: { mint: null, freeze: freezer } },
    };
    expect(verifyMarket(reported, f.chain, mints, f.pins)).toEqual({
      kind: 'ok',
      value: { freezeWarnings: ['quote'] },
    });
    // A node that hides the freeze authority (or reports another) fails at its own slot.
    expect(reasonOf(verifyMarket(f.detail, f.chain, mints, f.pins))).toMatch(/mint authorities/);
    const later = { ...f.chain, contextSlot: f.chain.contextSlot + 5n };
    expect(kindOf(verifyMarket(f.detail, later, mints, f.pins))).toBe('inconclusive');
    const other = {
      ...f.detail,
      mintAuthorities: {
        ...f.detail.mintAuthorities,
        base: { ...f.detail.mintAuthorities.base, mint: otherAddress },
      },
    };
    expect(kindOf(verifyMarket(other, f.chain, f.mints, f.pins))).toBe('fail');
  });
});

describe('V-2 committee', () => {
  it('checks the digest, the market and n <= 2t - 1', async () => {
    const f = await fixture();
    expect(verifyCommittee(f.detail.committee.descriptionBytes, f.chain.value).kind).toBe('ok');
    const raw = f.detail.committee.descriptionBytes.slice();
    raw[raw.length - 1]! ^= 1;
    expect(reasonOf(verifyCommittee(raw, f.chain.value))).toMatch(/digest/);
    const keys = [1, 2].map((i) => ed25519PublicKey(new Uint8Array(32).fill(i)));
    const loose = encodeCommittee({
      version: 1,
      market: b58.decode(f.node.market, 32),
      threshold: 1,
      members: keys.map((k, i) => ({
        index: i + 1,
        identity: k,
        transport: new Uint8Array(32).fill(i + 9),
      })),
    });
    const chain = { ...f.chain.value, committeeDigest: committeeDigest(loose) };
    expect(reasonOf(verifyCommittee(loose, chain))).toMatch(/disjoint quorums/);
    const prev = {
      ...f.chain.value,
      committeeDigest: new Uint8Array(32).fill(4),
      prevCommitteeDigest: f.chain.value.committeeDigest,
    };
    expect(
      verifyCommittee(f.detail.committee.descriptionBytes, prev, f.chain.value.committeeDigest)
        .kind,
    ).toBe('ok');
    expect(kindOf(verifyCommittee(f.detail.committee.descriptionBytes, prev))).toBe('fail');
  });
});

describe('V-3 epoch key', () => {
  it('accepts a vouched Feldman key and refuses every structural defect', async () => {
    const f = await fixture();
    const k = f.current.open!.key;
    const epoch = k.epoch;
    const ok = verifyEpochKey(k, f.committee, f.chain.value, epoch, f.pins);
    expect(ok.kind).toBe('ok');
    const b = decodeBundle(k.bundleBytes);
    const withBundle = (x: EpochKeyBundle, pk = x.announcement.epochPk): EpochKey => ({
      ...k,
      epochPk: pk,
      bundleBytes: resign(f.node, x),
    });
    // Fewer than t acks.
    const thin = { ...b, acks: b.acks.slice(0, 1) };
    expect(
      reasonOf(
        verifyEpochKey(
          { ...k, bundleBytes: encodeBundle(thin) },
          f.committee,
          f.chain.value,
          epoch,
          f.pins,
        ),
      ),
    ).toMatch(/fewer than t/);
    // u(C_0) is not the epoch key.
    const wrongPk = {
      ...b,
      announcement: { ...b.announcement, epochPk: new Uint8Array(32).fill(5) },
    };
    expect(
      reasonOf(verifyEpochKey(withBundle(wrongPk), f.committee, f.chain.value, epoch, f.pins)),
    ).toMatch(/u\(C_0\)/);
    // C_0 with a torsion component, and a non-canonical commitment.
    const torsion = ed25519.Point.fromBytes(
      hex.decode('26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05'),
    );
    const c0 = ed25519.Point.fromBytes(b.announcement.commitments[0]!).add(torsion).toBytes();
    const twisted = {
      ...b,
      announcement: {
        ...b.announcement,
        commitments: [c0, ...b.announcement.commitments.slice(1)],
      },
    };
    expect(
      reasonOf(verifyEpochKey(withBundle(twisted), f.committee, f.chain.value, epoch, f.pins)),
    ).toMatch(/prime-order/);
    const nonCanonical = hex.decode(
      'edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f',
    );
    const odd = {
      ...b,
      announcement: {
        ...b.announcement,
        commitments: [b.announcement.commitments[0]!, nonCanonical],
      },
    };
    expect(
      reasonOf(verifyEpochKey(withBundle(odd), f.committee, f.chain.value, epoch, f.pins)),
    ).toMatch(/canonical/);
    const identity = hex.decode('0100000000000000000000000000000000000000000000000000000000000000');
    const flat = {
      ...b,
      announcement: { ...b.announcement, commitments: [b.announcement.commitments[0]!, identity] },
    };
    expect(
      reasonOf(verifyEpochKey(withBundle(flat), f.committee, f.chain.value, epoch, f.pins)),
    ).toMatch(/prime-order/);
    // Another committee or another epoch.
    const foreign = {
      ...b,
      announcement: { ...b.announcement, committeeDigest: new Uint8Array(32).fill(1) },
    };
    expect(
      kindOf(
        verifyEpochKey(
          { ...withBundle(foreign), committeeDigest: foreign.announcement.committeeDigest },
          f.committee,
          f.chain.value,
          epoch,
          f.pins,
        ),
      ),
    ).toBe('fail');
    expect(reasonOf(verifyEpochKey(k, f.committee, f.chain.value, epoch + 1n, f.pins))).toMatch(
      /another epoch/,
    );
  });

  it('accepts the development scheme only on a localnet pin', async () => {
    const f = await fixture({ scheme: 'dev' });
    const k = f.current.open!.key;
    expect(verifyEpochKey(k, f.committee, f.chain.value, k.epoch, f.pins).kind).toBe('fail');
    expect(
      verifyEpochKey(k, f.committee, f.chain.value, k.epoch, { ...f.pins, cluster: 'localnet' })
        .kind,
    ).toBe('ok');
  });
});

describe('V-4 announcement and terms', () => {
  it('checks the relay signature, the key, the committee and the band', async () => {
    const f = await fixture();
    const open = f.current.open!;
    const bundle = decodeBundle(open.key.bundleBytes);
    const v = verifyAnnouncement(
      open.announcementBytes,
      f.chain.value,
      f.chain.value.params,
      bundle,
    );
    expect(v.kind).toBe('ok');
    if (v.kind === 'ok') {
      expect(hex.encode(v.value.binding)).toBe(hex.encode(open.binding));
      expect(hex.encode(v.value.terms)).toBe(hex.encode(open.termsDigest));
    }
    const a = decodeAnnouncement(open.announcementBytes);
    const sign = (x: typeof a, seed = f.node.secrets.relay) =>
      encodeAnnouncement({ ...x, signature: ed25519Sign(seed, epochAnnouncementDigest(x)) });
    expect(
      reasonOf(
        verifyAnnouncement(
          sign(a, new Uint8Array(32).fill(3)),
          f.chain.value,
          f.chain.value.params,
          bundle,
        ),
      ),
    ).toMatch(/not signed/);
    const wide = { ...a, band: { ...a.band, hi: a.band.hi + 1n } };
    expect(
      reasonOf(verifyAnnouncement(sign(wide), f.chain.value, f.chain.value.params, bundle)),
    ).toMatch(/band/);
    const otherKey = { ...a, keyDigest: new Uint8Array(32).fill(2) };
    expect(
      reasonOf(verifyAnnouncement(sign(otherKey), f.chain.value, f.chain.value.params, bundle)),
    ).toMatch(/epoch key/);
    expect(bandOf(f.chain.value.params, a.band.reference)).toEqual(a.band);
  });

  it('compares the committed terms after commit and keeps the evidence', async () => {
    const f = await fixture();
    const open = f.current.open!;
    const batch = (terms: Uint8Array) =>
      ({
        value: {
          termsDigest: terms,
          market: f.node.market,
          epoch: open.epoch,
          address: f.node.market,
          root: new Uint8Array(32),
          count: 1,
        } as BatchAccount,
        contextSlot: 9n,
        commitment: 'confirmed',
      }) as Observed<BatchAccount>;
    expect(kindOf(checkCommittedTerms(open.announcementBytes, open.termsDigest, null))).toBe(
      'inconclusive',
    );
    expect(
      kindOf(
        checkCommittedTerms(open.announcementBytes, open.termsDigest, batch(open.termsDigest)),
      ),
    ).toBe('ok');
    const v = checkCommittedTerms(
      open.announcementBytes,
      open.termsDigest,
      batch(new Uint8Array(32)),
    );
    expect(v.kind).toBe('fail');
    const doc = parseEvidence((v as { evidence: Uint8Array }).evidence);
    expect(doc.kind).toBe('terms');
    expect(doc.expected_terms_digest).toBe(hex.encode(open.termsDigest));
  });
});

describe('V-5 promise and refusals', () => {
  it('verifies against the relay in force at submission', async () => {
    const f = await fixture();
    const relay = f.node.secrets.relay;
    const envelope = new Uint8Array(289).fill(7);
    const c = new Uint8Array(32).fill(8);
    const unsigned = {
      market: b58.decode(f.node.market, 32),
      epoch: 4n,
      commitment: c,
      envelopeDigest: envelopeDigest(envelope),
      relay: ed25519PublicKey(relay),
      signature: new Uint8Array(64),
    };
    const raw = encodePromiseV2({
      ...unsigned,
      signature: ed25519Sign(relay, promiseV2Digest(unsigned)),
    });
    const expect5 = {
      market: f.node.market,
      epoch: 4n,
      commitment: c,
      envelope,
      relay: f.node.relay,
    };
    expect(verifyPromise(raw, expect5).kind).toBe('ok');
    expect(reasonOf(verifyPromise(raw, { ...expect5, envelope: new Uint8Array(289) }))).toMatch(
      /another envelope/,
    );
    expect(reasonOf(verifyPromise(raw, { ...expect5, relay: otherAddress }))).toMatch(
      /another relay/,
    );
    expect(reasonOf(verifyPromise(raw, { ...expect5, epoch: 5n }))).toMatch(/another epoch/);
    expect(kindOf(verifyPromise(raw.subarray(0, 200), expect5))).toBe('fail');
    const v1 = raw.slice();
    v1[0] = 1;
    expect(kindOf(verifyPromise(v1, expect5))).toBe('fail');
    const forged = raw.slice();
    forged[forged.length - 1]! ^= 1;
    expect(reasonOf(verifyPromise(forged, expect5))).toMatch(/not signed/);
    expect(kindOf(verifyPromise(raw, { ...expect5, envelope: new Uint8Array(10) }))).toBe('fail');
    // The original promise for bytes another tab submitted: any envelope digest.
    expect(verifyPromiseDigest(raw, { ...expect5, envelopeDigest: null }).kind).toBe('ok');

    const r = {
      market: b58.decode(f.node.market, 32),
      epoch: 4n,
      envelopeDigest: envelopeDigest(envelope),
      code: 1,
      atMs: 5n,
      relay: ed25519PublicKey(relay),
      signature: new Uint8Array(64),
    };
    const refusal = encodeRelayRefusal({
      ...r,
      signature: ed25519Sign(relay, relayRefusalDigest(r)),
    });
    const er = {
      market: f.node.market,
      epoch: 4n,
      envelopeDigest: envelopeDigest(envelope),
      relay: f.node.relay,
    };
    expect(verifyRefusal(refusal, er).kind).toBe('ok');
    expect(kindOf(verifyRefusal(refusal, { ...er, epoch: 3n }))).toBe('fail');
  });
});

describe('V-6 inclusion', () => {
  it('finds the own leaf, or saves exclusion or substitution evidence', async () => {
    const f = await fixture();
    const relay = f.node.secrets.relay;
    const own: BatchLeaf = {
      commitment: new Uint8Array(32).fill(1),
      envelopeDigest: new Uint8Array(32).fill(2),
    };
    const others: BatchLeaf[] = [3, 4, 5].map((i) => ({
      commitment: new Uint8Array(32).fill(i),
      envelopeDigest: new Uint8Array(32).fill(i + 10),
    }));
    const unsigned = {
      market: b58.decode(f.node.market, 32),
      epoch: 7n,
      commitment: own.commitment,
      envelopeDigest: own.envelopeDigest,
      relay: ed25519PublicKey(relay),
      signature: new Uint8Array(64),
    };
    const promise = encodePromiseV2({
      ...unsigned,
      signature: ed25519Sign(relay, promiseV2Digest(unsigned)),
    });
    const batchFor = (leaves: BatchLeaf[], count = leaves.length): Observed<BatchAccount> => ({
      value: {
        address: otherAddress,
        market: f.node.market,
        epoch: 7n,
        root: batchRootV2(leaves),
        count,
        termsDigest: new Uint8Array(32).fill(6),
      } as BatchAccount,
      contextSlot: 50n,
      commitment: 'confirmed',
    });
    const check = (leaves: BatchLeaf[], batch: Observed<BatchAccount> | null = batchFor(leaves)) =>
      checkInclusion(own, promise, f.node.relay, encodeLeaves(leaves), batch);
    expect(check([own, ...others])).toEqual({ kind: 'ok', value: { status: 'included' } });
    const excluded = check(others);
    expect(excluded.kind === 'ok' && excluded.value.status).toBe('excluded');
    const doc = parseEvidence((excluded as { value: { evidence: Uint8Array } }).value.evidence);
    expect(doc).toMatchObject({
      kind: 'exclusion',
      commitment: hex.encode(own.commitment),
      relay_at_submission: f.node.relay,
      batch: { epoch: '7', count: 3, slot: '50' },
    });
    const swapped = check([
      { commitment: own.commitment, envelopeDigest: new Uint8Array(32).fill(9) },
      ...others,
    ]);
    expect(swapped.kind === 'ok' && swapped.value.status).toBe('substituted');
    expect(kindOf(check([own], null))).toBe('inconclusive');
    expect(reasonOf(check([own, ...others], batchFor([own, ...others], 9)))).toMatch(/count/);
    expect(reasonOf(check([own, ...others], batchFor(others, 4)))).toMatch(/root/);
    expect(
      kindOf(
        checkInclusion(
          own,
          promise.subarray(1),
          f.node.relay,
          encodeLeaves(others),
          batchFor(others),
        ),
      ),
    ).toBe('fail');
  });
});

describe('V-7, V-8 and V-9: receipt, artifacts and own fills', () => {
  async function posted(quorum = 1) {
    const f = await fixture({ receiptQuorum: quorum });
    const n = f.node.open;
    const trader = new Uint8Array(32).fill(0x21);
    const order = {
      market: f.node.marketId,
      trader,
      nonce: 1n,
      side: 0 as const,
      role: 0 as const,
      kind: 0 as const,
      limit: f.node.band.reference,
      quantity: 6n,
      validFrom: n,
      expiresAt: n,
    };
    const c = new Uint8Array(32).fill(0x22);
    f.node.closeEpoch();
    f.node.commit(n);
    f.node.reveal(n);
    const tick = f.node.band.reference;
    f.node.post(n, {
      fills: [
        { commitment: c, trader, side: 0, role: 0, quantity: 4n, tick },
        {
          commitment: new Uint8Array(32).fill(0x23),
          trader: new Uint8Array(32).fill(0x24),
          side: 1,
          role: 1,
          quantity: 4n,
          tick,
        },
      ],
    });
    const detail = await f.node.api.epoch(f.node.market, n);
    const [address] = await batchPda(f.node.program, f.node.market, n);
    const batch = (await f.node.rpc.batch(address))!;
    const market = (await f.node.rpc.market(f.node.market)).value;
    return { ...f, n, c, order, detail, batch, market };
  }

  it('verifies the posted receipt and reports the live quorum', async () => {
    const p = await posted(2);
    const v = verifyReceipt(p.detail.receiptBytes!, p.detail.headerBytes!, {
      market: p.market,
      batch: p.batch,
    });
    expect(v.kind).toBe('ok');
    expect(v.kind === 'ok' && v.value.quorum).toEqual({ have: 1, need: 2, met: false });
    // A removed executor's signature stops counting.
    const removed = {
      ...p.market,
      executors: p.market.executors.map((e, i) => (i === 0 ? null : e)),
    };
    expect(
      reasonOf(
        verifyReceipt(p.detail.receiptBytes!, p.detail.headerBytes!, {
          market: removed,
          batch: p.batch,
        }),
      ),
    ).toMatch(/not registered/);
    const forged = p.detail.receiptBytes!.slice();
    forged[forged.length - 1]! ^= 1;
    expect(
      reasonOf(verifyReceipt(forged, p.detail.headerBytes!, { market: p.market, batch: p.batch })),
    ).toMatch(/not signed/);
    const header = p.detail.headerBytes!.slice();
    header[header.length - 1]! ^= 1;
    expect(
      kindOf(verifyReceipt(p.detail.receiptBytes!, header, { market: p.market, batch: p.batch })),
    ).toBe('fail');
    const early = { ...p.batch, value: { ...p.batch.value, receipt: null } };
    expect(
      kindOf(
        verifyReceipt(p.detail.receiptBytes!, p.detail.headerBytes!, {
          market: p.market,
          batch: early,
        }),
      ),
    ).toBe('inconclusive');
    // A receipt re-signed by an executor whose digest is not the one on chain.
    const r = decodeReceipt(p.detail.receiptBytes!);
    const other = { ...r, outcome: { ...r.outcome, fees: r.outcome.fees + 1n } };
    const unsigned = encodeReceipt(other);
    const resigned = encodeReceipt({
      ...other,
      signature: ed25519Sign(p.node.secrets.executors[0]!, receiptDigest(unsigned)),
    });
    expect(
      reasonOf(
        verifyReceipt(resigned, p.detail.headerBytes!, { market: p.market, batch: p.batch }),
      ),
    ).toMatch(/posted on chain/);
  });

  it('recomputes the artifacts and the own fills', async () => {
    const p = await posted();
    const receipt = decodeReceipt(p.detail.receiptBytes!);
    const art = await p.node.api.artifacts(p.node.market, p.n);
    const a = verifyArtifacts(art.artifactsBytes, receipt, p.market.params, p.n);
    expect(a.kind).toBe('ok');
    const decoded = decodeArtifacts(art.artifactsBytes);
    const tampered = encodeArtifacts({
      ...decoded,
      fills: decoded.fills.map((x, i) => (i === 0 ? { ...x, quantity: x.quantity + 1n } : x)),
    });
    expect(reasonOf(verifyArtifacts(tampered, receipt, p.market.params, p.n))).toMatch(/fills/);
    const fees = encodeArtifacts({
      ...decoded,
      settlement: { ...decoded.settlement, fees: decoded.settlement.fees + 1n },
    });
    expect(kindOf(verifyArtifacts(fees, receipt, p.market.params, p.n))).toBe('fail');
    expect(kindOf(verifyArtifacts(art.artifactsBytes, receipt, p.market.params, p.n + 1n))).toBe(
      'fail',
    );

    const artifacts = (a as { value: typeof decoded }).value;
    const mine = [{ commitment: p.c, order: p.order, filledBefore: 0n }];
    const v = ownFills(artifacts, receipt, mine, p.market.params);
    expect(v.kind).toBe('ok');
    if (v.kind === 'ok') {
      expect(v.value.fills.map((x) => x.quantity)).toEqual([4n]);
      const notional = 4n * p.node.band.reference * p.market.params.tickSize;
      const fee = (notional * BigInt(p.market.params.makerFeeBps)) / 10_000n;
      expect(v.value.delta).toEqual({
        base: 4n * p.market.params.baseLotSize,
        quote: -(notional + fee),
      });
      expect(v.value.fills[0]!.feeQuote).toBe(fee);
    }
    expect(
      reasonOf(ownFills(artifacts, receipt, [{ ...mine[0]!, filledBefore: 3n }], p.market.params)),
    ).toMatch(/beyond its quantity/);
    const below = { ...p.order, limit: p.node.band.reference - 1n };
    expect(
      reasonOf(ownFills(artifacts, receipt, [{ ...mine[0]!, order: below }], p.market.params)),
    ).toMatch(/limit/);
    const seller = { ...p.order, side: 1 as const };
    expect(
      reasonOf(ownFills(artifacts, receipt, [{ ...mine[0]!, order: seller }], p.market.params)),
    ).toMatch(/side or role/);
    expect(
      ownFills(
        artifacts,
        receipt,
        [{ ...mine[0]!, commitment: new Uint8Array(32) }],
        p.market.params,
      ),
    ).toEqual({
      kind: 'ok',
      value: { fills: [], delta: { base: 0n, quote: 0n } },
    });
  });
});

describe('V-13 governance', () => {
  it('decodes every pending change and marks decreases', async () => {
    const f = await fixture();
    const m: MarketAccount = { ...f.chain.value, receiptQuorum: 2, timelockSlots: 216_000n };
    const key = (i: number) => new Uint8Array(32).fill(i);
    const cases: [number, Uint8Array, Record<string, unknown>][] = [
      [1, key(1), { kind: 'set_relay', relay: b58.encode(key(1)) }],
      [
        2,
        new Writer().u8(2).fixed(key(1), 32).fixed(key(2), 32).u8(1).finish(),
        { kind: 'set_executors', quorum: 1, quorumDecrease: true },
      ],
      [3, key(3), { kind: 'set_committee_digest' }],
      [4, key(4), { kind: 'set_admin', admin: b58.encode(key(4)) }],
      [
        5,
        new Writer().u16(8).u64(750n).u64(9000n).finish(),
        { kind: 'set_timings', beaconDelaySlots: 8, execTimeoutSlots: 750n },
      ],
      [6, new Writer().u64(1000n).finish(), { kind: 'set_timelock', slots: 1000n, decrease: true }],
    ];
    for (const [kind, payload, want] of cases) {
      const pending = decodePending(kind, 99n, payload, m);
      expect(decodePendingChange({ ...m, pending })).toMatchObject({ etaSlot: 99n, ...want });
    }
    expect(() =>
      decodePending(2, 1n, new Writer().u8(1).fixed(key(1), 32).u8(2).finish(), m),
    ).toThrow();
    expect(() => decodePending(7, 1n, new Uint8Array(0), m)).toThrow();
    expect(decodePendingChange({ ...m, pending: null })).toBeNull();
  });
});

describe('V-14 policies', () => {
  it('labels the enclave from members’ signed release policies', async () => {
    const f = await fixture();
    const bundle = decodeBundle(f.current.open!.key.bundleBytes);
    const statements = f.detail.committee.policiesBytes;
    expect(verifyPolicies(statements, f.committee, bundle)).toEqual({
      kind: 'ok',
      value: { enclaveLabel: 'simulated' },
    });
    expect(verifyPolicies([], f.committee, bundle)).toEqual({
      kind: 'ok',
      value: { enclaveLabel: 'operator_reported' },
    });

    // TDX-only statements from every member, carried by their acks.
    const digestOfCommittee = committeeDigest(encodeCommittee(f.committee));
    const tdx = f.node.secrets.members.map((m) => {
      const unsigned = {
        market: b58.decode(f.node.market, 32),
        member: m.index,
        committeeDigest: digestOfCommittee,
        platforms: { simulated: false, intelTdx: true },
        measurementSetDigest: new Uint8Array(32).fill(1),
        allowDebug: false,
        minTcb: 3,
        mrConfigId: new Uint8Array(48),
        fromEpoch: 0n,
        signature: new Uint8Array(64),
      };
      const raw = encodePolicyStatement(unsigned);
      return encodePolicyStatement({
        ...unsigned,
        signature: ed25519Sign(m.seed, policyDigest(raw)),
      });
    });
    const digest = announcementDigest(bundle.announcement);
    const tdxBundle: EpochKeyBundle = {
      announcement: bundle.announcement,
      acks: f.node.secrets.members.map((m, i) => ({
        member: m.index,
        policyDigest: policyDigest(tdx[i]!),
        signature: ed25519Sign(m.seed, ackDigest(digest, policyDigest(tdx[i]!))),
      })),
    };
    expect(verifyPolicies(tdx, f.committee, tdxBundle)).toEqual({
      kind: 'ok',
      value: { enclaveLabel: 'intel_tdx_vouched' },
    });
    // Acks that carry other digests do not vouch, whatever the statements say.
    expect(verifyPolicies(tdx, f.committee, bundle)).toEqual({
      kind: 'ok',
      value: { enclaveLabel: 'operator_reported' },
    });
    // A statement claiming a member but signed by another one fails.
    const stolen = tdx[0]!.slice();
    stolen.set(tdx[1]!.subarray(tdx[1]!.length - 64), stolen.length - 64);
    expect(reasonOf(verifyPolicies([stolen], f.committee, tdxBundle))).toMatch(/not signed/);
  });
});

describe('V-15 own balance entry', () => {
  const market = b58.encode(new Uint8Array(32).fill(0x61)) as Address;
  const owner = b58.encode(new Uint8Array(32).fill(0x62)) as Address;
  const trader = (t: Partial<TraderAccount>): Observed<TraderAccount> => ({
    value: {
      address: otherAddress,
      market,
      owner,
      base: 100n,
      quote: 1000n,
      requestedBase: 0n,
      requestedQuote: 0n,
      requestEpoch: 0n,
      lastLeafEpoch: 0n,
      lastChangeSlot: 10n,
      floorEpoch: 0n,
      floorBase: 0n,
      floorQuote: 0n,
      ...t,
    },
    contextSlot: 99n,
    commitment: 'confirmed',
  });
  const batch = (b: Partial<BatchAccount> = {}) =>
    ({
      market,
      epoch: 5n,
      commitSlot: 20n,
      status: 'receipt_posted',
      appliedCount: 0,
      ...b,
    }) as BatchAccount;
  const sheet = (base: bigint, quote: bigint) =>
    encodeBalanceSheet([{ trader: b58.decode(owner, 32), base, quote }]);

  it('equals the available balance when the account did not change since the commit', () => {
    expect(verifyOwnBalance(sheet(100n, 1000n), trader({}), batch(), 5n).kind).toBe('ok');
    expect(kindOf(verifyOwnBalance(sheet(99n, 1000n), trader({}), batch(), 5n))).toBe('fail');
    expect(kindOf(verifyOwnBalance(encodeBalanceSheet([]), trader({}), batch(), 5n))).toBe('fail');
    // A withdrawal requested before the epoch reserves its amount.
    const reserving = trader({ requestedQuote: 300n, requestEpoch: 4n });
    expect(verifyOwnBalance(sheet(100n, 700n), reserving, batch(), 5n).kind).toBe('ok');
    expect(kindOf(verifyOwnBalance(sheet(100n, 1000n), reserving, batch(), 5n))).toBe('fail');
  });

  it('lies between the floor and the current balance after a change', () => {
    const changed = trader({
      lastChangeSlot: 30n,
      floorEpoch: 5n,
      floorBase: 50n,
      floorQuote: 500n,
    });
    expect(verifyOwnBalance(sheet(60n, 900n), changed, batch(), 5n).kind).toBe('ok');
    expect(kindOf(verifyOwnBalance(sheet(40n, 900n), changed, batch(), 5n))).toBe('fail');
    expect(kindOf(verifyOwnBalance(sheet(160n, 900n), changed, batch(), 5n))).toBe('fail');
    expect(
      kindOf(verifyOwnBalance(sheet(60n, 900n), changed, batch({ appliedCount: 1 }), 5n)),
    ).toBe('inconclusive');
    expect(kindOf(verifyOwnBalance(sheet(60n, 900n), changed, batch(), 6n))).toBe('fail');
  });
});

describe('V-16 program', () => {
  it('pins the upgrade authority and flags a recent deploy', async () => {
    const f = await fixture();
    const pd = (authority: Address | null, slot: bigint) => {
      const w = new Writer()
        .u32(3)
        .u64(slot)
        .u8(authority === null ? 0 : 1);
      return w
        .fixed(authority === null ? new Uint8Array(32) : b58.decode(authority, 32), 32)
        .finish();
    };
    const pins: AppPins = f.pins;
    const m = f.chain.value;
    expect(
      verifyProgram(pd(pins.upgradeAuthority, 10n), pins, m, 10n + m.timelockSlots + 1n),
    ).toEqual({
      kind: 'ok',
      value: { recentUpgrade: false },
    });
    expect(verifyProgram(pd(pins.upgradeAuthority, 10n), pins, m, 11n)).toEqual({
      kind: 'ok',
      value: { recentUpgrade: true },
    });
    expect(reasonOf(verifyProgram(pd(otherAddress, 10n), pins, m, 11n))).toMatch(
      /upgrade authority/,
    );
    expect(
      verifyProgram(pd(null, 10n), { ...pins, upgradeAuthority: null }, m, 10n ** 9n).kind,
    ).toBe('ok');
    expect(kindOf(verifyProgram(pd(null, 10n), pins, m, 10n ** 9n))).toBe('fail');
    const bad = pd(null, 1n);
    bad[0] = 2;
    expect(kindOf(verifyProgram(bad, pins, m, 1n))).toBe('fail');
  });
});

describe('evidence', () => {
  it('is canonical JSON: sorted keys, no whitespace, stable bytes', () => {
    expect(canonicalJson({ b: 1, a: [true, null, 'x'], c: { z: 2, y: 1 } })).toBe(
      '{"a":[true,null,"x"],"b":1,"c":{"y":1,"z":2}}',
    );
    expect(() => canonicalJson(Number.NaN)).toThrow();
    expect(() => parseEvidence(new TextEncoder().encode('[1]'))).toThrow();
    expect(fromUtf8(new TextEncoder().encode(canonicalJson({ k: 'v' })))).toBe('{"k":"v"}');
  });
});

describe('verifiers never throw on adversarial input', () => {
  it('returns a Verdict for random bytes', async () => {
    const f = await fixture();
    const bundle = decodeBundle(f.current.open!.key.bundleBytes);
    const empty = {
      value: {
        market: f.node.market,
        epoch: 1n,
        root: new Uint8Array(32),
        count: 1,
      } as BatchAccount,
      contextSlot: 1n,
      commitment: 'confirmed' as const,
    };
    const trader = {
      value: {
        market: f.node.market,
        owner: f.node.market,
        base: 0n,
        quote: 0n,
        requestedBase: 0n,
        requestedQuote: 0n,
        requestEpoch: 0n,
        lastChangeSlot: 0n,
        floorEpoch: 0n,
      } as TraderAccount,
      contextSlot: 1n,
      commitment: 'confirmed' as const,
    };
    const verdicts = (b: Uint8Array): Verdict<unknown>[] => [
      verifyCommittee(b, f.chain.value),
      verifyEpochKey(
        { epoch: 1n, epochPk: b.slice(0, 32), committeeDigest: b.slice(0, 32), bundleBytes: b },
        f.committee,
        f.chain.value,
        1n,
        f.pins,
      ),
      verifyAnnouncement(b, f.chain.value, f.chain.value.params, bundle),
      verifyPromise(b, {
        market: f.node.market,
        epoch: 1n,
        commitment: b.slice(0, 32),
        envelope: b,
        relay: f.node.relay,
      }),
      checkInclusion(
        { commitment: new Uint8Array(32), envelopeDigest: new Uint8Array(32) },
        b,
        f.node.relay,
        b,
        empty,
      ),
      verifyReceipt(b, b, {
        market: f.chain.value,
        batch: { ...empty, value: { ...empty.value, receipt: new Uint8Array(32) } },
      }),
      verifyArtifacts(b, emptyReceipt(), f.chain.value.params, 1n),
      verifyPolicies([b], f.committee, bundle),
      verifyOwnBalance(
        b,
        trader,
        { ...empty.value, commitSlot: 1n, status: 'committed', appliedCount: 0 } as BatchAccount,
        1n,
      ),
      verifyProgram(b, f.pins, f.chain.value, 1n),
      verifyRefusal(b, {
        market: f.node.market,
        epoch: 1n,
        envelopeDigest: new Uint8Array(32),
        relay: f.node.relay,
      }),
    ];
    fc.assert(
      fc.property(fc.uint8Array({ maxLength: 700 }), (b) => {
        for (const v of verdicts(b)) expect(['ok', 'fail', 'inconclusive']).toContain(v.kind);
      }),
      { numRuns: 300 },
    );
  });
});

/** A structurally valid receipt to pair with random artifacts. */
function emptyReceipt() {
  return {
    version: 1 as const,
    outcome: {
      market: 1n,
      epoch: 1n,
      headerDigest: new Uint8Array(32),
      clearing: [],
      fillCount: 0,
      fillsRoot: new Uint8Array(32),
      cancelledRoot: new Uint8Array(32),
      nextStateRoot: new Uint8Array(32),
      settlementCount: 0,
      settlementRoot: new Uint8Array(32),
      fees: 0n,
    },
    backend: 'tee' as const,
    executor: new Uint8Array(32),
    attestation: new Uint8Array(32),
    proof: new Uint8Array(32),
    trace: new Uint8Array(32),
    signature: new Uint8Array(64),
  };
}
