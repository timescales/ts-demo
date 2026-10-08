import fc from 'fast-check';
import { describe, expect, it } from 'vitest';
import {
  BandError,
  DecodeError,
  Writer,
  auditPath,
  b58,
  b64,
  band,
  decodeAnnouncement,
  decodeArtifacts,
  decodeBalanceSheet,
  decodeBundle,
  decodeCommittee,
  decodeEnvelope,
  decodeExact,
  decodeHeader,
  decodeInclusionProof,
  decodeKeyAnnouncement,
  decodeLeaves,
  decodeMarketParams,
  decodePolicyStatement,
  decodePrivateIntent,
  decodePromiseV1,
  decodePromiseV2,
  decodeReceipt,
  decodeRelayRefusal,
  decodeSettlementBatch,
  decodeStateTable,
  decodeSubmission,
  ed25519PublicKey,
  ed25519Sign,
  encodeAnnouncement,
  encodeArtifacts,
  encodeBundle,
  encodeCommittee,
  encodeHeader,
  encodeInclusionProof,
  encodeMarketParams,
  encodePolicyStatement,
  encodePrivateIntent,
  encodePromiseV1,
  encodePromiseV2,
  encodeReceipt,
  encodeRelayRefusal,
  hex,
  leafHash,
  merkleRoot,
  policyDigest,
  rootFor,
  slot,
  validateMarketParams,
  verifyStrict,
  type Cancel,
  type ExecutionArtifacts,
  type ExecutionReceipt,
  type IntentBody,
  type MarketParams,
  type Order,
} from '../src/core/index.js';
import { referenceVerifyStrict } from './support/ed25519Reference.js';
import { testMarketParams } from '../src/testing/index.js';

const U64 = (1n << 64n) - 1n;
const bytes = (n: number) => fc.uint8Array({ minLength: n, maxLength: n });
const u64 = fc.bigInt({ min: 0n, max: U64 });
const u32 = fc.integer({ min: 0, max: 0xffff_ffff });
const bit = fc.constantFrom(0 as const, 1 as const);

const params: fc.Arbitrary<MarketParams> = fc.record({
  market: u64,
  baseLotSize: u64,
  tickSize: u64,
  bandHalfWidth: u32,
  maxOrderLotsLog2: fc.integer({ min: 0, max: 255 }),
  maxOrdersPerTrader: fc.integer({ min: 0, max: 0xffff }),
  maxBatchEnvelopes: u32,
  maxOrderLifetime: u32,
  makerFeeBps: fc.integer({ min: 0, max: 0xffff }),
  takerFeeBps: fc.integer({ min: 0, max: 0xffff }),
  flow: bit,
  rationing: bit,
  commitmentScheme: bit,
});

const order: fc.Arbitrary<Order> = fc
  .record({
    market: u64,
    trader: bytes(32),
    nonce: u64,
    side: bit,
    role: bit,
    kind: bit,
    limit: u64,
    quantity: u64,
    validFrom: u64,
    expiresAt: u64,
  })
  .map((o) => (o.kind === 1 ? { ...o, limit: 0n } : o));
const cancel: fc.Arbitrary<Cancel> = fc.record({
  market: u64,
  trader: bytes(32),
  nonce: u64,
  target: bytes(32),
  epoch: u64,
});
const body: fc.Arbitrary<IntentBody> = fc.oneof(
  fc.constant({ kind: 'noop' as const }),
  order.map((o) => ({ kind: 'place' as const, order: o })),
  cancel.map((c) => ({ kind: 'cancel' as const, cancel: c })),
);

const outcome = fc.record({
  market: u64,
  epoch: u64,
  headerDigest: bytes(32),
  clearing: fc.array(
    fc.record({
      book: fc.constantFrom(0 as const, 1 as const, 2 as const),
      tick: u64,
      volume: u64,
    }),
    { maxLength: 2 },
  ),
  fillCount: u32,
  fillsRoot: bytes(32),
  cancelledRoot: bytes(32),
  nextStateRoot: bytes(32),
  settlementCount: u32,
  settlementRoot: bytes(32),
  fees: u64,
});
const receipt: fc.Arbitrary<ExecutionReceipt> = fc.record({
  version: fc.constant(1 as const),
  outcome,
  backend: fc.constantFrom('tee' as const, 'reference' as const, 'mpc' as const),
  executor: bytes(32),
  attestation: bytes(32),
  proof: bytes(32),
  trace: bytes(32),
  signature: bytes(64),
});
const i64 = fc.bigInt({ min: -(1n << 63n), max: (1n << 63n) - 1n });
const artifacts: fc.Arbitrary<ExecutionArtifacts> = fc
  .record({
    fills: fc.array(
      fc.record({
        commitment: bytes(32),
        trader: bytes(32),
        book: fc.constantFrom(0 as const, 1 as const, 2 as const),
        side: bit,
        role: bit,
        quantity: u64,
        tick: u64,
      }),
      { maxLength: 5 },
    ),
    cancelled: fc.array(bytes(32), { maxLength: 4 }),
    market: u64,
    epoch: u64,
    traders: fc.uniqueArray(bytes(32), { maxLength: 5, selector: (t) => hex.encode(t) }),
    amounts: fc.array(fc.tuple(i64, i64), { minLength: 5, maxLength: 5 }),
    fees: u64,
  })
  .map((a) => ({
    fills: a.fills,
    cancelled: a.cancelled,
    settlement: {
      market: a.market,
      epoch: a.epoch,
      fees: a.fees,
      deltas: [...a.traders]
        .sort((x, y) => hex.encode(x).localeCompare(hex.encode(y)))
        .map((trader, i) => {
          const [b, q] = a.amounts[i]!;
          return { trader, base: b === 0n && q === 0n ? 1n : b, quote: q };
        }),
    },
  }));

/** Decoders that must either succeed or throw DecodeError on any input. */
const DECODERS: [string, (b: Uint8Array) => unknown][] = [
  ['market params', decodeMarketParams],
  ['header', decodeHeader],
  ['envelope', decodeEnvelope],
  ['private intent', decodePrivateIntent],
  ['submission', decodeSubmission],
  ['promise v1', decodePromiseV1],
  ['promise v2', decodePromiseV2],
  ['refusal', decodeRelayRefusal],
  ['receipt', decodeReceipt],
  ['artifacts', decodeArtifacts],
  ['settlement', decodeSettlementBatch],
  ['state table', decodeStateTable],
  ['balance sheet', decodeBalanceSheet],
  ['inclusion proof', decodeInclusionProof],
  ['leaves', decodeLeaves],
  ['committee', decodeCommittee],
  ['key announcement', decodeKeyAnnouncement],
  ['bundle', decodeBundle],
  ['policy statement', decodePolicyStatement],
  ['policy digest', policyDigest],
  ['epoch announcement', decodeAnnouncement],
];

function decodesOrThrowsDecodeError(f: (b: Uint8Array) => unknown, b: Uint8Array): void {
  try {
    f(b);
  } catch (e) {
    expect(e).toBeInstanceOf(DecodeError);
  }
}

const SEEDS: Uint8Array[] = [
  encodeMarketParams(testMarketParams()),
  new Uint8Array(283).fill(7),
  Uint8Array.from({ length: 289 }, (_, i) => (i * 37) & 0xff),
  Uint8Array.from({ length: 1024 }, (_, i) => (i * 11) & 0xff),
];

describe('codec primitives', () => {
  it('round-trip every integer width at any value', () => {
    fc.assert(
      fc.property(
        fc.integer({ min: 0, max: 255 }),
        fc.integer({ min: 0, max: 0xffff }),
        u32,
        u64,
        i64,
        fc.boolean(),
        fc.uint8Array({ maxLength: 40 }),
        (a, b, c, d, e, f, g) => {
          const enc = new Writer()
            .u8(a)
            .u16(b)
            .u32(c)
            .u64(d)
            .i64(e)
            .bool(f)
            .bytes(g, 40)
            .seq([d, d], 2, (w, v) => w.u64(v))
            .finish();
          const out = decodeExact(enc, (r) => [
            r.u8(),
            r.u16(),
            r.u32(),
            r.u64(),
            r.i64(),
            r.bool(),
            r.bytes(40),
            r.seq(2, (x) => x.u64(), 8),
          ]);
          expect(out).toEqual([a, b, c, d, e, f, g, [d, d]]);
        },
      ),
    );
  });

  it('refuses out-of-range values before writing', () => {
    expect(() => new Writer().u8(256)).toThrow(RangeError);
    expect(() => new Writer().u64(-1n)).toThrow(RangeError);
    expect(() => new Writer().u64(1n << 64n)).toThrow(RangeError);
    expect(() => new Writer().i64(1n << 63n)).toThrow(RangeError);
    expect(() => new Writer().u32(1.5)).toThrow(RangeError);
    expect(() => new Writer().bytes(new Uint8Array(3), 2)).toThrow(RangeError);
    expect(() => new Writer().fixed(new Uint8Array(3), 4)).toThrow(RangeError);
  });

  it('rejects strictness violations with the right DecodeError kind', () => {
    const kind = (f: () => unknown) => {
      try {
        f();
      } catch (e) {
        return (e as DecodeError).kind;
      }
      return 'ok';
    };
    expect(kind(() => decodeExact(Uint8Array.of(2), (r) => r.bool()))).toBe('tag');
    expect(kind(() => decodeExact(Uint8Array.of(1, 0), (r) => r.bool()))).toBe('trailing');
    expect(kind(() => decodeExact(Uint8Array.of(1), (r) => r.u16()))).toBe('eof');
    expect(kind(() => decodeExact(Uint8Array.of(5, 0, 0, 0), (r) => r.bytes(4)))).toBe('length');
    expect(kind(() => decodeExact(Uint8Array.of(3, 0, 0, 0), (r) => r.seq(2, (x) => x.u8())))).toBe(
      'length',
    );
  });

  it('never reserves more than the input could describe', () => {
    const hostile = Uint8Array.of(0xff, 0xff, 0xff, 0x7f, 1, 2, 3);
    expect(() => decodeExact(hostile, (r) => r.seq(1 << 31, (x) => x.fixed(32), 32))).toThrow(
      DecodeError,
    );
  });

  it('hex, base64 and base58 round-trip and decode canonically', () => {
    fc.assert(
      fc.property(fc.uint8Array({ maxLength: 64 }), (b) => {
        expect(hex.decode(hex.encode(b))).toEqual(b);
        expect(b64.decode(b64.encode(b))).toEqual(b);
        expect(b58.decode(b58.encode(b))).toEqual(b);
        expect(b64.encode(b)).toBe(Buffer.from(b).toString('base64'));
      }),
    );
    expect(() => b64.decode('QR==')).toThrow(DecodeError);
    expect(() => b64.decode('QQ')).toThrow(DecodeError);
    expect(() => hex.decode('0g')).toThrow(DecodeError);
    expect(() => b58.decode('0')).toThrow(DecodeError);
    expect(() => hex.decode('00', 2)).toThrow(DecodeError);
  });
});

describe('protocol round trips', () => {
  it('market params', () => {
    fc.assert(
      fc.property(params, (p) => {
        expect(decodeMarketParams(encodeMarketParams(p))).toEqual(p);
      }),
    );
  });

  it('private intents of every kind', () => {
    fc.assert(
      fc.property(body, bytes(32), bytes(64), (b, salt, signature) => {
        const i = { body: b, salt, signature };
        const enc = encodePrivateIntent(i);
        expect(enc.length).toBeLessThanOrEqual(192);
        expect(decodePrivateIntent(enc)).toEqual(i);
      }),
    );
  });

  it('a market order with a limit is refused on both sides', () => {
    fc.assert(
      fc.property(order, fc.bigInt({ min: 1n, max: U64 }), bytes(32), (o, limit, salt) => {
        const bad = {
          body: { kind: 'place' as const, order: { ...o, kind: 1 as const, limit } },
          salt,
          signature: new Uint8Array(64),
        };
        expect(() => encodePrivateIntent(bad)).toThrow(RangeError);
        const good = encodePrivateIntent({
          ...bad,
          body: { kind: 'place', order: { ...o, kind: 1, limit: 0n } },
        });
        good.set(new Uint8Array(new BigUint64Array([limit]).buffer), 1 + 51);
        expect(() => decodePrivateIntent(good)).toThrow(
          expect.objectContaining({ kind: 'value' }) as DecodeError,
        );
      }),
    );
  });

  it('receipts and artifacts', () => {
    fc.assert(
      fc.property(receipt, (r) => {
        expect(decodeReceipt(encodeReceipt(r))).toEqual(r);
      }),
    );
    fc.assert(
      fc.property(artifacts, (a) => {
        expect(decodeArtifacts(encodeArtifacts(a))).toEqual(a);
      }),
    );
  });

  it('headers of both versions', () => {
    fc.assert(
      fc.property(
        params,
        fc.constantFrom(1 as const, 2 as const),
        u64,
        fc.bigInt({ min: 0n, max: U64 - 1024n }),
        fc.integer({ min: 0, max: 1024 }),
        fc.array(bytes(32), { minLength: 6, maxLength: 6 }),
        u32,
        (p, version, epoch, lo, width, h, count) => {
          const header = {
            version,
            market: p.market,
            epoch,
            params: p,
            band: { lo, hi: lo + BigInt(width), reference: lo },
            priceCommitmentOrBinding: h[0]!,
            envelopeCount: count,
            batchRoot: h[1]!,
            beacon: h[2]!,
            priorStateRoot: h[3]!,
            balancesRoot: h[4]!,
            prevReceipt: h[5]!,
          };
          const enc = encodeHeader(header);
          expect(enc.length).toBe(283);
          expect(decodeHeader(enc)).toEqual(header);
        },
      ),
    );
  });

  it('relay, committee and key-dealing messages', () => {
    fc.assert(
      fc.property(
        fc.array(bytes(32), { minLength: 6, maxLength: 6 }),
        bytes(64),
        u64,
        u64,
        (h, sig, a, b) => {
          const p2 = {
            market: h[0]!,
            epoch: a,
            commitment: h[1]!,
            envelopeDigest: h[2]!,
            relay: h[3]!,
            signature: sig,
          };
          expect(encodePromiseV2(p2).length).toBe(201);
          expect(decodePromiseV2(encodePromiseV2(p2))).toEqual(p2);
          const p1 = { market: a, epoch: b, commitment: h[1]!, relay: h[3]!, signature: sig };
          expect(decodePromiseV1(encodePromiseV1(p1))).toEqual(p1);
          const refusal = {
            market: h[0]!,
            epoch: a,
            envelopeDigest: h[2]!,
            code: 3,
            atMs: b,
            relay: h[3]!,
            signature: sig,
          };
          expect(encodeRelayRefusal(refusal).length).toBe(177);
          expect(decodeRelayRefusal(encodeRelayRefusal(refusal))).toEqual(refusal);
          const committee = {
            version: 1,
            market: h[0]!,
            threshold: 2,
            members: [1, 2, 3].map((index, i) => ({
              index,
              identity: h[i + 1]!,
              transport: h[i + 2]!,
            })),
          };
          expect(decodeCommittee(encodeCommittee(committee))).toEqual(committee);
          const announcement = {
            version: 1,
            market: h[0]!,
            epoch: a,
            committeeDigest: h[1]!,
            scheme: 'feldman' as const,
            epochPk: h[2]!,
            commitments: [h[3]!, h[4]!],
          };
          const bundle = {
            announcement,
            acks: [
              { member: 1, policyDigest: h[5]!, signature: sig },
              { member: 3, policyDigest: h[4]!, signature: sig },
            ],
          };
          expect(decodeBundle(encodeBundle(bundle))).toEqual(bundle);
          const policy = {
            market: h[0]!,
            member: 2,
            committeeDigest: h[1]!,
            platforms: { simulated: false, intelTdx: true },
            measurementSetDigest: h[2]!,
            allowDebug: false,
            minTcb: 1,
            mrConfigId: new Uint8Array(48).fill(7),
            fromEpoch: b,
            signature: sig,
          };
          expect(encodePolicyStatement(policy).length).toBe(221);
          expect(decodePolicyStatement(encodePolicyStatement(policy))).toEqual(policy);
          const epochAnnouncement = {
            market: h[0]!,
            epoch: a,
            opensAtMs: b,
            cutoffMs: b,
            band: { lo: 10n, hi: 20n, reference: 15n },
            priceCommitment: h[1]!,
            keyDigest: h[2]!,
            committeeDigest: h[3]!,
            relay: h[4]!,
            signature: sig,
          };
          expect(encodeAnnouncement(epochAnnouncement).length).toBe(273);
          expect(decodeAnnouncement(encodeAnnouncement(epochAnnouncement))).toEqual(
            epochAnnouncement,
          );
          const proof = { index: a, treeSize: b, path: h.slice(0, 3) };
          expect(decodeInclusionProof(encodeInclusionProof(proof))).toEqual(proof);
        },
      ),
    );
  });
});

describe('decoders throw only DecodeError', () => {
  it.each(DECODERS)('%s on random bytes', (_name, f) => {
    fc.assert(
      fc.property(fc.uint8Array({ maxLength: 600 }), (b) => decodesOrThrowsDecodeError(f, b)),
    );
  });

  it.each(DECODERS)('%s on mutated valid encodings', (_name, f) => {
    fc.assert(
      fc.property(
        fc.constantFrom(...SEEDS),
        fc.nat(),
        fc.integer({ min: 0, max: 255 }),
        fc.integer({ min: -8, max: 8 }),
        (seed, at, value, resize) => {
          const b = Uint8Array.from(seed);
          if (b.length > 0) b[at % b.length] = value;
          const sized =
            resize >= 0
              ? new Uint8Array([...b, ...new Uint8Array(resize)])
              : b.subarray(0, Math.max(0, b.length + resize));
          decodesOrThrowsDecodeError(f, sized);
        },
      ),
    );
  });
});

describe('merkle', () => {
  it('rootFor agrees with merkleRoot for every leaf of trees up to 64', () => {
    fc.assert(
      fc.property(
        fc.array(fc.uint8Array({ maxLength: 8 }), { minLength: 1, maxLength: 64 }),
        (data) => {
          const root = merkleRoot(data);
          const n = BigInt(data.length);
          data.forEach((d, i) => {
            const path = auditPath(data, i);
            expect(rootFor(BigInt(i), n, path, leafHash(d))).toEqual(root);
            expect(rootFor(BigInt(i), n, [...path, root], leafHash(d))).toBeNull();
            if (path.length > 0)
              expect(rootFor(BigInt(i), n, path.slice(1), leafHash(d))).not.toEqual(root);
          });
          expect(rootFor(n, n, [], leafHash(data[0]!))).toBeNull();
        },
      ),
      { numRuns: 60 },
    );
  });
});

describe('band and slot', () => {
  const valid = params
    .map((p) => ({
      ...p,
      baseLotSize: (p.baseLotSize % 1000n) + 1n,
      tickSize: (p.tickSize % 1000n) + 1n,
      bandHalfWidth: (p.bandHalfWidth % 512) + 1,
      maxOrderLotsLog2: (p.maxOrderLotsLog2 % 30) + 1,
      maxOrdersPerTrader: (p.maxOrdersPerTrader % 100) + 1,
      maxBatchEnvelopes: (p.maxBatchEnvelopes % 1024) + 1,
      makerFeeBps: p.makerFeeBps % 10001,
      takerFeeBps: p.takerFeeBps % 10001,
    }))
    .filter((p) => {
      try {
        validateMarketParams(p);
        return true;
      } catch {
        return false;
      }
    });

  it('is the exact band or a BandError, and slots are monotone in the limit', () => {
    fc.assert(
      fc.property(
        valid,
        u64,
        fc.array(u64, { minLength: 2, maxLength: 8 }),
        (p, reference, limits) => {
          let b;
          try {
            b = band(p, reference);
          } catch (e) {
            expect(e).toBeInstanceOf(BandError);
            return;
          }
          const w = BigInt(p.bandHalfWidth);
          expect(b).toEqual({ lo: reference - w, hi: reference + w, reference });
          const k = 2 * p.bandHalfWidth + 1;
          const near = limits.map((l) => b.lo - 2n + (l % (2n * w + 5n)));
          const all = [...limits, ...near]
            .filter((l) => l >= 0n)
            .sort((x, y) => (x < y ? -1 : x > y ? 1 : 0));
          for (const side of [0, 1] as const) {
            let prev = -1;
            for (const l of all) {
              const s = slot(b, side, l);
              if (side === 0) expect(s === null).toBe(l < b.lo);
              else expect(s === null).toBe(l > b.hi);
              if (s === null) continue;
              expect(s >= 0 && s < k).toBe(true);
              expect(s).toBeGreaterThanOrEqual(prev);
              prev = s;
            }
          }
        },
      ),
    );
  });

  it('band underflow is strict at reference == W', () => {
    const p = fc.sample(valid, 1)[0]!;
    expect(() => band(p, BigInt(p.bandHalfWidth))).toThrow(
      expect.objectContaining({ reason: 'underflow' }) as BandError,
    );
  });
});

describe('verifyStrict agrees with a pure-BigInt reference', () => {
  it('on random genuine and corrupted signatures', () => {
    fc.assert(
      fc.property(
        bytes(32),
        fc.uint8Array({ maxLength: 64 }),
        fc.nat(63),
        fc.integer({ min: 1, max: 255 }),
        (seed, msg, at, flip) => {
          const pub = ed25519PublicKey(seed);
          const sig = ed25519Sign(seed, msg);
          expect(verifyStrict(pub, msg, sig)).toBe(true);
          expect(referenceVerifyStrict(pub, msg, sig)).toBe(true);
          const bad = Uint8Array.from(sig);
          bad[at]! ^= flip;
          expect(verifyStrict(pub, msg, bad)).toBe(referenceVerifyStrict(pub, msg, bad));
        },
      ),
      { numRuns: 40 },
    );
  });
});
