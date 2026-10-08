import type { Address } from '@solana/kit';
import { b64 } from '../core/encoding/base64.js';
import { fromUtf8, utf8 } from '../core/encoding/bytes.js';
import { hex } from '../core/encoding/hex.js';
import { randomBytes } from '../core/crypto/random.js';
import type { BatchLeaf } from '../core/protocol/leaves.js';
import type { BatchAccount, Observed } from '../solana/accounts.js';

export type EvidenceRecord = {
  id: string;
  kind: 'exclusion' | 'substitution' | 'terms' | 'refusal' | 'verification_failed';
  market: Address;
  epoch: bigint;
  createdAtMs: number;
  /** Portable JSON, verifiable on /verify. */
  bytes: Uint8Array;
};

export type JsonValue = null | boolean | number | string | JsonValue[] | { [k: string]: JsonValue };

/** JSON with object keys sorted, no whitespace. The same value always gives the same bytes. */
export function canonicalJson(v: JsonValue): string {
  if (v === null || typeof v !== 'object') {
    if (typeof v === 'number' && !Number.isFinite(v)) throw new RangeError('non-finite number');
    return JSON.stringify(v);
  }
  if (Array.isArray(v)) return `[${v.map(canonicalJson).join(',')}]`;
  const keys = Object.keys(v).sort();
  return `{${keys.map((k) => `${JSON.stringify(k)}:${canonicalJson(v[k]!)}`).join(',')}}`;
}

/** Evidence format version, carried in every evidence document. */
export const EVIDENCE_VERSION = 1;

function batchJson(batch: Observed<BatchAccount>): JsonValue {
  const b = batch.value;
  return {
    address: b.address,
    market: b.market,
    epoch: b.epoch.toString(),
    root: hex.encode(b.root),
    count: b.count,
    terms_digest: hex.encode(b.termsDigest),
    slot: batch.contextSlot.toString(),
    commitment: batch.commitment,
  };
}

function encode(doc: { [k: string]: JsonValue }): Uint8Array {
  return utf8(canonicalJson({ version: EVIDENCE_VERSION, ...doc }));
}

/**
 * V-6 evidence: a valid promise for `(C, d)`, the relay key recorded at
 * submission, the committed leaves and the batch they hash to. Anyone can
 * re-check it against the chain: the leaves hash to the batch root and do
 * not contain `(C, d)` (or contain `C` with another digest).
 */
export function exclusionEvidence(a: {
  kind: 'exclusion' | 'substitution';
  own: BatchLeaf;
  promise: Uint8Array;
  relayAtSubmission: Address;
  leaves: Uint8Array;
  batch: Observed<BatchAccount>;
}): Uint8Array {
  return encode({
    kind: a.kind,
    market: a.batch.value.market,
    epoch: a.batch.value.epoch.toString(),
    commitment: hex.encode(a.own.commitment),
    envelope_digest: hex.encode(a.own.envelopeDigest),
    promise_b64: b64.encode(a.promise),
    relay_at_submission: a.relayAtSubmission,
    leaves_b64: b64.encode(a.leaves),
    batch: batchJson(a.batch),
  });
}

/** V-4 evidence: the relay-signed announcement, the terms it implies and the different terms on chain. */
export function termsEvidence(a: {
  announcement: Uint8Array;
  expectedTerms: Uint8Array;
  batch: Observed<BatchAccount>;
}): Uint8Array {
  return encode({
    kind: 'terms',
    market: a.batch.value.market,
    epoch: a.batch.value.epoch.toString(),
    announcement_b64: b64.encode(a.announcement),
    expected_terms_digest: hex.encode(a.expectedTerms),
    batch: batchJson(a.batch),
  });
}

/** A relay-signed refusal and the relay key it verifies under. */
export function refusalEvidence(a: {
  market: Address;
  epoch: bigint;
  refusal: Uint8Array;
  relay: Address;
  code: string;
}): Uint8Array {
  return encode({
    kind: 'refusal',
    market: a.market,
    epoch: a.epoch.toString(),
    code: a.code,
    refusal_b64: b64.encode(a.refusal),
    relay: a.relay,
  });
}

/** A failed  check with the inputs that failed it. */
export function failureEvidence(a: {
  market: Address;
  epoch: bigint;
  check: string;
  reason: string;
  inputs: Record<string, Uint8Array>;
}): Uint8Array {
  const inputs: { [k: string]: JsonValue } = {};
  for (const [k, v] of Object.entries(a.inputs)) inputs[`${k}_b64`] = b64.encode(v);
  return encode({
    kind: 'verification_failed',
    market: a.market,
    epoch: a.epoch.toString(),
    check: a.check,
    reason: a.reason,
    inputs,
  });
}

export function parseEvidence(bytes: Uint8Array): { [k: string]: JsonValue } {
  const v = JSON.parse(fromUtf8(bytes)) as JsonValue;
  if (v === null || typeof v !== 'object' || Array.isArray(v)) {
    throw new TypeError('evidence is not a JSON object');
  }
  return v;
}

export function evidenceRecord(
  kind: EvidenceRecord['kind'],
  market: Address,
  epoch: bigint,
  bytes: Uint8Array,
  createdAtMs: number,
): EvidenceRecord {
  return { id: hex.encode(randomBytes(16)), kind, market, epoch, createdAtMs, bytes };
}
