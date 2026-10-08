import { b64 } from '../core/encoding/base64.js';
import { fromUtf8, utf8 } from '../core/encoding/bytes.js';
import { canonicalJson, type JsonValue } from '../verify/evidence.js';

// Journal records hold bigints, byte strings and maps, which JSON has no
// form for. They are tagged as one-key objects, so a record decodes back to
// exactly the value that was stored. No record field name starts with `$`.

const BIGINT = '$bigint';
const BYTES = '$bytes';
const MAP = '$map';

function toJson(v: unknown): JsonValue {
  if (v === null || typeof v === 'string' || typeof v === 'boolean') return v;
  if (typeof v === 'number') {
    if (!Number.isFinite(v)) throw new RangeError('non-finite number in a journal record');
    return v;
  }
  if (typeof v === 'bigint') return { [BIGINT]: v.toString() };
  if (v instanceof Uint8Array) return { [BYTES]: b64.encode(v) };
  if (v instanceof Map) return { [MAP]: [...v.entries()].map(([k, x]) => [toJson(k), toJson(x)]) };
  if (Array.isArray(v)) return v.map(toJson);
  if (typeof v === 'object') {
    const out: { [k: string]: JsonValue } = {};
    for (const [k, x] of Object.entries(v)) {
      if (x !== undefined) out[k] = toJson(x);
    }
    return out;
  }
  throw new TypeError(`cannot store a ${typeof v} in the journal`);
}

function fromJson(v: JsonValue): unknown {
  if (v === null || typeof v !== 'object') return v;
  if (Array.isArray(v)) return v.map(fromJson);
  const keys = Object.keys(v);
  if (keys.length === 1) {
    const tag = keys[0]!;
    const x = v[tag]!;
    if (tag === BIGINT && typeof x === 'string') return BigInt(x);
    if (tag === BYTES && typeof x === 'string') return b64.decode(x);
    if (tag === MAP && Array.isArray(x)) {
      return new Map(
        x.map((e) => {
          if (!Array.isArray(e) || e.length !== 2) throw new TypeError('malformed map entry');
          return [fromJson(e[0]!), fromJson(e[1]!)];
        }),
      );
    }
  }
  const out: Record<string, unknown> = {};
  for (const k of keys) out[k] = fromJson(v[k]!);
  return out;
}

/** Canonical UTF-8 JSON of a journal value (bigints, bytes and maps tagged). */
export function encodeJson(v: unknown): Uint8Array {
  return utf8(canonicalJson(toJson(v)));
}

export function decodeJson(b: Uint8Array): unknown {
  return fromJson(JSON.parse(fromUtf8(b)) as JsonValue);
}
