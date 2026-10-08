import { sha256 } from '@noble/hashes/sha2.js';
import { utf8 } from '../encoding/bytes.js';
import { DOMAIN, type DomainName } from './tags.js';

const PREFIX = new Map<string, Uint8Array>();

function prefixFor(tag: string): Uint8Array {
  let p = PREFIX.get(tag);
  if (p === undefined) {
    const t = utf8(tag);
    if (t.length > 255) throw new RangeError('domain tag longer than 255 bytes');
    p = new Uint8Array(1 + t.length);
    p[0] = t.length;
    p.set(t, 1);
    PREFIX.set(tag, p);
  }
  return p;
}

/** `SHA-256(u8 len(tag) || tag || parts...)` for an arbitrary tag string. */
export function hashTagged(tag: string, ...parts: Uint8Array[]): Uint8Array {
  const h = sha256.create();
  h.update(prefixFor(tag));
  for (const p of parts) h.update(p);
  return h.digest();
}

/** Domain-separated SHA-256 over the concatenation of `parts`. */
export function H(tag: DomainName, ...parts: Uint8Array[]): Uint8Array {
  return hashTagged(DOMAIN[tag], ...parts);
}

export { sha256 };
