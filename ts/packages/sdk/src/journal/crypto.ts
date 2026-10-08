import { concat, u32le, utf8 } from '../core/encoding/bytes.js';
import { randomBytes } from '../core/crypto/random.js';

const AAD_PREFIX = utf8('timescales-journal-v2');

/**
 * `"timescales-journal-v2" || store || id || version`, each string length
 * prefixed: a ciphertext moved to another store, record or version fails to
 * decrypt.
 */
export function recordAad(store: string, id: string, version: number): Uint8Array {
  const s = utf8(store);
  const i = utf8(id);
  if (s.length > 255 || i.length > 255) throw new RangeError('store or id too long');
  return concat(AAD_PREFIX, Uint8Array.of(s.length), s, Uint8Array.of(i.length), i, u32le(version));
}

/** The device key: AES-GCM-256, generated non-extractable. */
export async function generateDeviceKey(): Promise<CryptoKey> {
  return crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
}

/** AES-256-GCM with the non-extractable device key. AAD binds store, id and version. */
export async function sealRecord(
  key: CryptoKey,
  store: string,
  id: string,
  version: number,
  plain: Uint8Array,
): Promise<{ iv: Uint8Array; ct: Uint8Array }> {
  const iv = randomBytes(12);
  const ct = await crypto.subtle.encrypt(
    {
      name: 'AES-GCM',
      iv: iv as Uint8Array<ArrayBuffer>,
      additionalData: recordAad(store, id, version) as Uint8Array<ArrayBuffer>,
    },
    key,
    plain as Uint8Array<ArrayBuffer>,
  );
  return { iv, ct: new Uint8Array(ct) };
}

export async function openRecord(
  key: CryptoKey,
  store: string,
  id: string,
  version: number,
  iv: Uint8Array,
  ct: Uint8Array,
): Promise<Uint8Array> {
  const plain = await crypto.subtle.decrypt(
    {
      name: 'AES-GCM',
      iv: iv as Uint8Array<ArrayBuffer>,
      additionalData: recordAad(store, id, version) as Uint8Array<ArrayBuffer>,
    },
    key,
    ct as Uint8Array<ArrayBuffer>,
  );
  return new Uint8Array(plain);
}
