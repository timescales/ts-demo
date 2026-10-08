import { xchacha20poly1305 } from '@noble/ciphers/chacha.js';
import { concat, equal, utf8 } from '../core/encoding/bytes.js';
import { hex } from '../core/encoding/hex.js';
import { randomBytes } from '../core/crypto/random.js';
import { TimescalesError } from '../errors.js';
import type { OrderRecord } from '../orders/model.js';
import type { EvidenceRecord } from '../verify/evidence.js';
import { deriveExportKey } from './export.worker.js';
import { decodeJson, encodeJson } from './json.js';
import { journalInternals, storageError, type Journal } from './journal.js';

const MAGIC = utf8('TSJNL2');
const FORMAT = 0x02;
const SCRYPT_R = 8;
const SCRYPT_P = 1;
const SALT_LEN = 16;
const NONCE_LEN = 24;
/** `"TSJNL2" || 0x02 || log2N || r || p || salt16 || nonce24`. */
const HEADER_LEN = MAGIC.length + 4 + SALT_LEN + NONCE_LEN;
const TAG_LEN = 16;
const MIN_PASSPHRASE = 12;
const PAYLOAD_VERSION = 2;

interface ExportPayload {
  version: number;
  cluster: string;
  program: string;
  wallet: string;
  orders: OrderRecord[];
  evidence: EvidenceRecord[];
}

function exportError(code: string, message: string, cause?: unknown): TimescalesError {
  return storageError(code, message, cause);
}

/** Derives the key in a Web Worker where there is one, else on this thread (Node, scripts). */
async function deriveKey(passphrase: string, salt: Uint8Array, log2N: number): Promise<Uint8Array> {
  if (typeof Worker === 'undefined') return deriveExportKey({ passphrase, salt, log2N });
  let worker: Worker;
  try {
    worker = new Worker(new URL('./export.worker.js', import.meta.url), { type: 'module' });
  } catch {
    return deriveExportKey({ passphrase, salt, log2N });
  }
  return new Promise<Uint8Array>((resolve, reject) => {
    worker.addEventListener('message', (e: MessageEvent<{ key?: Uint8Array; error?: string }>) => {
      worker.terminate();
      if (e.data.key instanceof Uint8Array) resolve(e.data.key);
      else reject(exportError('export_failed', e.data.error ?? 'key derivation failed'));
    });
    worker.addEventListener('error', () => {
      worker.terminate();
      // A worker blocked by policy still lets the export run, only slower.
      deriveExportKey({ passphrase, salt, log2N }).then(resolve, reject);
    });
    worker.postMessage({ passphrase, salt, log2N });
  });
}

/**
 * Passphrase-encrypted export: XChaCha20-Poly1305 under
 * `scrypt(passphrase >= 12 chars, salt, N = 2^log2N, r = 8, p = 1)` with the
 * whole header as AAD. `log2N` is 17 by default (desktop). 16 is the mobile
 * choice, cheaper to brute-force.
 */
export async function exportJournal(
  j: Journal,
  passphrase: string,
  o?: { log2N?: 15 | 16 | 17 },
): Promise<Uint8Array> {
  if ([...passphrase].length < MIN_PASSPHRASE) {
    throw exportError(
      'passphrase_too_short',
      `the passphrase needs at least ${MIN_PASSPHRASE} characters`,
    );
  }
  const log2N = o?.log2N ?? 17;
  if (log2N !== 15 && log2N !== 16 && log2N !== 17)
    throw new RangeError('log2N must be 15, 16 or 17');
  const internals = journalInternals(j);
  if (internals === null)
    throw exportError('unsupported_journal', 'this journal cannot be exported');
  const payload: ExportPayload = {
    version: PAYLOAD_VERSION,
    cluster: internals.scope.cluster,
    program: internals.scope.program,
    wallet: internals.scope.wallet,
    orders: await j.list(),
    evidence: await internals.listEvidence(),
  };
  const salt = randomBytes(SALT_LEN);
  const nonce = randomBytes(NONCE_LEN);
  const header = concat(MAGIC, Uint8Array.of(FORMAT, log2N, SCRYPT_R, SCRYPT_P), salt, nonce);
  const key = await deriveKey(passphrase, salt, log2N);
  const ct = xchacha20poly1305(key, nonce, header).encrypt(encodeJson(payload));
  return concat(header, ct);
}

function parseHeader(bundle: Uint8Array): { log2N: number; salt: Uint8Array; nonce: Uint8Array } {
  if (bundle.length < HEADER_LEN + TAG_LEN || !equal(bundle.subarray(0, MAGIC.length), MAGIC)) {
    throw exportError('unsupported_export', 'not a Timescales journal export');
  }
  const at = MAGIC.length;
  const [format, log2N, r, p] = [bundle[at], bundle[at + 1], bundle[at + 2], bundle[at + 3]];
  if (format !== FORMAT) throw exportError('unsupported_export', `export format ${format}`);
  // Checked before scrypt runs, so a crafted header cannot demand any work.
  if ((log2N !== 15 && log2N !== 16 && log2N !== 17) || r !== SCRYPT_R || p !== SCRYPT_P) {
    throw exportError('unsupported_export', 'unsupported key-derivation parameters');
  }
  return {
    log2N,
    salt: bundle.slice(at + 4, at + 4 + SALT_LEN),
    nonce: bundle.slice(at + 4 + SALT_LEN, HEADER_LEN),
  };
}

function isPayload(x: unknown): x is ExportPayload {
  const p = x as Partial<ExportPayload> | null;
  return (
    p?.version === PAYLOAD_VERSION &&
    typeof p.cluster === 'string' &&
    typeof p.program === 'string' &&
    typeof p.wallet === 'string' &&
    Array.isArray(p.orders) &&
    Array.isArray(p.evidence) &&
    p.orders.every(
      (r) =>
        typeof r?.id === 'string' && r.commitment instanceof Uint8Array && r.epochs instanceof Map,
    ) &&
    p.evidence.every((e) => typeof e?.id === 'string' && e.bytes instanceof Uint8Array)
  );
}

/**
 * Imports an export into this wallet's journal. Only `log2N in {15, 16, 17}`,
 * `r = 8` and `p = 1` are accepted, before any key derivation. The header is
 * authenticated as AAD. Orders merge by commitment: one already present is
 * skipped.
 */
export async function importJournal(
  bundle: Uint8Array,
  passphrase: string,
  into: Journal,
): Promise<{ imported: number; skipped: number }> {
  const { log2N, salt, nonce } = parseHeader(bundle);
  const header = bundle.subarray(0, HEADER_LEN);
  const key = await deriveKey(passphrase, salt, log2N);
  let payload: unknown;
  try {
    payload = decodeJson(
      xchacha20poly1305(key, nonce, header).decrypt(bundle.subarray(HEADER_LEN)),
    );
  } catch (e) {
    throw exportError('bad_passphrase', 'wrong passphrase, or the export is damaged', e);
  }
  if (!isPayload(payload)) throw exportError('unsupported_export', 'unreadable export contents');
  const internals = journalInternals(into);
  if (
    internals !== null &&
    (payload.cluster !== internals.scope.cluster ||
      payload.program !== internals.scope.program ||
      payload.wallet !== internals.scope.wallet)
  ) {
    throw exportError('other_wallet', 'this export belongs to another wallet, program or cluster');
  }
  const present = new Set((await into.list()).map((r) => hex.encode(r.commitment)));
  let imported = 0;
  let skipped = 0;
  for (const r of payload.orders) {
    const c = hex.encode(r.commitment);
    if (present.has(c)) {
      skipped++;
      continue;
    }
    try {
      await into.put({ ...r, version: 0 }, 0);
    } catch (e) {
      if (e instanceof TimescalesError && e.code === 'version_conflict') {
        skipped++;
        continue;
      }
      throw e;
    }
    present.add(c);
    imported++;
  }
  if (internals !== null) {
    const known = new Set((await internals.listEvidence()).map((e) => e.id));
    for (const e of payload.evidence) {
      if (!known.has(e.id)) await into.putEvidence(e);
    }
  }
  return { imported, skipped };
}
