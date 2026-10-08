import { scryptAsync } from '@noble/hashes/scrypt.js';
import { utf8 } from '../core/encoding/bytes.js';

/** Export key parameters. `log2N` is bounded by the caller before anything runs. */
export interface DeriveRequest {
  passphrase: string;
  salt: Uint8Array;
  log2N: number;
}

/** `scrypt(passphrase, salt, N = 2^log2N, r = 8, p = 1)`, 32 bytes. The passphrase is NFKC-normalised. */
export function deriveExportKey(r: DeriveRequest): Promise<Uint8Array> {
  return scryptAsync(utf8(r.passphrase.normalize('NFKC')), r.salt, {
    N: 2 ** r.log2N,
    r: 8,
    p: 1,
    dkLen: 32,
  });
}

function isDeriveRequest(x: unknown): x is DeriveRequest {
  const r = x as Partial<DeriveRequest> | null;
  return (
    typeof r?.passphrase === 'string' &&
    r.salt instanceof Uint8Array &&
    (r.log2N === 15 || r.log2N === 16 || r.log2N === 17)
  );
}

/** Worker entry: derives the export key with scrypt off the main thread. */
export function handleExportMessage(data: unknown): Promise<unknown> {
  if (!isDeriveRequest(data)) return Promise.reject(new TypeError('bad export key request'));
  return deriveExportKey(data);
}

interface WorkerScope {
  addEventListener(type: 'message', f: (e: MessageEvent) => void): void;
  postMessage(message: unknown): void;
}

// Loaded as a dedicated worker (export.ts starts it), answer derive requests.
if ((globalThis as { WorkerGlobalScope?: unknown }).WorkerGlobalScope !== undefined) {
  const scope = globalThis as unknown as WorkerScope;
  scope.addEventListener('message', (e) => {
    handleExportMessage(e.data).then(
      (key) => scope.postMessage({ key }),
      (err: unknown) =>
        scope.postMessage({ error: err instanceof Error ? err.message : String(err) }),
    );
  });
}
