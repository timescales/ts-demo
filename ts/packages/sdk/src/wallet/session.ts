import type { Address } from '@solana/kit';
import type { ServerClock } from '../api/clock.js';
import type { TimescalesApi } from '../api/client.js';
import type { Info } from '../api/schemas.js';
import { b58 } from '../core/encoding/base58.js';
import { equal, fromUtf8, u64le, utf8 } from '../core/encoding/bytes.js';
import { hex } from '../core/encoding/hex.js';
import { ed25519PublicKey, ed25519Sign } from '../core/crypto/ed25519.js';
import { H, sha256 } from '../core/crypto/hash.js';
import { randomBytes } from '../core/crypto/random.js';
import { verifyStrict } from '../core/crypto/verifyStrict.js';
import { intentMessage } from '../core/protocol/intent.js';
import {
  SESSION_STATEMENT,
  parseSessionMessage,
  renderSessionMessage,
  type SessionGrant,
} from '../core/protocol/sessionText.js';
import { encodeSubmission, submissionDigest } from '../core/protocol/submission.js';
import { TimescalesError } from '../errors.js';
import { journalInternals, type Journal, type StoredSession } from '../journal/journal.js';
import { WalletError, abandonable, toWalletError, type TraderWallet } from './port.js';
import { sameGrant, siwsInputFor } from './siws.js';

const DEFAULT_TTL_MS = 12 * 3_600_000;
const MAX_TTL_MS = 24 * 3_600_000;

/**
 * V-11: one wallet prompt for the intent's text (its digest as a short code).
 * A signature that resolves after `signal` aborted is dropped.
 */
export async function signIntent(
  w: TraderWallet,
  c: Uint8Array,
  signal?: AbortSignal,
): Promise<Uint8Array> {
  const digest = intentMessage(c);
  let out: { signedMessage: Uint8Array; signature: Uint8Array };
  try {
    out = await abandonable(w.signMessage(digest, signal), signal);
  } catch (e) {
    throw toWalletError(e);
  }
  if (signal?.aborted === true) {
    throw new WalletError('abandoned', 'the signature arrived after the request was abandoned');
  }
  if (!equal(out.signedMessage, digest)) {
    throw new WalletError('modified_message', 'the wallet did not sign the intent text');
  }
  if (!verifyStrict(b58.decode(w.address, 32), digest, out.signature)) {
    throw new WalletError('bad_signature', "the signature does not verify under the wallet's key");
  }
  return out.signature;
}

/** `H(SESSION, "request" || method || 0 || path_and_query || 0 || ts u64 || SHA-256(body))`. */
export function sessionRequestDigest(
  method: string,
  pathAndQuery: string,
  tsMs: bigint,
  body: Uint8Array,
): Uint8Array {
  const zero = Uint8Array.of(0);
  return H(
    'SESSION',
    utf8('request'),
    utf8(method),
    zero,
    utf8(pathAndQuery),
    zero,
    u64le(tsMs),
    sha256(body),
  );
}

interface Signer {
  publicKey: Uint8Array;
  /** Set for a non-extractable WebCrypto key. Null for the in-memory noble fallback. */
  cryptoKey: CryptoKey | null;
  sign(msg: Uint8Array): Promise<Uint8Array>;
}

function webCryptoSigner(privateKey: CryptoKey, publicKey: Uint8Array): Signer {
  return {
    publicKey,
    cryptoKey: privateKey,
    async sign(msg) {
      return new Uint8Array(
        await crypto.subtle.sign({ name: 'Ed25519' }, privateKey, msg as Uint8Array<ArrayBuffer>),
      );
    },
  };
}

function nobleSigner(seed: Uint8Array): Signer {
  return {
    publicKey: ed25519PublicKey(seed),
    cryptoKey: null,
    sign: (msg) => Promise.resolve(ed25519Sign(seed, msg)),
  };
}

/**
 * A non-extractable WebCrypto Ed25519 key, or an in-memory noble key where
 * WebCrypto has no Ed25519 (a reload then needs a new session prompt).
 */
async function generateSigner(): Promise<Signer> {
  const subtle = globalThis.crypto?.subtle;
  if (subtle !== undefined) {
    try {
      const pair = (await subtle.generateKey({ name: 'Ed25519' }, false, [
        'sign',
      ])) as CryptoKeyPair;
      const publicKey = new Uint8Array(await subtle.exportKey('raw', pair.publicKey));
      return webCryptoSigner(pair.privateKey, publicKey);
    } catch {
      // No WebCrypto Ed25519 in this browser: use the noble fallback below.
    }
  }
  return nobleSigner(randomBytes(32));
}

function assertSecureContext(): void {
  const secure = (globalThis as { isSecureContext?: boolean }).isSecureContext;
  if (secure === false || globalThis.crypto?.subtle === undefined) {
    throw new TimescalesError({
      kind: 'environment',
      code: 'insecure_context',
      message: 'Timescales needs a secure (https) context for WebCrypto',
    });
  }
}

function chainIdOf(cluster: Info['cluster']): SessionGrant['chainId'] {
  if (cluster === 'localnet' || cluster === 'devnet') return cluster;
  if (cluster === 'mainnet-beta') return 'mainnet';
  throw new TimescalesError({
    kind: 'api',
    code: 'VERSION_UNSUPPORTED',
    message: `unknown cluster ${cluster}`,
  });
}

function sessionError(code: string, message: string): TimescalesError {
  return new TimescalesError({ kind: 'api', code, message });
}

/** The page's host, which wallets compare with the grant's domain. Absent outside a browser. */
function pageHost(): string | undefined {
  const host = (globalThis as { location?: { host?: unknown } }).location?.host;
  return typeof host === 'string' && host.length > 0 ? host : undefined;
}

/** Signs the SDK-rendered grant text with `signMessage` (where the deployment accepts such grants). */
async function signCanonical(
  w: TraderWallet,
  text: string,
  signal?: AbortSignal,
): Promise<{ message: string; signature: Uint8Array; method: 'sign_message' }> {
  const bytes = utf8(text);
  let out: { signedMessage: Uint8Array; signature: Uint8Array };
  try {
    out = await abandonable(w.signMessage(bytes, signal), signal);
  } catch (e) {
    throw toWalletError(e);
  }
  if (!equal(out.signedMessage, bytes)) throw new WalletError('modified_message');
  if (!verifyStrict(b58.decode(w.address, 32), bytes, out.signature)) {
    throw new WalletError('bad_signature');
  }
  return { message: text, signature: out.signature, method: 'sign_message' };
}

interface SessionState {
  api: TimescalesApi;
  clock: ServerClock;
  signer: Signer;
  lastTs: number;
  market: Address | null;
  revoked: boolean;
  journal: Journal | null;
}

// The class's declared surface is frozen, so its state lives here.
const STATE = new WeakMap<TradingSession, SessionState>();

function stateOf(s: TradingSession): SessionState {
  const st = STATE.get(s);
  if (st === undefined) throw new TypeError('TradingSession used before construction');
  return st;
}

/** The clock a session timestamps its requests with. */
export function sessionClockOf(s: TradingSession): ServerClock | null {
  return STATE.get(s)?.clock ?? null;
}

/**
 * Keeps the session in the wallet's journal for `resume`. Only a
 * non-extractable WebCrypto key can be kept. The noble fallback lives in
 * memory and is dropped with the tab.
 */
export async function rememberSession(s: TradingSession, journal: Journal): Promise<boolean> {
  const st = stateOf(s);
  const internals = journalInternals(journal);
  if (internals === null || st.signer.cryptoKey === null) return false;
  st.journal = journal;
  await internals.saveSession({
    wallet: s.wallet,
    sessionKey: s.sessionKey,
    privateKey: st.signer.cryptoKey,
    expiresAtMs: s.expiresAtMs,
    market: st.market,
    lastTs: st.lastTs,
  });
  return true;
}

/** A wallet-authorised session key. */
export class TradingSession {
  declare readonly sessionKey: Uint8Array;
  declare readonly wallet: Address;
  declare readonly expiresAtMs: number;
  declare readonly nonExtractable: boolean;

  private constructor(
    init: { sessionKey: Uint8Array; wallet: Address; expiresAtMs: number },
    st: SessionState,
  ) {
    this.sessionKey = init.sessionKey;
    this.wallet = init.wallet;
    this.expiresAtMs = init.expiresAtMs;
    this.nonExtractable = st.signer.cryptoKey !== null;
    STATE.set(this, st);
  }

  /**
   * One prompt (two if the wallet's sign-in text is unusable and the user
   * agrees). `ttlMs` defaults to 12 h. The grant goes through
   * `solana:signIn` when the wallet offers it: the returned text is parsed
   * before it is posted and must carry exactly the requested fields, and the
   * signing account must be this wallet. `signMessage` of the SDK-rendered
   * text is used only where the deployment accepts such grants (not in
   * production).
   */
  static async open(a: {
    api: TimescalesApi;
    wallet: TraderWallet;
    info: Info;
    clock: ServerClock;
    market: Address | null;
    ttlMs?: number;
    minContextSlot?: bigint;
    signal?: AbortSignal;
    onSecondPrompt?: () => Promise<boolean>;
  }): Promise<TradingSession> {
    assertSecureContext();
    const ttl = Math.min(
      a.ttlMs ?? DEFAULT_TTL_MS,
      MAX_TTL_MS,
      a.info.limits.sessionMaxTtlS * 1000,
    );
    if (!(ttl > 0)) throw new RangeError('session lifetime must be positive');
    const chainId = chainIdOf(a.info.cluster);
    const signer = await generateSigner();
    const nonce = await a.api.sessionNonce();
    if (nonce.statement !== SESSION_STATEMENT) {
      throw sessionError('SESSION_TEMPLATE_INVALID', 'the node asks for another session statement');
    }
    const issuedAtMs = Math.floor(a.clock.now());
    const grant: SessionGrant = {
      domain: pageHost() ?? nonce.domain,
      wallet: a.wallet.address,
      statement: nonce.statement,
      uri: nonce.uri,
      chainId,
      nonce: nonce.nonce,
      issuedAtMs,
      expiresAtMs: issuedAtMs + ttl,
      sessionKey: signer.publicKey,
      program: a.info.programId,
      market: a.market,
    };
    const canonical = renderSessionMessage(grant);
    const messageGrants = a.info.profile !== 'production';
    let signed:
      { message: string; signature: Uint8Array; method: 'sign_in' | 'sign_message' } | undefined;
    // Wallets know no local validator: they rewrite or refuse a localnet
    // Sign-In, so on localnet the canonical text is signed directly.
    if (a.wallet.signIn !== undefined && grant.chainId !== 'localnet') {
      let out: { account: Address; signedMessage: Uint8Array; signature: Uint8Array } | null = null;
      try {
        out = await abandonable(a.wallet.signIn(siwsInputFor(grant), a.signal), a.signal);
      } catch (e) {
        const err = toWalletError(e);
        // A refusal by the user ends the attempt. Any other sign-in failure
        // (a wallet that does not know the cluster, or rejects a field)
        // falls through to signing the canonical text where that is allowed.
        if (err.code === 'rejected' || err.code === 'abandoned' || !messageGrants) throw err;
      }
      if (out !== null) {
        if (out.account !== a.wallet.address) {
          throw new WalletError('account_changed', 'the wallet signed in with another account');
        }
        let text: string | null;
        try {
          text = fromUtf8(out.signedMessage);
        } catch {
          text = null;
        }
        let usable = false;
        if (text !== null) {
          try {
            usable = sameGrant(parseSessionMessage(text), grant);
          } catch {
            usable = false;
          }
        }
        if (text !== null && usable) {
          if (!verifyStrict(b58.decode(a.wallet.address, 32), out.signedMessage, out.signature)) {
            throw new WalletError('bad_signature', 'the sign-in signature does not verify');
          }
          signed = { message: text, signature: out.signature, method: 'sign_in' };
        } else {
          if (!messageGrants) {
            throw sessionError(
              'SESSION_TEMPLATE_INVALID',
              "the wallet's sign-in message is not in a format Timescales accepts",
            );
          }
          if (a.onSecondPrompt === undefined || !(await a.onSecondPrompt())) {
            throw sessionError(
              'SESSION_TEMPLATE_INVALID',
              "the wallet's sign-in message is not usable and a second signature was declined",
            );
          }
          signed = await signCanonical(a.wallet, canonical, a.signal);
        }
      }
    }
    if (signed === undefined) {
      if (!messageGrants) {
        throw sessionError(
          'SESSION_METHOD_REFUSED',
          'this deployment needs a wallet that supports Sign-In',
        );
      }
      signed = await signCanonical(a.wallet, canonical, a.signal);
    }
    const session = await a.api.createSession({
      wallet: a.wallet.address,
      message: signed.message,
      signatureBytes: signed.signature,
      method: signed.method,
      ...(a.minContextSlot !== undefined ? { minContextSlot: a.minContextSlot } : {}),
    });
    if (!equal(session.sessionKey, signer.publicKey) || session.wallet !== a.wallet.address) {
      throw sessionError('session_mismatch', 'the node created a session for another key');
    }
    return new TradingSession(
      { sessionKey: signer.publicKey, wallet: a.wallet.address, expiresAtMs: session.expiresAtMs },
      {
        api: a.api,
        clock: a.clock,
        signer,
        lastTs: 0,
        market: session.market,
        revoked: false,
        journal: null,
      },
    );
  }

  /**
   * Resumes with the non-extractable CryptoKey kept in IndexedDB. Null when
   * no live session is stored, or the node no longer knows it (revoked,
   * evicted or expired). A node that cannot be reached does not discard it.
   */
  static async resume(a: {
    api: TimescalesApi;
    wallet: Address;
    journal: Journal;
    clock: ServerClock;
  }): Promise<TradingSession | null> {
    const internals = journalInternals(a.journal);
    if (internals === null) return null;
    const stored: StoredSession | undefined = await internals.loadSession();
    if (stored === undefined || stored.wallet !== a.wallet) return null;
    if (stored.expiresAtMs <= a.clock.now()) {
      await internals.deleteSession();
      return null;
    }
    const s = new TradingSession(
      { sessionKey: stored.sessionKey, wallet: stored.wallet, expiresAtMs: stored.expiresAtMs },
      {
        api: a.api,
        clock: a.clock,
        signer: webCryptoSigner(stored.privateKey, stored.sessionKey),
        lastTs: stored.lastTs,
        market: stored.market,
        revoked: false,
        journal: a.journal,
      },
    );
    try {
      await a.api.currentSession(s);
    } catch (e) {
      if (
        e instanceof TimescalesError &&
        e.kind === 'api' &&
        (e.code.startsWith('SESSION_') || e.code === 'BAD_SIGNATURE')
      ) {
        await internals.deleteSession();
        return null;
      }
      if (!(e instanceof TimescalesError) || !e.retryable) throw e;
    }
    return s;
  }

  /** The 386-byte submission. */
  async signSubmission(envelope: Uint8Array): Promise<Uint8Array> {
    const st = stateOf(this);
    const sig = await st.signer.sign(submissionDigest(envelope, this.sessionKey));
    return encodeSubmission(envelope, this.sessionKey, sig);
  }

  /** A fresh `TimescalesSession` header per attempt, on server time, with strictly increasing ts. */
  async authorization(method: string, pathAndQuery: string, body: Uint8Array): Promise<string> {
    const st = stateOf(this);
    if (st.revoked) throw sessionError('SESSION_REVOKED', 'this session was revoked');
    const ts = Math.max(Math.floor(st.clock.now()), st.lastTs + 1);
    st.lastTs = ts;
    const sig = await st.signer.sign(sessionRequestDigest(method, pathAndQuery, BigInt(ts), body));
    return `TimescalesSession ${hex.encode(this.sessionKey)}.${ts}.${hex.encode(sig)}`;
  }

  async revoke(): Promise<void> {
    const st = stateOf(this);
    if (st.revoked) return;
    try {
      await st.api.revokeSession(this);
    } catch (e) {
      if (!(e instanceof TimescalesError) || !e.code.startsWith('SESSION_')) throw e;
    }
    st.revoked = true;
    const internals = st.journal === null ? null : journalInternals(st.journal);
    if (internals !== null) await internals.deleteSession();
  }
}
