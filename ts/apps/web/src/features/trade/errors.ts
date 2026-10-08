// Inline copy for errors raised while sealing or cancelling (rows that
// belong next to the ticket and the stepper). Errors are read by shape
// because the SDK's error classes live in its root entry, which the app does
// not load at runtime.
import type { ErrorCode, TimescalesErrorKind, WalletErrorCode } from '@timescales/sdk';

import { tradeCopy } from './copy';

export interface ErrorInfo {
  kind: TimescalesErrorKind | 'unknown';
  code: string;
  retryable: boolean;
  retryAfterMs: number | null;
  /** A relay-signed refusal came with the error (it is kept as evidence). */
  refusal: boolean;
}

export function errorInfo(e: unknown): ErrorInfo {
  const x = (typeof e === 'object' && e !== null ? e : {}) as Record<string, unknown>;
  const details = (typeof x.details === 'object' && x.details !== null ? x.details : {}) as Record<
    string,
    unknown
  >;
  return {
    kind: typeof x.kind === 'string' ? (x.kind as TimescalesErrorKind) : 'unknown',
    code: typeof x.code === 'string' ? x.code : 'unknown',
    retryable: x.retryable === true,
    retryAfterMs: typeof x.retryAfterMs === 'number' ? x.retryAfterMs : null,
    refusal: typeof details.refusal_b64 === 'string' || details.refusalBytes instanceof Uint8Array,
  };
}

const c = tradeCopy.errors;
const versionMismatch = c.versionMismatch;

/** One message per API error code. The Record type makes the mapping exhaustive. */
const API_MESSAGES: Record<ErrorCode, (epoch: string, seconds: number) => string> = {
  BAD_REQUEST: () => versionMismatch,
  DECODE_FAILED: () => versionMismatch,
  UNSUPPORTED_MEDIA_TYPE: () => versionMismatch,
  BODY_TOO_LARGE: () => versionMismatch,
  VERSION_UNSUPPORTED: () => versionMismatch,
  WRONG_MARKET: () => versionMismatch,
  MASKED_NOT_SUPPORTED: () => versionMismatch,
  BAD_SIGNATURE: () => c.session,
  SKEW: () => c.SKEW,
  SESSION_UNKNOWN: () => c.session,
  SESSION_EXPIRED: () => c.session,
  SESSION_REVOKED: () => c.sessionRevoked,
  SESSION_TEMPLATE_INVALID: () => c.SESSION_TEMPLATE_INVALID,
  SESSION_DOMAIN_MISMATCH: () => c.SESSION_DOMAIN_MISMATCH,
  SESSION_NONCE_INVALID: () => c.SESSION_NONCE_INVALID,
  SESSION_METHOD_REFUSED: () => c.SESSION_METHOD_REFUSED,
  WALLET_NOT_ELIGIBLE: () => c.WALLET_NOT_ELIGIBLE,
  MARKET_HALTED: () => c.MARKET_HALTED,
  MARKET_UNKNOWN: () => c.MARKET_UNKNOWN,
  NOT_FOUND: () => c.pruned,
  NOT_YET_AVAILABLE: () => c.NOT_YET_AVAILABLE,
  PRUNED: () => c.pruned,
  EPOCH_CLOSED: () => c.EPOCH_CLOSED,
  EPOCH_TOO_FAR: (epoch) => c.EPOCH_TOO_FAR(epoch),
  DUPLICATE_COMMITMENT: () => c.DUPLICATE_COMMITMENT,
  BATCH_FULL: (epoch) => c.BATCH_FULL(epoch),
  QUOTA_EXCEEDED: () => c.QUOTA_EXCEEDED,
  RATE_LIMITED: (_, s) => c.RATE_LIMITED(s),
  EPOCH_KEY_UNAVAILABLE: (epoch) => c.EPOCH_KEY_UNAVAILABLE(epoch),
  INTAKE_PAUSED: () => c.INTAKE_PAUSED,
  MARKET_UNAVAILABLE: () => c.MARKET_UNAVAILABLE,
  OVERLOADED: (_, s) => c.OVERLOADED(s),
  DRAINING: () => c.DRAINING,
  INTERNAL: () => c.generic,
};

const WALLET_CODES = new Set<string>(Object.keys(c.wallet));

export function isApiCode(code: string): code is ErrorCode {
  return Object.hasOwn(API_MESSAGES, code);
}

/** Inline message for an error while sealing or cancelling in epoch `epoch`. */
export function errorMessage(e: unknown, epoch: bigint | null): string {
  const info = errorInfo(e);
  const epochText = epoch === null ? '?' : epoch.toString();
  const seconds = Math.max(1, Math.ceil((info.retryAfterMs ?? 1000) / 1000));
  let message: string;
  if (info.kind === 'wallet' && WALLET_CODES.has(info.code)) {
    message = c.wallet[info.code as WalletErrorCode];
    // An unclassified wallet error says nothing on its own. Show the wallet's words.
    const own = (e as { message?: unknown } | null)?.message;
    if (info.code === 'unknown' && typeof own === 'string' && own.length > 0 && own !== 'unknown') {
      message = `The wallet reported: ${own}. Nothing was sent.`;
    }
  } else if (isApiCode(info.code)) {
    message = API_MESSAGES[info.code](epochText, seconds);
  } else if (info.code === 'self_trade') {
    message = tradeCopy.selfTrade;
  } else if (info.code === 'paused') {
    message = tradeCopy.seal.paused;
  } else if (info.kind === 'verify' || info.code === 'unverified') {
    message = tradeCopy.seal.unverified;
  } else if (info.kind === 'storage') {
    message = c.storage;
  } else if (info.kind === 'network' || info.kind === 'timeout') {
    message = c.network;
  } else if (info.kind === 'schema' || info.kind === 'decode') {
    message = c.schema;
  } else {
    message = c.generic;
  }
  return info.refusal ? `${message} ${c.refusalSaved}` : message;
}

/** Message for a `submit_failed` record, whose state carries only the code. */
export function failedCodeMessage(code: string, epoch: bigint | null): string {
  return errorMessage({ kind: 'api', code }, epoch);
}
