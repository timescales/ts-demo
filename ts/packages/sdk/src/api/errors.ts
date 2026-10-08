import {
  TimescalesError,
  type ErrorCode,
  type TimescalesErrorKind,
  type WalletErrorCode,
} from '../errors.js';
import type { Problem } from './schemas.js';

/** HTTP status and retryability of every  code. */
export const ERROR_TABLE: Readonly<Record<ErrorCode, { http: number; retryable: boolean }>> = {
  BAD_REQUEST: { http: 400, retryable: false },
  DECODE_FAILED: { http: 400, retryable: false },
  UNSUPPORTED_MEDIA_TYPE: { http: 415, retryable: false },
  BODY_TOO_LARGE: { http: 413, retryable: false },
  VERSION_UNSUPPORTED: { http: 400, retryable: false },
  WRONG_MARKET: { http: 400, retryable: false },
  MASKED_NOT_SUPPORTED: { http: 400, retryable: false },
  BAD_SIGNATURE: { http: 401, retryable: false },
  SKEW: { http: 401, retryable: true },
  SESSION_UNKNOWN: { http: 401, retryable: false },
  SESSION_EXPIRED: { http: 401, retryable: false },
  SESSION_REVOKED: { http: 401, retryable: false },
  SESSION_TEMPLATE_INVALID: { http: 400, retryable: false },
  SESSION_DOMAIN_MISMATCH: { http: 400, retryable: false },
  SESSION_NONCE_INVALID: { http: 400, retryable: false },
  SESSION_METHOD_REFUSED: { http: 400, retryable: false },
  WALLET_NOT_ELIGIBLE: { http: 403, retryable: false },
  MARKET_HALTED: { http: 403, retryable: false },
  MARKET_UNKNOWN: { http: 404, retryable: false },
  NOT_FOUND: { http: 404, retryable: false },
  NOT_YET_AVAILABLE: { http: 404, retryable: true },
  PRUNED: { http: 410, retryable: false },
  EPOCH_CLOSED: { http: 409, retryable: true },
  EPOCH_TOO_FAR: { http: 409, retryable: false },
  DUPLICATE_COMMITMENT: { http: 409, retryable: false },
  BATCH_FULL: { http: 409, retryable: true },
  QUOTA_EXCEEDED: { http: 429, retryable: true },
  RATE_LIMITED: { http: 429, retryable: true },
  EPOCH_KEY_UNAVAILABLE: { http: 503, retryable: true },
  INTAKE_PAUSED: { http: 503, retryable: true },
  MARKET_UNAVAILABLE: { http: 503, retryable: true },
  OVERLOADED: { http: 503, retryable: true },
  DRAINING: { http: 503, retryable: true },
  INTERNAL: { http: 500, retryable: true },
};

function retryableStatus(status: number): boolean {
  return status === 429 || status >= 500;
}

/** Maps a node problem (or a bare HTTP status) to a TimescalesError. Unknown codes map by HTTP class. */
export function problemToError(status: number, problem: Problem | null): TimescalesError {
  if (problem === null) {
    return new TimescalesError({
      kind: 'api',
      code: 'unknown',
      message: `HTTP ${status}`,
      retryable: retryableStatus(status),
    });
  }
  return new TimescalesError({
    kind: 'api',
    code: problem.code,
    message: problem.detail.length > 0 ? problem.detail : problem.title,
    retryable: problem.code === 'unknown' ? retryableStatus(status) : problem.retryable,
    ...(problem.retryAfterMs !== undefined ? { retryAfterMs: problem.retryAfterMs } : {}),
    requestId: problem.requestId,
    ...(problem.details !== undefined ? { details: problem.details } : {}),
  });
}

/**
 * The row of the failure-mode matrix an error belongs to. The app maps
 * rows to copy and placement. Every ErrorCode, WalletErrorCode and
 * TimescalesErrorKind has one.
 */
export type FailureRow =
  | 'verification_failed'
  | 'verification_inconclusive'
  | 'epoch_key_not_vouched'
  | 'version_mismatch'
  | 'api_unreachable'
  | 'response_invalid'
  | 'clock_skew'
  | 'intake_paused'
  | 'market_halted'
  | 'market_unavailable'
  | 'wallet_declined'
  | 'wallet_changed'
  | 'wallet_busy'
  | 'session_error'
  | 'session_evicted'
  | 'not_eligible'
  | 'duplicate_commitment'
  | 'pruned'
  | 'capacity_refused'
  | 'partial_parking'
  | 'rate_limited'
  | 'journal_unavailable'
  | 'insecure_context';

export const ERROR_ROWS: Readonly<Record<ErrorCode, FailureRow>> = {
  BAD_REQUEST: 'version_mismatch',
  DECODE_FAILED: 'version_mismatch',
  UNSUPPORTED_MEDIA_TYPE: 'version_mismatch',
  BODY_TOO_LARGE: 'version_mismatch',
  VERSION_UNSUPPORTED: 'version_mismatch',
  WRONG_MARKET: 'version_mismatch',
  MASKED_NOT_SUPPORTED: 'version_mismatch',
  BAD_SIGNATURE: 'session_error',
  SKEW: 'clock_skew',
  SESSION_UNKNOWN: 'session_error',
  SESSION_EXPIRED: 'session_error',
  SESSION_REVOKED: 'session_evicted',
  SESSION_TEMPLATE_INVALID: 'session_error',
  SESSION_DOMAIN_MISMATCH: 'session_error',
  SESSION_NONCE_INVALID: 'session_error',
  SESSION_METHOD_REFUSED: 'session_error',
  WALLET_NOT_ELIGIBLE: 'not_eligible',
  MARKET_HALTED: 'market_halted',
  MARKET_UNKNOWN: 'market_unavailable',
  NOT_FOUND: 'pruned',
  NOT_YET_AVAILABLE: 'verification_inconclusive',
  PRUNED: 'pruned',
  EPOCH_CLOSED: 'capacity_refused',
  EPOCH_TOO_FAR: 'partial_parking',
  DUPLICATE_COMMITMENT: 'duplicate_commitment',
  BATCH_FULL: 'capacity_refused',
  QUOTA_EXCEEDED: 'capacity_refused',
  RATE_LIMITED: 'rate_limited',
  EPOCH_KEY_UNAVAILABLE: 'epoch_key_not_vouched',
  INTAKE_PAUSED: 'intake_paused',
  MARKET_UNAVAILABLE: 'market_unavailable',
  OVERLOADED: 'rate_limited',
  DRAINING: 'rate_limited',
  INTERNAL: 'api_unreachable',
};

export const WALLET_ROWS: Readonly<Record<WalletErrorCode, FailureRow>> = {
  rejected: 'wallet_declined',
  unsupported_feature: 'wallet_declined',
  modified_message: 'wallet_declined',
  bad_signature: 'wallet_declined',
  abandoned: 'wallet_declined',
  unknown: 'wallet_declined',
  disconnected: 'wallet_changed',
  account_changed: 'wallet_changed',
  locked: 'wallet_changed',
  busy: 'wallet_busy',
  timeout: 'wallet_busy',
};

export const KIND_ROWS: Readonly<Record<TimescalesErrorKind, FailureRow>> = {
  api: 'api_unreachable',
  network: 'api_unreachable',
  timeout: 'api_unreachable',
  schema: 'response_invalid',
  decode: 'response_invalid',
  wallet: 'wallet_declined',
  storage: 'journal_unavailable',
  verify: 'verification_failed',
  environment: 'insecure_context',
  aborted: 'wallet_declined',
};

export function failureRow(e: TimescalesError): FailureRow {
  if (e.kind === 'api' && Object.hasOwn(ERROR_ROWS, e.code)) {
    return ERROR_ROWS[e.code as ErrorCode];
  }
  if (e.kind === 'wallet' && Object.hasOwn(WALLET_ROWS, e.code)) {
    return WALLET_ROWS[e.code as WalletErrorCode];
  }
  return KIND_ROWS[e.kind];
}
