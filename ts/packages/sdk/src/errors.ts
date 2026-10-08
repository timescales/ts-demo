export type TimescalesErrorKind =
  | 'api'
  | 'network'
  | 'timeout'
  | 'schema'
  | 'wallet'
  | 'decode'
  | 'storage'
  | 'verify'
  | 'environment'
  | 'aborted';

/** Every node error code. */
export type ErrorCode =
  | 'BAD_REQUEST'
  | 'DECODE_FAILED'
  | 'UNSUPPORTED_MEDIA_TYPE'
  | 'BODY_TOO_LARGE'
  | 'VERSION_UNSUPPORTED'
  | 'WRONG_MARKET'
  | 'MASKED_NOT_SUPPORTED'
  | 'BAD_SIGNATURE'
  | 'SKEW'
  | 'SESSION_UNKNOWN'
  | 'SESSION_EXPIRED'
  | 'SESSION_REVOKED'
  | 'SESSION_TEMPLATE_INVALID'
  | 'SESSION_DOMAIN_MISMATCH'
  | 'SESSION_NONCE_INVALID'
  | 'SESSION_METHOD_REFUSED'
  | 'WALLET_NOT_ELIGIBLE'
  | 'MARKET_HALTED'
  | 'MARKET_UNKNOWN'
  | 'NOT_FOUND'
  | 'NOT_YET_AVAILABLE'
  | 'PRUNED'
  | 'EPOCH_CLOSED'
  | 'EPOCH_TOO_FAR'
  | 'DUPLICATE_COMMITMENT'
  | 'BATCH_FULL'
  | 'QUOTA_EXCEEDED'
  | 'RATE_LIMITED'
  | 'EPOCH_KEY_UNAVAILABLE'
  | 'INTAKE_PAUSED'
  | 'MARKET_UNAVAILABLE'
  | 'OVERLOADED'
  | 'DRAINING'
  | 'INTERNAL';

export type WalletErrorCode =
  | 'rejected'
  | 'unsupported_feature'
  | 'modified_message'
  | 'bad_signature'
  | 'disconnected'
  | 'account_changed'
  | 'locked'
  | 'busy'
  | 'timeout'
  | 'abandoned'
  | 'unknown';

export interface TimescalesErrorInit {
  kind: TimescalesErrorKind;
  code: ErrorCode | WalletErrorCode | 'unknown' | string;
  message?: string;
  retryable?: boolean;
  retryAfterMs?: number;
  requestId?: string;
  details?: unknown;
  cause?: unknown;
}

export class TimescalesError extends Error {
  readonly kind: TimescalesErrorKind;
  readonly code: ErrorCode | WalletErrorCode | 'unknown' | string;
  readonly retryable: boolean;
  readonly retryAfterMs?: number;
  readonly requestId?: string;
  readonly details?: unknown;

  constructor(init: TimescalesErrorInit) {
    super(init.message ?? `${init.kind}: ${init.code}`, { cause: init.cause });
    this.name = 'TimescalesError';
    this.kind = init.kind;
    this.code = init.code;
    this.retryable = init.retryable ?? false;
    if (init.retryAfterMs !== undefined) this.retryAfterMs = init.retryAfterMs;
    if (init.requestId !== undefined) this.requestId = init.requestId;
    if (init.details !== undefined) this.details = init.details;
  }
}

/**
 * Thrown by SDK entry points whose implementation belongs to a later work
 * package. Not part of the public API.
 */
export class NotImplementedError extends Error {
  readonly owner: string;

  constructor(owner: string, ...args: unknown[]) {
    super(`not implemented yet (${owner}), called with ${args.length} argument(s)`);
    this.name = 'NotImplementedError';
    this.owner = owner;
  }
}
