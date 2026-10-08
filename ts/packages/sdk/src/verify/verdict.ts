/**
 * Result of a client-side check. `fail` is a hard error that stops
 * trading on the market. `inconclusive` means the data is not yet consistent
 * and the check is retried. Verifiers never throw on adversarial input.
 */
export type Verdict<T = void> =
  | { kind: 'ok'; value: T }
  | { kind: 'fail'; reason: string; evidence?: Uint8Array }
  | { kind: 'inconclusive'; reason: string; retryAfterMs: number };

/** Default retry delay for an inconclusive check (RPC lag is a few slots). */
export const RETRY_MS = 2_000;

export function ok<T>(value: T): Verdict<T> {
  return { kind: 'ok', value };
}

export function fail<T>(reason: string, evidence?: Uint8Array): Verdict<T> {
  return evidence === undefined ? { kind: 'fail', reason } : { kind: 'fail', reason, evidence };
}

export function inconclusive<T>(reason: string, retryAfterMs = RETRY_MS): Verdict<T> {
  return { kind: 'inconclusive', reason, retryAfterMs };
}

/** Thrown inside a check to end it with `fail`. */
export class CheckFailed extends Error {
  readonly evidence: Uint8Array | undefined;

  constructor(reason: string, evidence?: Uint8Array) {
    super(reason);
    this.name = 'CheckFailed';
    this.evidence = evidence;
  }
}

/** Thrown inside a check to end it with `inconclusive`. */
export class CheckInconclusive extends Error {
  readonly retryAfterMs: number;

  constructor(reason: string, retryAfterMs = RETRY_MS) {
    super(reason);
    this.name = 'CheckInconclusive';
    this.retryAfterMs = retryAfterMs;
  }
}

/** Ends the check with `fail` unless `cond` holds. */
export function must(cond: boolean, reason: string): asserts cond {
  if (!cond) throw new CheckFailed(reason);
}

/** Ends the check with `inconclusive` unless `cond` holds: the data is not consistent yet. */
export function mustBeReady(cond: boolean, reason: string, retryAfterMs = RETRY_MS): asserts cond {
  if (!cond) throw new CheckInconclusive(reason, retryAfterMs);
}

/**
 * Runs a check. Any exception other than the two above (a decode error on
 * hostile bytes, a range error) becomes `fail` with its message, so a
 * verifier never throws.
 */
export function check<T>(what: string, f: () => T): Verdict<T> {
  try {
    return ok(f());
  } catch (e) {
    if (e instanceof CheckInconclusive) return inconclusive(e.message, e.retryAfterMs);
    if (e instanceof CheckFailed) return fail(e.message, e.evidence);
    return fail(`${what}: ${e instanceof Error ? e.message : String(e)}`);
  }
}
