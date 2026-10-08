// Every error the SDK can raise lands on one row: `failureRow` maps
// node error codes, wallet error codes and error kinds to a row, and this
// table gives each row its copy, severity and placement. The record type
// makes a missing row a compile error.
import type { FailureRow } from '@timescales/sdk/api';
import { failureRow } from '@timescales/sdk/api';
import { TimescalesError } from '@timescales/sdk';

import { appCopy } from '../app/copy';
import { brand } from '../design/brand';

export type Severity = 'critical' | 'warning' | 'info';
export type Placement = 'banner' | 'inline' | 'stepper' | 'dialog' | 'chip' | 'activity';

export interface FailureCopy {
  severity: Severity;
  placement: Placement;
  /** Short copy. `detail` comes from the error where the row needs it. */
  text: (detail: FailureDetail) => string;
}

export interface FailureDetail {
  code: string;
  /** The error's own message, shown where the code alone says too little. */
  message?: string | undefined;
  epoch?: string | undefined;
  retryAfterS?: number | undefined;
}

const name = brand.name;
const b = appCopy.banners;

export const FAILURE_ROWS: Readonly<Record<FailureRow, FailureCopy>> = {
  verification_failed: {
    severity: 'critical',
    placement: 'banner',
    text: () =>
      "Could not verify this result. Don't rely on it. Trading in this market is paused on this device.",
  },
  verification_inconclusive: {
    severity: 'info',
    placement: 'inline',
    text: () => b.inconclusive('this result'),
  },
  epoch_key_not_vouched: {
    severity: 'warning',
    placement: 'inline',
    text: (d) => b.keyNotVouched(d.epoch ?? 'N'),
  },
  version_mismatch: { severity: 'critical', placement: 'banner', text: () => b.versionMismatch },
  api_unreachable: { severity: 'warning', placement: 'banner', text: () => b.apiUnreachable },
  response_invalid: { severity: 'warning', placement: 'banner', text: () => b.responseInvalid },
  clock_skew: { severity: 'info', placement: 'banner', text: () => b.clockSkew('1') },
  intake_paused: {
    severity: 'warning',
    placement: 'banner',
    text: () => b.intakePaused(b.pauseReasons.unknown),
  },
  market_halted: { severity: 'critical', placement: 'banner', text: () => b.halted },
  market_unavailable: { severity: 'critical', placement: 'banner', text: () => b.recovering },
  wallet_declined: {
    severity: 'warning',
    placement: 'stepper',
    text: (d) =>
      d.code === 'unsupported_feature' ||
      d.code === 'modified_message' ||
      d.code === 'bad_signature'
        ? `This wallet can't sign ${name} orders.`
        : d.code === 'rejected' || d.code === 'abandoned' || !d.message
          ? 'Declined in wallet. Nothing was sent.'
          : `The wallet returned an error: ${d.message}. Nothing was sent.`,
  },
  wallet_changed: {
    severity: 'warning',
    placement: 'banner',
    text: (d) =>
      d.code === 'locked'
        ? b.walletLocked
        : d.code === 'disconnected'
          ? b.walletDisconnected
          : 'Your wallet switched to another account.',
  },
  wallet_busy: {
    severity: 'info',
    placement: 'stepper',
    text: (d) =>
      d.code === 'timeout'
        ? 'Still waiting for your wallet... Cancel'
        : 'Your wallet already has a request open.',
  },
  session_error: {
    severity: 'warning',
    placement: 'dialog',
    text: (d) => appCopy.session.errors[d.code] ?? appCopy.session.errors.fallback!,
  },
  session_evicted: {
    severity: 'warning',
    placement: 'chip',
    text: () => appCopy.session.errors.SESSION_REVOKED!,
  },
  not_eligible: {
    severity: 'warning',
    placement: 'inline',
    // The node says which: no account, or too little available value.
    text: (d) =>
      d.message !== undefined && /below/.test(d.message)
        ? `Deposit more to trade: the ${d.message.replace(/^available value/, 'available balance is')}.`
        : `Open a ${name} account first.`,
  },
  duplicate_commitment: {
    severity: 'info',
    placement: 'activity',
    text: () => 'This order was already submitted from another tab or device.',
  },
  pruned: {
    severity: 'info',
    placement: 'inline',
    text: () => 'This epoch is older than the service keeps. Its public data is in the archive.',
  },
  capacity_refused: {
    severity: 'info',
    placement: 'inline',
    text: (d) =>
      d.code === 'QUOTA_EXCEEDED'
        ? "You've reached the order limit for this epoch."
        : d.code === 'BATCH_FULL'
          ? `Epoch #${d.epoch ?? 'N'} is full.`
          : 'The cutoff passed.',
  },
  partial_parking: {
    severity: 'info',
    placement: 'inline',
    text: () => `Some later epochs need ${name} open.`,
  },
  rate_limited: {
    severity: 'info',
    placement: 'inline',
    text: (d) => `Busy, retrying in ${d.retryAfterS ?? 1}s.`,
  },
  journal_unavailable: {
    severity: 'warning',
    placement: 'banner',
    text: () => 'Some local records can’t be read on this device.',
  },
  insecure_context: {
    severity: 'critical',
    placement: 'banner',
    text: () => appCopy.insecure.title,
  },
};

/** The rows and copy for any thrown value. */
export function describeFailure(e: unknown): { row: FailureRow; copy: FailureCopy; text: string } {
  const err =
    e instanceof TimescalesError
      ? e
      : new TimescalesError({ kind: 'network', code: 'unknown', cause: e });
  const row = failureRow(err);
  const copy = FAILURE_ROWS[row];
  const details = (err.details ?? {}) as { epoch?: unknown };
  const text = copy.text({
    code: err.code,
    message: err.message.length > 0 && err.message !== err.code ? err.message : undefined,
    epoch: typeof details.epoch === 'string' ? details.epoch : undefined,
    retryAfterS:
      err.retryAfterMs === undefined ? undefined : Math.max(1, Math.ceil(err.retryAfterMs / 1000)),
  });
  return { row, copy, text };
}
