import type { OrderRecord, SubmitStep } from '@timescales/sdk/orders';
import { useEffect, useRef, useState, useSyncExternalStore } from 'react';

import { SealGlyph, Slats } from '../../components/motif';
import type { Step, StepStatus } from '../../components/primitives';
import { Button, Dialog, Stepper } from '../../components/primitives';
import { SecondPromptDialog } from '../orders/SecondPromptDialog';
import { tradeCopy } from './copy';
import { errorInfo, errorMessage, failedCodeMessage } from './errors';
import type { SealOutcome, SealRun } from './sealRun';
import styles from './trade.module.css';
import { orderFingerprint } from './units';

/** After this long without an answer the stepper offers to stop waiting. */
export const WALLET_WAIT_MS = 20_000;

const STEP_INDEX: Record<SubmitStep, number> = {
  validating: 0,
  awaiting_wallet: 0,
  sealing: 1,
  submitting: 2,
  verifying_promise: 3,
  done: 4,
};

type Outcome =
  | { kind: 'running'; at: number }
  | { kind: 'sealed'; record: OrderRecord }
  | {
      kind: 'failed';
      at: number;
      message: string;
      action: 'retry' | 'sign_again' | 'retry_submit' | null;
    };

function outcomeOf(step: SubmitStep | null, result: SealOutcome | null, epoch: bigint): Outcome {
  const at = STEP_INDEX[step ?? 'validating'];
  if (result === null) return { kind: 'running', at };
  if (result.kind === 'error') {
    const info = errorInfo(result.error);
    const unsupported =
      info.kind === 'wallet' &&
      ['unsupported_feature', 'modified_message', 'bad_signature'].includes(info.code);
    return {
      kind: 'failed',
      at: Math.min(at, 3),
      message: errorMessage(result.error, epoch),
      action: unsupported ? null : 'retry',
    };
  }
  const r = result.record;
  switch (r.state.kind) {
    case 'wallet_rejected':
      return { kind: 'failed', at: 0, message: tradeCopy.seal.rejected, action: 'retry' };
    case 'unsupported_wallet':
      return { kind: 'failed', at: 0, message: tradeCopy.seal.unsupported, action: null };
    case 'abandoned':
      return { kind: 'failed', at: 0, message: tradeCopy.seal.abandoned, action: 'retry' };
    case 'signed_too_late':
      return { kind: 'failed', at: 0, message: tradeCopy.seal.tooLate, action: 'sign_again' };
    case 'submit_failed':
      return {
        kind: 'failed',
        at: 2,
        message: tradeCopy.seal.failed(failedCodeMessage(r.state.code, epoch)),
        action: r.state.retryable ? 'retry_submit' : 'retry',
      };
    default:
      return { kind: 'sealed', record: r };
  }
}

/** The newest record waiting for the wallet: the one whose code the wallet shows. */
export function promptedRecord(
  records: readonly OrderRecord[],
  market: string,
): OrderRecord | null {
  let best: OrderRecord | null = null;
  for (const r of records) {
    if (r.market !== market || r.state.kind !== 'awaiting_wallet') continue;
    const at = r.history[r.history.length - 1]?.atMs ?? 0;
    if (best === null || at >= (best.history[best.history.length - 1]?.atMs ?? 0)) best = r;
  }
  return best;
}

function sealedLabel(record: OrderRecord): { text: string; epoch: bigint | null } {
  const epochs = [...record.epochs.values()]
    .filter((p) => p.state.kind === 'sealed' || p.state.kind === 'parked')
    .map((p) => p.epoch)
    .sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
  const first = epochs[0];
  const last = epochs[epochs.length - 1];
  if (first === undefined || last === undefined) return { text: tradeCopy.seal.done, epoch: null };
  const sealedOpen = record.epochs.get(first)?.state.kind === 'sealed';
  return {
    text: sealedOpen
      ? tradeCopy.seal.sealed(first.toString())
      : tradeCopy.seal.queued(first.toString(), last.toString()),
    epoch: first,
  };
}

export interface SealStepperProps {
  run: SealRun;
  records: readonly OrderRecord[];
  now: () => number;
  announce?: ((message: string) => void) | undefined;
  /** Closing while the wallet is still open abandons the order (nothing is sent). */
  onClose: () => void;
  /** Start a fresh attempt with a new signature. */
  onRetry: () => void;
  /** Re-send the stored submission with the same bytes. Rejects when it could not be sent. */
  onRetrySubmit: (record: OrderRecord) => Promise<void>;
}

/**
 * Confirm in wallet (with the order fingerprint) -> Encrypting to the epoch
 * key -> Submitting -> Relay receipt verified. While a wallet pop-up has
 * focus and returns it, focus goes back to the live step.
 */
export function SealStepper({
  run,
  records,
  now,
  announce,
  onClose,
  onRetry,
  onRetrySubmit,
}: SealStepperProps) {
  const copy = tradeCopy.seal;
  const state = useSyncExternalStore(run.subscribe, run.getState, run.getState);
  const epoch = run.prepared.epochs.from;
  // The submit result is a snapshot. A re-send moves the stored record on, so
  // follow the live copy of it.
  const sealedRecord = state.outcome?.kind === 'record' ? state.outcome.record : null;
  const result: SealOutcome | null =
    sealedRecord === null
      ? state.outcome
      : { kind: 'record', record: records.find((r) => r.id === sealedRecord.id) ?? sealedRecord };
  const outcome = outcomeOf(state.step, result, epoch);
  const liveRef = useRef<HTMLParagraphElement>(null);
  const [waitedLong, setWaitedLong] = useState(false);
  const [secondPrompt, setSecondPrompt] = useState(false);
  const [resend, setResend] = useState<
    { kind: 'idle' | 'busy' } | { kind: 'failed'; message: string }
  >({ kind: 'idle' });
  // A retry swaps in a new run without remounting. Its state starts fresh.
  const [runShown, setRunShown] = useState(run);
  if (runShown !== run) {
    setRunShown(run);
    setWaitedLong(false);
    setResend({ kind: 'idle' });
  }

  const awaiting = outcome.kind === 'running' && outcome.at === 0;
  useEffect(() => {
    if (!awaiting) return;
    const left = WALLET_WAIT_MS - (now() - state.startedAt);
    const timer = setTimeout(() => setWaitedLong(true), Math.max(0, left));
    return () => clearTimeout(timer);
  }, [awaiting, now, state.startedAt]);

  useEffect(() => {
    const back = () => liveRef.current?.focus();
    window.addEventListener('focus', back);
    return () => window.removeEventListener('focus', back);
  }, []);

  const prompted =
    result?.kind === 'record' ? result.record : promptedRecord(records, run.prepared.draft.market);
  const fingerprint = prompted ? orderFingerprint(prompted.commitment) : null;

  const at = outcome.kind === 'sealed' ? 4 : outcome.at;
  const status = (i: number): StepStatus =>
    i < at ? 'done' : i > at ? 'upcoming' : outcome.kind === 'failed' ? 'error' : 'current';

  let live: string;
  if (outcome.kind === 'sealed') {
    live = sealedLabel(outcome.record).text;
  } else if (outcome.kind === 'failed') {
    live = resend.kind === 'failed' ? copy.resendFailed(resend.message) : outcome.message;
  } else if (outcome.at === 0) {
    live = waitedLong ? copy.stillWaiting : copy.confirm;
  } else if (outcome.at === 1) {
    live = copy.encrypting(epoch.toString());
  } else if (outcome.at === 2) {
    live = copy.submitting;
  } else {
    live = copy.receipt;
  }

  const lastAnnounced = useRef<string | null>(null);
  useEffect(() => {
    if (announce === undefined || lastAnnounced.current === live) return;
    lastAnnounced.current = live;
    announce(live);
  }, [announce, live]);

  const steps: Step[] = [
    {
      id: 'confirm',
      label: copy.confirm,
      status: status(0),
      detail: fingerprint ? (
        <div className={styles.fingerprint}>
          <p>{copy.fingerprint(fingerprint)}</p>
          <p className={styles.muted}>{copy.fingerprintWeak}</p>
        </div>
      ) : null,
    },
    {
      id: 'encrypt',
      label: (
        <>
          {copy.encrypting(epoch.toString())}
          {at > 1 ? ` ✓ (${copy.keyVerified})` : ''}
        </>
      ),
      status: status(1),
    },
    { id: 'submit', label: copy.submitting, status: status(2) },
    { id: 'receipt', label: `${copy.receipt}${at > 3 ? ' ✓' : ''}`, status: status(3) },
  ];

  const sealed = outcome.kind === 'sealed' ? sealedLabel(outcome.record) : null;
  const failedRecord = result?.kind === 'record' ? result.record : null;

  const retrySubmit = (record: OrderRecord) => {
    setResend({ kind: 'busy' });
    onRetrySubmit(record).then(
      () => setResend({ kind: 'idle' }),
      (e: unknown) => setResend({ kind: 'failed', message: errorMessage(e, epoch) }),
    );
  };

  const close = () => {
    run.abandon();
    onClose();
  };

  return (
    <>
      <Dialog
        open
        onClose={close}
        title={copy.title}
        footer={
          <div className={styles.dialogActions}>
            {outcome.kind === 'running' ? (
              <Button onClick={close}>{copy.cancel}</Button>
            ) : (
              <Button onClick={onClose}>{copy.close}</Button>
            )}
            {outcome.kind === 'failed' && outcome.action === 'retry' ? (
              <Button variant="primary" onClick={onRetry}>
                {copy.retry}
              </Button>
            ) : null}
            {outcome.kind === 'failed' && outcome.action === 'sign_again' ? (
              <Button variant="primary" onClick={() => setSecondPrompt(true)}>
                {copy.signAgain}
              </Button>
            ) : null}
            {outcome.kind === 'failed' && outcome.action === 'retry_submit' && failedRecord ? (
              <Button
                variant="primary"
                busy={resend.kind === 'busy'}
                disabled={resend.kind === 'busy'}
                onClick={() => retrySubmit(failedRecord)}
              >
                {copy.retry}
              </Button>
            ) : null}
          </div>
        }
      >
        <Stepper label={copy.stepsLabel} steps={steps} />
        <p
          ref={liveRef}
          tabIndex={-1}
          className={styles.liveStep}
          data-state={outcome.kind}
          {...(announce === undefined ? { role: 'status' } : {})}
        >
          {sealed?.epoch != null ? <SealGlyph epoch={sealed.epoch} size={24} decorative /> : null}
          {live}
        </p>
        {sealed ? <Slats count={5} state="closed" className={styles.sealSlats} /> : null}
      </Dialog>
      <SecondPromptDialog
        open={secondPrompt}
        why={copy.secondPromptWhyClosed}
        onCancel={() => setSecondPrompt(false)}
        onSign={() => {
          setSecondPrompt(false);
          onRetry();
        }}
      />
    </>
  );
}
