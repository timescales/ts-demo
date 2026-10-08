import type { ReactNode } from 'react';
import { useRef, useState } from 'react';

import type { Step, StepStatus } from '../../components/primitives';
import { Button, CopyHash, Sheet, Stepper } from '../../components/primitives';
import type { Address } from '../trade/services';
import { fundsCopy } from './copy';
import styles from './funds.module.css';
import type { FundsAction, FundsPort } from './port';
import type { TxOutcome, TxProgress, TxStep } from './txRun';
import { runTx } from './txRun';

const ORDER: Record<TxStep, number> = { build: 0, sign: 0, send: 1, done: 3 };

/** sign -> send -> confirmed / failed / expired, with Retry (TxStepper). */
export function TxStepper({ progress }: { progress: TxProgress }) {
  const copy = fundsCopy.tx;
  const at = progress.outcome?.kind === 'confirmed' ? 3 : ORDER[progress.step];
  const failed = progress.outcome?.kind === 'failed';
  const status = (i: number): StepStatus =>
    i < at ? 'done' : i > at ? 'upcoming' : failed ? 'error' : 'current';
  const steps: Step[] = [
    { id: 'sign', label: copy.sign, status: status(0) },
    { id: 'send', label: copy.send, status: status(1) },
    { id: 'confirm', label: copy.confirm, status: status(2) },
  ];
  return <Stepper label={copy.label} steps={steps} />;
}

export interface TxSheetProps {
  open: boolean;
  title: string;
  description?: string | undefined;
  port: FundsPort;
  market: Address;
  /** The action to send, or null while the form is invalid (the submit then shows the errors). */
  action: () => FundsAction | null;
  submitLabel?: string | undefined;
  estimate: ReactNode;
  /** The epoch a WithdrawLocked failure waits for. */
  unlockEpoch?: bigint | null | undefined;
  children?: ReactNode;
  onClose: () => void;
  onFinished: (outcome: TxOutcome) => void;
}

/** A sheet for one public transaction: its fields, the fee or rent estimate, then the stepper. */
export function TxSheet({
  open,
  title,
  description,
  port,
  market,
  action,
  submitLabel = fundsCopy.tx.submit,
  estimate,
  unlockEpoch,
  children,
  onClose,
  onFinished,
}: TxSheetProps) {
  const copy = fundsCopy.tx;
  const [progress, setProgress] = useState<TxProgress | null>(null);
  const controller = useRef<AbortController | null>(null);
  const running = progress !== null && progress.outcome === null;
  const outcome = progress?.outcome ?? null;

  const submit = () => {
    const a = action();
    if (a === null) return;
    const c = new AbortController();
    controller.current = c;
    void runTx(port, market, a, setProgress, {
      signal: c.signal,
      unlockEpoch: unlockEpoch ?? null,
    }).then(onFinished);
  };

  const close = () => {
    if (running) controller.current?.abort();
    setProgress(null);
    onClose();
  };

  return (
    <Sheet
      open={open}
      onClose={close}
      title={title}
      description={description}
      footer={
        <div className={styles.actions}>
          <Button onClick={close}>{copy.close}</Button>
          {outcome?.kind === 'confirmed' ? null : (
            <Button
              variant="primary"
              busy={running}
              disabled={running || (outcome?.kind === 'failed' && !outcome.retry)}
              onClick={submit}
            >
              {outcome?.kind === 'failed' ? copy.retry : submitLabel}
            </Button>
          )}
        </div>
      }
    >
      <div className={styles.sheetBody}>
        {progress === null || outcome?.kind === 'failed' ? children : null}
        <div className={styles.estimate}>
          {estimate}
          <p>{fundsCopy.publicTx}</p>
        </div>
        {progress ? <TxStepper progress={progress} /> : null}
        {outcome?.kind === 'confirmed' ? <p role="status">{copy.confirmed}</p> : null}
        {outcome?.kind === 'failed' ? <p role="alert">{outcome.message}</p> : null}
        {outcome?.signature ? <CopyHash value={outcome.signature} label={copy.signature} /> : null}
      </div>
    </Sheet>
  );
}
