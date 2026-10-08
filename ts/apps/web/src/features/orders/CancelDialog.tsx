import type { OrderRecord, SubmitStep } from '@timescales/sdk/orders';
import { useRef, useState } from 'react';

import type { Step, StepStatus } from '../../components/primitives';
import { Button, Dialog, Stepper } from '../../components/primitives';
import { errorMessage } from '../trade/errors';
import type { OrdersPort } from '../trade/services';
import { ordersCopy } from './copy';
import styles from './orders.module.css';
import { SecondPromptDialog } from './SecondPromptDialog';

export interface CancelDialogProps {
  open: boolean;
  record: OrderRecord;
  orders: OrdersPort;
  /** The epoch the cancel is expected to seal into (the SDK picks it with the signing budget). */
  epoch: bigint;
  onClose: () => void;
}

type Phase =
  | { kind: 'confirm' }
  | { kind: 'running'; step: SubmitStep }
  | { kind: 'done'; epoch: bigint }
  | { kind: 'failed'; message: string };

const STEP_INDEX: Record<SubmitStep, number> = {
  validating: 0,
  awaiting_wallet: 0,
  sealing: 1,
  submitting: 2,
  verifying_promise: 2,
  done: 3,
};

/**
 * A cancel is a sealed Cancel intent (one wallet signature). If its epoch
 * closes before the wallet signs, the user is asked before a second prompt.
 */
export function CancelDialog({ open, record, orders, epoch, onClose }: CancelDialogProps) {
  const copy = ordersCopy.cancel;
  const [phase, setPhase] = useState<Phase>({ kind: 'confirm' });
  const [asking, setAsking] = useState(false);
  const answer = useRef<((yes: boolean) => void) | null>(null);
  const controller = useRef<AbortController | null>(null);

  const start = () => {
    const c = new AbortController();
    controller.current = c;
    setPhase({ kind: 'running', step: 'validating' });
    orders
      .cancel(record, {
        signal: c.signal,
        onStep: (step) => setPhase((p) => (p.kind === 'running' ? { kind: 'running', step } : p)),
        confirmSecondPrompt: () =>
          new Promise<boolean>((resolve) => {
            answer.current = resolve;
            setAsking(true);
          }),
      })
      .then(
        (placement) => {
          const s = placement.state;
          setPhase({ kind: 'done', epoch: s.kind === 'cancel_pending' ? s.epoch : epoch });
        },
        (e: unknown) => setPhase({ kind: 'failed', message: copy.failed(errorMessage(e, epoch)) }),
      );
  };

  const reply = (yes: boolean) => {
    setAsking(false);
    answer.current?.(yes);
    answer.current = null;
  };

  const close = () => {
    if (phase.kind === 'running') controller.current?.abort();
    if (answer.current) reply(false);
    setPhase({ kind: 'confirm' });
    onClose();
  };

  const at =
    phase.kind === 'running'
      ? STEP_INDEX[phase.step]
      : phase.kind === 'done'
        ? 3
        : phase.kind === 'failed'
          ? 0
          : -1;
  const status = (i: number): StepStatus =>
    i < at ? 'done' : i > at ? 'upcoming' : phase.kind === 'failed' ? 'error' : 'current';
  const steps: Step[] = [
    { id: 'wallet', label: copy.confirmWallet, status: status(0) },
    { id: 'seal', label: copy.sealing, status: status(1) },
    { id: 'submit', label: copy.submitting, status: status(2) },
  ];

  return (
    <>
      <Dialog
        open={open}
        onClose={close}
        title={copy.title}
        description={copy.body(epoch.toString())}
        footer={
          <div className={styles.dialogActions}>
            {phase.kind === 'confirm' ? (
              <>
                <Button onClick={close}>{copy.keep}</Button>
                <Button variant="danger" onClick={start}>
                  {copy.confirm}
                </Button>
              </>
            ) : phase.kind === 'failed' ? (
              <>
                <Button onClick={close}>{copy.close}</Button>
                <Button variant="primary" onClick={start}>
                  {copy.retry}
                </Button>
              </>
            ) : (
              <Button onClick={close}>{copy.close}</Button>
            )}
          </div>
        }
      >
        {phase.kind !== 'confirm' ? <Stepper label={copy.stepsLabel} steps={steps} /> : null}
        {phase.kind === 'done' ? (
          <p className={styles.result} role="status">
            {copy.done(phase.epoch.toString())}
          </p>
        ) : null}
        {phase.kind === 'failed' ? (
          <p className={styles.result} role="alert">
            {phase.message}
          </p>
        ) : null}
      </Dialog>
      <SecondPromptDialog
        open={asking}
        why={ordersCopy.secondPrompt.cancelEpochClosed}
        onSign={() => reply(true)}
        onCancel={() => reply(false)}
      />
    </>
  );
}
