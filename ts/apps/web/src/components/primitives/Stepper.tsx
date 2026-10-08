import { Check, CircleAlert } from 'lucide-react';
import type { ReactNode } from 'react';

import { componentsCopy } from '../copy';
import { cx } from '../cx';
import styles from './Stepper.module.css';
import { VisuallyHidden } from './VisuallyHidden';

export type StepStatus = 'done' | 'current' | 'upcoming' | 'error';

export interface Step {
  id: string;
  label: ReactNode;
  status: StepStatus;
  /** Shown under the label, e.g. an error with its Retry action. */
  detail?: ReactNode;
}

export interface StepperProps {
  label: string;
  steps: readonly Step[];
  className?: string | undefined;
}

/** An ordered list of steps. The current one carries aria-current="step". */
export function Stepper({ label, steps, className }: StepperProps) {
  return (
    <ol className={cx(styles.list, className)} aria-label={label}>
      {steps.map((step, index) => (
        <li
          key={step.id}
          className={styles.step}
          data-status={step.status}
          aria-current={step.status === 'current' ? 'step' : undefined}
        >
          <span className={styles.marker} aria-hidden="true">
            {step.status === 'done' ? (
              <Check size={14} />
            ) : step.status === 'error' ? (
              <CircleAlert size={14} />
            ) : (
              index + 1
            )}
          </span>
          <div className={styles.text}>
            <span className={styles.label}>
              {step.label}
              <VisuallyHidden> ({componentsCopy.stepStatus[step.status]})</VisuallyHidden>
            </span>
            {step.detail ? <div className={styles.detail}>{step.detail}</div> : null}
          </div>
        </li>
      ))}
    </ol>
  );
}
