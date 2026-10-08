import { FlaskConical } from 'lucide-react';
import type { ReactNode } from 'react';

import { componentsCopy } from '../copy';
import { cx } from '../cx';
import styles from './SimulatedLabel.module.css';

export type SimulatedKind = 'simulated' | 'modelled' | 'untested';

export interface SimulatedLabelProps {
  kind?: SimulatedKind | undefined;
  /** Replaces the default word, e.g. "Enclave: SIMULATED". */
  children?: ReactNode;
  className?: string | undefined;
}

/**
 * The plum label for simulated, modelled or untested components.
 * Plum is reserved for this label. The diagonal stripe tells it apart from
 * the horizontal slats that mark private values.
 */
export function SimulatedLabel({ kind = 'simulated', children, className }: SimulatedLabelProps) {
  return (
    <span className={cx(styles.label, className)} data-kind={kind}>
      <FlaskConical size={14} aria-hidden="true" />
      <span>{children ?? componentsCopy.simulated[kind]}</span>
    </span>
  );
}
