import type { LucideIcon } from 'lucide-react';
import { CircleCheck, CircleDashed, CircleMinus, CircleX } from 'lucide-react';

import type { Tone } from '../../components/types';
import { Badge } from '../../components/primitives';
import type { CheckResult } from './checks';
import { epochsCopy } from './copy';
import styles from './Epochs.module.css';

const LOOK: Record<CheckResult['status'], { icon: LucideIcon; tone: Tone }> = {
  ok: { icon: CircleCheck, tone: 'buy' },
  fail: { icon: CircleX, tone: 'danger' },
  pending: { icon: CircleDashed, tone: 'info' },
  skipped: { icon: CircleMinus, tone: 'neutral' },
};

export interface CheckRow {
  id: string;
  label: string;
  result: CheckResult;
}

/** One row per check: glyph + word + sentence, with the technical reason under it. */
export function CheckList({ rows, label }: { rows: readonly CheckRow[]; label: string }) {
  return (
    <ul className={styles.checks} aria-label={label}>
      {rows.map((row) => {
        const { icon: Icon, tone } = LOOK[row.result.status];
        return (
          <li key={row.id} className={styles.check} data-status={row.result.status}>
            <Badge tone={tone} icon={<Icon aria-hidden="true" />}>
              {epochsCopy.check[row.result.status]}
            </Badge>
            <span>{row.label}</span>
            {row.result.status !== 'ok' ? (
              <span className={styles.reason}>{row.result.reason}</span>
            ) : row.result.note ? (
              <span className={styles.reason}>{row.result.note}</span>
            ) : null}
          </li>
        );
      })}
    </ul>
  );
}
