import type { OrderRecord, Participation } from '@timescales/sdk/orders';
import { hex } from '@timescales/sdk/core';
import type { LucideIcon } from 'lucide-react';
import { CircleCheck, CircleDashed, CircleMinus, CircleX, LoaderCircle } from 'lucide-react';
import { Link } from 'react-router';

import type { CheckId, CheckStatus } from './checklist';
import { checklist } from './checklist';
import { ordersCopy } from './copy';
import styles from './orders.module.css';

const ICONS: Record<CheckStatus, LucideIcon> = {
  passed: CircleCheck,
  failed: CircleX,
  checking: LoaderCircle,
  pending: CircleDashed,
  not_reached: CircleMinus,
};

const STATUS_TEXT: Record<CheckStatus, string> = {
  passed: ordersCopy.checks.passed,
  failed: ordersCopy.checks.failed,
  checking: ordersCopy.checks.checking,
  pending: ordersCopy.checks.pending,
  not_reached: ordersCopy.checks.notApplicable,
};

function detail(id: CheckId, p: Participation): string {
  const d = ordersCopy.checks.detail;
  return id === 'promise' ? d.promise(hex.encode(p.envelopeDigest).slice(0, 16)) : d[id];
}

export interface VerificationChecklistProps {
  record: OrderRecord;
  participation: Participation;
  epochHref: string;
}

/** One row check of this order in one epoch, each with its technical detail. */
export function VerificationChecklist({
  record,
  participation,
  epochHref,
}: VerificationChecklistProps) {
  const copy = ordersCopy.checks;
  const rows = checklist(record, participation);
  const epoch = participation.epoch.toString();
  return (
    <section className={styles.checklist} aria-labelledby={`checks-${epoch}`}>
      <h3 id={`checks-${epoch}`}>{ordersCopy.drawer.checklist(epoch)}</h3>
      <ul>
        {rows.map((row) => {
          const Icon = ICONS[row.status];
          const label =
            row.id === 'quorum' && row.quorum
              ? copy.quorumValue(row.quorum.have, row.quorum.need)
              : copy[row.id];
          return (
            <li key={row.id} className={styles.check} data-status={row.status}>
              <Icon size={16} aria-hidden="true" />
              <details>
                <summary>
                  {label}: <span className={styles.checkStatus}>{STATUS_TEXT[row.status]}</span>
                </summary>
                <p className={styles.muted}>{detail(row.id, participation)}</p>
              </details>
            </li>
          );
        })}
      </ul>
      <Link to={epochHref}>{ordersCopy.drawer.epochLink(epoch)}</Link>
    </section>
  );
}
