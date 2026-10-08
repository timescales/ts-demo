import type { LucideIcon } from 'lucide-react';
import { CircleAlert, CircleCheck, CircleX, LoaderCircle } from 'lucide-react';
import type { ReactNode } from 'react';

import { componentsCopy } from '../copy';
import { Badge } from '../primitives/Badge';
import { Drawer } from '../primitives/Drawer';
import type { Tone } from '../types';
import styles from './ActivityDrawer.module.css';

export type ActivityStatus = 'pending' | 'done' | 'failed' | 'action';

export interface ActivityItem {
  id: string;
  title: ReactNode;
  status: ActivityStatus;
  detail?: ReactNode;
  /** Preformatted time. */
  time?: string | undefined;
  /** E.g. Retry, for failures that need the user. */
  action?: ReactNode;
}

export interface ActivityDrawerProps {
  open: boolean;
  onClose: () => void;
  items: readonly ActivityItem[];
}

const STATUS: Record<ActivityStatus, { icon: LucideIcon; tone: Tone }> = {
  pending: { icon: LoaderCircle, tone: 'info' },
  done: { icon: CircleCheck, tone: 'buy' },
  failed: { icon: CircleX, tone: 'danger' },
  action: { icon: CircleAlert, tone: 'warning' },
};

/** Background jobs: wallet prompts, sealing, transactions, settlement, failures. */
export function ActivityDrawer({ open, onClose, items }: ActivityDrawerProps) {
  const copy = componentsCopy.activity;
  return (
    <Drawer open={open} onClose={onClose} title={copy.title}>
      {items.length === 0 ? (
        <p className={styles.empty}>{copy.empty}</p>
      ) : (
        <ul className={styles.list}>
          {items.map((item) => {
            const { icon: Icon, tone } = STATUS[item.status];
            return (
              <li key={item.id} className={styles.item}>
                <div className={styles.head}>
                  <span className={styles.title}>{item.title}</span>
                  <Badge tone={tone} icon={<Icon aria-hidden="true" />}>
                    {copy.status[item.status]}
                  </Badge>
                </div>
                {item.detail ? <div className={styles.detail}>{item.detail}</div> : null}
                {item.time ? <span className={styles.time}>{item.time}</span> : null}
                {item.action ? <div>{item.action}</div> : null}
              </li>
            );
          })}
        </ul>
      )}
    </Drawer>
  );
}
