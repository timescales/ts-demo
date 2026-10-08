import { HardDrive } from 'lucide-react';

import { Button } from '../../components/primitives';
import type { JournalPort } from '../trade/services';
import { ordersCopy } from './copy';
import styles from './orders.module.css';

export interface JournalBannerProps {
  journal: JournalPort;
  lastExportAtMs: number | null;
  onExport: () => void;
  onImport: () => void;
  onReconcile: () => void;
}

const date = new Intl.DateTimeFormat(undefined, { dateStyle: 'medium', timeStyle: 'short' });

/** Order details live only on this device. The banner keeps a backup one click away. */
export function JournalBanner({
  journal,
  lastExportAtMs,
  onExport,
  onImport,
  onReconcile,
}: JournalBannerProps) {
  const copy = ordersCopy.journal;
  const last = lastExportAtMs === null ? copy.never : date.format(new Date(lastExportAtMs));
  const warning =
    journal.available === 'memory'
      ? copy.memory
      : journal.persisted === false
        ? copy.notPersistent
        : null;
  return (
    <section
      className={styles.journal}
      aria-labelledby="journal-banner-title"
      data-warning={warning ? true : undefined}
    >
      <HardDrive size={20} aria-hidden="true" />
      <div>
        <h2 id="journal-banner-title" className={styles.journalTitle}>
          {copy.title}
        </h2>
        <p>{copy.body(last)}</p>
        {warning ? <p className={styles.warningText}>{warning}</p> : null}
      </div>
      <div className={styles.journalActions}>
        <Button size="sm" onClick={onExport}>
          {copy.export}
        </Button>
        <Button size="sm" onClick={onImport}>
          {copy.import}
        </Button>
        <Button size="sm" onClick={onReconcile}>
          {copy.reconcile}
        </Button>
      </div>
    </section>
  );
}
