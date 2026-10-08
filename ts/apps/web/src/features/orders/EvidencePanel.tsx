import type { MarketDetail } from '@timescales/sdk/api';
import type { EvidenceRecord } from '@timescales/sdk/verify';
import { Download } from 'lucide-react';

import type { Column } from '../../components/primitives';
import { Banner, Button, Skeleton, Table } from '../../components/primitives';
import { ordersCopy } from './copy';
import { saveFile } from './download';
import styles from './orders.module.css';

export interface EvidencePanelProps {
  evidence: readonly EvidenceRecord[] | undefined;
  failed: boolean;
  details: ReadonlyMap<string, MarketDetail>;
}

const date = new Intl.DateTimeFormat(undefined, { dateStyle: 'medium', timeStyle: 'short' });

/** Exclusion, substitution, terms, refusal and verification-failure evidence, each exportable. */
export function EvidencePanel({ evidence, failed, details }: EvidencePanelProps) {
  const c = ordersCopy.evidence;
  if (failed) return <Banner severity="warning" title={c.loadFailed} />;
  if (evidence === undefined) return <Skeleton lines={3} />;
  const rows = [...evidence].sort((a, b) => b.createdAtMs - a.createdAtMs);
  const columns: Column<EvidenceRecord>[] = [
    { key: 'kind', header: c.kind, cell: (e) => c.kinds[e.kind] },
    { key: 'market', header: c.market, cell: (e) => details.get(e.market)?.name ?? e.market },
    { key: 'epoch', header: c.epoch, cell: (e) => `#${e.epoch}`, numeric: true },
    { key: 'saved', header: c.saved, cell: (e) => date.format(new Date(e.createdAtMs)) },
    {
      key: 'export',
      header: c.export,
      cell: (e) => (
        <Button
          size="sm"
          icon={<Download size={16} aria-hidden="true" />}
          aria-label={c.exportLabel(c.kinds[e.kind], e.epoch.toString())}
          onClick={() =>
            saveFile(e.bytes, `evidence-${e.kind}-${e.epoch}.json`, 'application/json')
          }
        >
          {c.export}
        </Button>
      ),
    },
  ];
  return (
    <div className={styles.panel}>
      <p className={styles.muted}>{c.verifyHint}</p>
      <Table
        caption={c.caption}
        captionHidden
        columns={columns}
        rows={rows}
        rowKey={(e) => e.id}
        empty={ordersCopy.empty.evidence}
      />
    </div>
  );
}
