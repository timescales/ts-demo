import type { EpochSummary, PublicPhase } from '@timescales/sdk/api';
import { useState } from 'react';

import { componentsCopy } from '../../components/copy';
import type { Column } from '../../components/primitives';
import {
  Button,
  EmptyState,
  PhaseBadge,
  Select,
  SimulatedLabel,
  Skeleton,
  Table,
} from '../../components/primitives';
import { routerLink } from '../../app/links';
import { formatClearing, formatDateTime } from '../../state/format';
import { useEpochs, useMarketDetail } from '../../state/queries';
import type { Address } from '../../state/types';
import { epochsCopy } from './copy';
import styles from './Epochs.module.css';

const PHASES = Object.keys(componentsCopy.phase).filter((p) => p !== 'unknown') as PublicPhase[];

/** The epoch table (Epoch explorer): filter by phase, page backwards in time. */
export function EpochExplorer({ market }: { market: Address }) {
  const t = epochsCopy.table;
  const [before, setBefore] = useState<bigint | null>(null);
  const [phase, setPhase] = useState<PublicPhase | ''>('');
  const page = useEpochs(market, before);
  const detail = useMarketDetail(market).data;
  const rows = (page.data?.items ?? []).filter((e) => phase === '' || e.phase === phase);
  const columns: Column<EpochSummary>[] = [
    {
      key: 'epoch',
      header: t.epoch,
      cell: (e) => routerLink({ href: `/epochs/${market}/${e.epoch}`, children: `#${e.epoch}` }),
    },
    { key: 'phase', header: t.phase, cell: (e) => <PhaseBadge phase={e.phase} /> },
    { key: 'cutoff', header: t.cutoff, cell: (e) => formatDateTime(e.cutoffMs) },
    {
      key: 'envelopes',
      header: t.envelopes,
      numeric: true,
      cell: (e) => (e.envelopeCount === null ? t.none : String(e.envelopeCount)),
    },
    {
      key: 'clearing',
      header: t.clearing,
      numeric: true,
      cell: (e) =>
        e.clearing === null || e.clearing.length === 0
          ? t.none
          : formatClearing(detail, e.clearing),
    },
    {
      key: 'fills',
      header: t.fills,
      numeric: true,
      cell: (e) => (e.fillCount === null ? t.none : String(e.fillCount)),
    },
    {
      key: 'settled',
      header: t.settled,
      cell: (e) =>
        e.phase === 'settled' && e.terminalAtMs !== null ? formatDateTime(e.terminalAtMs) : t.none,
    },
    {
      key: 'enclave',
      header: t.enclave,
      cell: (e) =>
        e.teePlatform === 'simulated' ? (
          <SimulatedLabel />
        ) : e.teePlatform === 'intel_tdx' ? (
          t.tdxReported
        ) : (
          t.none
        ),
    },
  ];
  return (
    <div className={styles.panels}>
      <div className={styles.panel}>
        <div className={styles.toolbar}>
          <Select
            label={epochsCopy.filter}
            value={phase}
            onValueChange={(v) => setPhase(v as PublicPhase | '')}
            options={[
              { value: '', label: epochsCopy.filterAll },
              ...PHASES.map((p) => ({ value: p, label: componentsCopy.phase[p] })),
            ]}
          />
          <div className={styles.pager}>
            <Button size="sm" disabled={before === null} onClick={() => setBefore(null)}>
              {epochsCopy.newer}
            </Button>
            <Button
              size="sm"
              disabled={page.data?.nextBefore == null}
              onClick={() => setBefore(page.data?.nextBefore ?? null)}
            >
              {epochsCopy.older}
            </Button>
          </div>
        </div>
        {page.data ? (
          <Table
            caption={t.caption}
            columns={columns}
            rows={rows}
            rowKey={(e) => String(e.epoch)}
            empty={<EmptyState as="p" title={epochsCopy.empty} />}
          />
        ) : page.isError ? (
          <p>{epochsCopy.loadFailed}</p>
        ) : (
          <Skeleton lines={5} />
        )}
      </div>
    </div>
  );
}
