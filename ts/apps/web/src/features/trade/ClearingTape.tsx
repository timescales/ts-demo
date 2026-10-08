import type { MarketDetail, TapeRow } from '@timescales/sdk/api';

import type { Column } from '../../components/primitives';
import { Button, PhaseBadge, Table } from '../../components/primitives';
import { tradeCopy } from './copy';
import { unitsOf } from './data';
import type { NumberFormat } from './services';
import styles from './trade.module.css';
import { localize, lotsToBaseText, priceOf } from './units';

export const TAPE_PAGE = 50;

const time = new Intl.DateTimeFormat(undefined, {
  hour: '2-digit',
  minute: '2-digit',
  second: '2-digit',
});

export function formatTime(ms: number): string {
  return time.format(new Date(ms));
}

export interface ClearingTapeProps {
  id: string;
  detail: MarketDetail;
  rows: readonly TapeRow[];
  numberFormat: NumberFormat;
  hasOlder: boolean;
  hasNewer: boolean;
  onOlder: () => void;
  onNewest: () => void;
}

/** Public result per epoch. Both books' prices in dual-flow markets. It is the chart's table alternative. */
export function ClearingTape({
  id,
  detail,
  rows,
  numberFormat,
  hasOlder,
  hasNewer,
  onOlder,
  onNewest,
}: ClearingTapeProps) {
  const copy = tradeCopy.tape;
  const u = unitsOf(detail);
  const books = detail.params.flow === 1 ? detail.books : [{ book: 0 as const, label: '' }];
  const clearing = (row: TapeRow) => {
    if (row.clearing.length === 0) return copy.notCleared;
    return books
      .map(({ book, label }) => {
        const c = row.clearing.find((x) => x.book === book);
        const value =
          c === undefined
            ? copy.notCleared
            : c.volume === 0n
              ? `${localize(priceOf(u, c.tick), numberFormat)} (${copy.noVolume})`
              : localize(priceOf(u, c.tick), numberFormat);
        return label ? `${label}: ${value}` : value;
      })
      .join(' - ');
  };
  const columns: Column<TapeRow>[] = [
    { key: 'epoch', header: copy.epoch, cell: (r) => `#${r.epoch}`, numeric: true },
    { key: 'cutoff', header: copy.cutoff, cell: (r) => formatTime(r.cutoffMs) },
    { key: 'clearing', header: copy.clearing, cell: clearing },
    {
      key: 'matched',
      header: copy.matched,
      cell: (r) =>
        `${localize(lotsToBaseText(u, r.matchedLots), numberFormat)} ${detail.baseSymbol}`,
      numeric: true,
    },
    { key: 'fills', header: copy.fills, cell: (r) => r.fillCount, numeric: true },
    {
      key: 'status',
      header: copy.status,
      cell: (r) => (r.phase === 'unknown' ? copy.notCleared : <PhaseBadge phase={r.phase} />),
    },
    {
      key: 'settled',
      header: copy.settled,
      cell: (r) =>
        r.phase === 'settled' && r.terminalAtMs !== null
          ? formatTime(r.terminalAtMs)
          : copy.notCleared,
    },
  ];
  return (
    <section className={styles.tape} id={id} tabIndex={-1} aria-labelledby={`${id}-title`}>
      <h2 id={`${id}-title`}>{copy.title}</h2>
      <Table
        caption={copy.caption}
        captionHidden
        columns={columns}
        rows={rows}
        rowKey={(r) => r.epoch.toString()}
        empty={copy.empty}
      />
      {hasOlder || hasNewer ? (
        <nav className={styles.pager} aria-label={copy.page}>
          {hasNewer ? <Button onClick={onNewest}>{copy.newer}</Button> : null}
          {hasOlder ? <Button onClick={onOlder}>{copy.older}</Button> : null}
        </nav>
      ) : null}
    </section>
  );
}
