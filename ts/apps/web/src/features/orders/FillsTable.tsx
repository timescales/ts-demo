import type { MarketDetail } from '@timescales/sdk/api';
import type { OrderRecord } from '@timescales/sdk/orders';
import { Download } from 'lucide-react';

import { componentsCopy } from '../../components/copy';
import { DirectionGlyph } from '../../components/motif';
import type { Column } from '../../components/primitives';
import { Button, Table } from '../../components/primitives';
import { unitsOf } from '../trade/data';
import type { NumberFormat } from '../trade/services';
import { atomsToDecimal, localize, lotsToBaseText, priceOf } from '../trade/units';
import { ordersCopy } from './copy';
import { saveFile } from './download';
import { fillsByEpoch, toCsv } from './fills';
import styles from './orders.module.css';

export interface FillRow {
  key: string;
  market: string;
  marketName: string;
  epoch: bigint;
  book: string;
  side: 0 | 1;
  role: 0 | 1;
  /** Canonical decimals. The units are the market's symbols (empty when the market is unknown). */
  quantity: string;
  price: string;
  fee: string;
  base: string;
  quote: string;
  settled: boolean;
}

/** One row per verified own fill, newest epoch first. */
export function fillRows(
  records: readonly OrderRecord[],
  details: ReadonlyMap<string, MarketDetail>,
): FillRow[] {
  const rows: FillRow[] = [];
  for (const r of records) {
    const detail = details.get(r.market);
    fillsByEpoch(r).forEach((f, i) => {
      const units = detail ? unitsOf(detail) : null;
      rows.push({
        key: `${r.id}:${i}`,
        market: r.market,
        marketName: detail?.name ?? r.market,
        epoch: f.epoch,
        book:
          f.book === 0
            ? ordersCopy.fills.single
            : (detail?.books.find((b) => b.book === f.book)?.label ?? String(f.book)),
        side: f.side,
        role: f.role,
        quantity: units ? lotsToBaseText(units, f.quantity) : f.quantity.toString(),
        price: units ? priceOf(units, f.tick) : f.tick.toString(),
        fee: detail ? atomsToDecimal(f.feeQuote, detail.quoteDecimals) : f.feeQuote.toString(),
        base: detail?.baseSymbol ?? '',
        quote: detail?.quoteSymbol ?? '',
        settled: f.settled,
      });
    });
  }
  return rows.sort((a, b) => (a.epoch < b.epoch ? 1 : a.epoch > b.epoch ? -1 : 0));
}

/** The CSV the export writes: plain canonical decimals, no locale formatting. */
export function fillsCsv(rows: readonly FillRow[]): string {
  const c = ordersCopy.fills;
  const t = ordersCopy.table;
  return toCsv(
    [
      c.market,
      c.epoch,
      c.book,
      c.side,
      c.role,
      c.quantity,
      c.base,
      c.price,
      c.fee,
      c.quote,
      c.status,
    ],
    rows.map((r) => [
      r.marketName,
      r.epoch.toString(),
      r.book,
      r.side === 0 ? componentsCopy.side.buy : componentsCopy.side.sell,
      r.role === 0 ? t.maker : t.taker,
      r.quantity,
      r.base,
      r.price,
      r.fee,
      r.quote,
      r.settled ? c.settled : c.provisional,
    ]),
  );
}

export interface FillsTableProps {
  records: readonly OrderRecord[];
  details: ReadonlyMap<string, MarketDetail>;
  numberFormat: NumberFormat;
}

export function FillsTable({ records, details, numberFormat }: FillsTableProps) {
  const c = ordersCopy.fills;
  const rows = fillRows(records, details);
  const num = (v: string, unit: string) => `${localize(v, numberFormat)}${unit ? ` ${unit}` : ''}`;
  const columns: Column<FillRow>[] = [
    { key: 'market', header: c.market, cell: (r) => r.marketName },
    { key: 'epoch', header: c.epoch, cell: (r) => `#${r.epoch}`, numeric: true },
    { key: 'book', header: c.book, cell: (r) => r.book },
    {
      key: 'side',
      header: c.side,
      cell: (r) => <DirectionGlyph side={r.side === 0 ? 'buy' : 'sell'} />,
    },
    {
      key: 'role',
      header: c.role,
      cell: (r) => (r.role === 0 ? ordersCopy.table.maker : ordersCopy.table.taker),
    },
    { key: 'quantity', header: c.quantity, cell: (r) => num(r.quantity, r.base), numeric: true },
    { key: 'price', header: c.price, cell: (r) => num(r.price, ''), numeric: true },
    { key: 'fee', header: c.fee, cell: (r) => num(r.fee, r.quote), numeric: true },
    { key: 'status', header: c.status, cell: (r) => (r.settled ? c.settled : c.provisional) },
  ];
  return (
    <div className={styles.panel}>
      <div className={styles.toolbar}>
        <Button
          icon={<Download size={16} aria-hidden="true" />}
          disabled={rows.length === 0}
          onClick={() => saveFile(fillsCsv(rows), c.csvName, 'text/csv')}
          aria-describedby="fills-csv-hint"
        >
          {c.exportCsv}
        </Button>
        <p id="fills-csv-hint" className={styles.muted}>
          {c.csvHint}
        </p>
      </div>
      <Table
        caption={c.caption}
        captionHidden
        columns={columns}
        rows={rows}
        rowKey={(r) => r.key}
        empty={ordersCopy.empty.fills}
      />
    </div>
  );
}
