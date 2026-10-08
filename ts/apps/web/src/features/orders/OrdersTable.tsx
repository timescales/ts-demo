import type { MarketDetail } from '@timescales/sdk/api';
import type { OrderRecord } from '@timescales/sdk/orders';
import type { ReactNode } from 'react';
import { useState } from 'react';

import { DirectionGlyph } from '../../components/motif';
import type { Column } from '../../components/primitives';
import { Button, MaskedValue, Table } from '../../components/primitives';
import { unitsOf } from '../trade/data';
import type { NumberFormat } from '../trade/services';
import { localize, lotsToBaseText, priceOf } from '../trade/units';
import { ordersCopy } from './copy';
import { resolveBadge } from './lifecycleUi';
import { epochWindow, updatedAt } from './lists';
import { OrderBadge } from './OrderBadge';
import styles from './orders.module.css';

export interface OrderListProps {
  caption: string;
  records: readonly OrderRecord[];
  details: ReadonlyMap<string, MarketDetail>;
  numberFormat: NumberFormat;
  maskByDefault: boolean;
  empty: string;
  onOpen: (record: OrderRecord) => void;
}

const time = new Intl.DateTimeFormat(undefined, { timeStyle: 'medium' });

function filledPercent(r: OrderRecord): string {
  if (r.body.kind !== 'place' || r.body.order.quantity === 0n) return '0';
  const tenths = (r.filled * 1000n) / r.body.order.quantity;
  const frac = tenths % 10n;
  return `${tenths / 10n}${frac === 0n ? '' : `.${frac}`}`;
}

/** Row values shared by the table and the cards. */
function useRows(props: OrderListProps) {
  const [revealed, setRevealed] = useState<ReadonlySet<string>>(() => new Set());
  const { details, numberFormat, maskByDefault } = props;
  const masked = (key: string, value: string): ReactNode => (
    <MaskedValue
      revealed={!maskByDefault || revealed.has(key)}
      onRevealedChange={(on) =>
        setRevealed((prev) => {
          const next = new Set(prev);
          if (on) next.add(key);
          else next.delete(key);
          return next;
        })
      }
    >
      {value}
    </MaskedValue>
  );
  return (r: OrderRecord) => {
    const detail = details.get(r.market);
    const units = detail ? unitsOf(detail) : null;
    const order = r.body.kind === 'place' ? r.body.order : null;
    const window = epochWindow(r);
    const badge = resolveBadge(r, units, numberFormat);
    const market = detail?.name ?? `${r.market.slice(0, 4)}...${r.market.slice(-4)}`;
    const epochs = window
      ? ordersCopy.table.epochRange(window.from.toString(), window.to.toString())
      : '-';
    return {
      market,
      side: order ? <DirectionGlyph side={order.side === 0 ? 'buy' : 'sell'} /> : null,
      role: order?.role === 1 ? ordersCopy.table.taker : ordersCopy.table.maker,
      qty:
        order && units
          ? masked(
              `${r.id}:q`,
              `${localize(lotsToBaseText(units, order.quantity), numberFormat)} ${detail?.baseSymbol ?? ''}`,
            )
          : '-',
      limit:
        order?.kind === 1
          ? ordersCopy.table.market_order
          : order && units
            ? masked(`${r.id}:l`, localize(priceOf(units, order.limit), numberFormat))
            : '-',
      filled: ordersCopy.table.percent(filledPercent(r)),
      epochs,
      badge: <OrderBadge badge={badge} />,
      updated: updatedAt(r) > 0 ? time.format(new Date(updatedAt(r))) : '-',
      open: (
        <Button
          size="sm"
          variant="ghost"
          aria-label={ordersCopy.table.openLabel(market, epochs)}
          onClick={() => props.onOpen(r)}
        >
          {ordersCopy.table.open}
        </Button>
      ),
    };
  };
}

/** Desktop list (OrdersTable). */
export function OrdersTable(props: OrderListProps) {
  const row = useRows(props);
  const t = ordersCopy.table;
  const rows = props.records.map((r) => ({ id: r.id, v: row(r) }));
  const columns: Column<(typeof rows)[number]>[] = [
    { key: 'market', header: t.market, cell: (x) => x.v.market },
    { key: 'side', header: t.side, cell: (x) => x.v.side },
    { key: 'role', header: t.role, cell: (x) => x.v.role },
    { key: 'qty', header: t.qty, cell: (x) => x.v.qty, numeric: true },
    { key: 'limit', header: t.limit, cell: (x) => x.v.limit, numeric: true },
    { key: 'filled', header: t.filled, cell: (x) => x.v.filled, numeric: true },
    { key: 'epochs', header: t.epochs, cell: (x) => x.v.epochs },
    { key: 'status', header: t.status, cell: (x) => x.v.badge },
    { key: 'updated', header: t.updated, cell: (x) => x.v.updated },
    { key: 'open', header: t.open, cell: (x) => x.v.open },
  ];
  return (
    <Table
      caption={props.caption}
      captionHidden
      columns={columns}
      rows={rows}
      rowKey={(x) => x.id}
      empty={props.empty}
    />
  );
}

/** Narrow-screen list: tables become cards. */
export function OrderCards(props: OrderListProps) {
  const row = useRows(props);
  const t = ordersCopy.table;
  if (props.records.length === 0) return <p className={styles.muted}>{props.empty}</p>;
  return (
    <ul className={styles.cards} aria-label={props.caption}>
      {props.records.map((r) => {
        const v = row(r);
        return (
          <li key={r.id} className={styles.card}>
            <div className={styles.cardHead}>
              <strong>{v.market}</strong>
              {v.side}
              {v.badge}
            </div>
            <dl className={styles.facts}>
              <div>
                <dt>{t.role}</dt>
                <dd>{v.role}</dd>
              </div>
              <div>
                <dt>{t.qty}</dt>
                <dd>{v.qty}</dd>
              </div>
              <div>
                <dt>{t.limit}</dt>
                <dd>{v.limit}</dd>
              </div>
              <div>
                <dt>{t.filled}</dt>
                <dd>{v.filled}</dd>
              </div>
              <div>
                <dt>{t.epochs}</dt>
                <dd>{v.epochs}</dd>
              </div>
              <div>
                <dt>{t.updated}</dt>
                <dd>{v.updated}</dd>
              </div>
            </dl>
            {v.open}
          </li>
        );
      })}
    </ul>
  );
}
