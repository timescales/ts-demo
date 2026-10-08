import type { MarketDetail } from '@timescales/sdk/api';
import type { OrderRecord } from '@timescales/sdk/orders';
import { useState } from 'react';
import { Link } from 'react-router';

import { DirectionGlyph } from '../../components/motif';
import { Button, MaskedValue } from '../../components/primitives';
import { OrderBadge } from '../orders/OrderBadge';
import { resolveBadge } from '../orders/lifecycleUi';
import { isOpenRecord } from '../orders/lists';
import { tradeCopy } from './copy';
import { unitsOf } from './data';
import type { NumberFormat } from './services';
import styles from './trade.module.css';
import { localize, lotsToBaseText, priceOf } from './units';

export interface MyMarketOrdersProps {
  detail: MarketDetail;
  records: readonly OrderRecord[];
  numberFormat: NumberFormat;
  maskByDefault: boolean;
  onOpen: (record: OrderRecord) => void;
  allOrdersHref: string;
}

/** The wallet's open orders in this market. Sizes and prices are masked until revealed. */
export function MyMarketOrders({
  detail,
  records,
  numberFormat,
  maskByDefault,
  onOpen,
  allOrdersHref,
}: MyMarketOrdersProps) {
  const copy = tradeCopy.myOrders;
  const u = unitsOf(detail);
  const [revealed, setRevealed] = useState<ReadonlySet<string>>(() => new Set());
  const shown = records.filter(
    (r) => r.market === detail.market && r.body.kind === 'place' && isOpenRecord(r),
  );
  const toggle = (key: string, on: boolean) =>
    setRevealed((prev) => {
      const next = new Set(prev);
      if (on) next.add(key);
      else next.delete(key);
      return next;
    });
  const masked = (key: string, value: string) => (
    <MaskedValue
      revealed={!maskByDefault || revealed.has(key)}
      onRevealedChange={(on) => toggle(key, maskByDefault ? on : true)}
    >
      {value}
    </MaskedValue>
  );

  return (
    <section className={styles.myOrders} aria-labelledby="my-market-orders">
      <h2 id="my-market-orders">{copy.title}</h2>
      {shown.length === 0 ? (
        <p className={styles.muted}>{copy.empty}</p>
      ) : (
        <ul className={styles.myOrderList}>
          {shown.map((r) => {
            if (r.body.kind !== 'place') return null;
            const o = r.body.order;
            const badge = resolveBadge(r, u, numberFormat);
            return (
              <li key={r.id} className={styles.myOrder}>
                <DirectionGlyph side={o.side === 0 ? 'buy' : 'sell'} />
                <span className={styles.myOrderValue}>
                  <span className={styles.muted}>{copy.qty}</span>
                  {masked(
                    `${r.id}:q`,
                    `${localize(lotsToBaseText(u, o.quantity), numberFormat)} ${detail.baseSymbol}`,
                  )}
                </span>
                <span className={styles.myOrderValue}>
                  <span className={styles.muted}>{copy.limit}</span>
                  {o.kind === 1
                    ? copy.marketOrder
                    : masked(`${r.id}:l`, localize(priceOf(u, o.limit), numberFormat))}
                </span>
                <OrderBadge badge={badge} />
                <Button
                  size="sm"
                  variant="ghost"
                  aria-label={copy.detailsLabel(
                    o.side === 0 ? tradeCopy.ticket.buy : tradeCopy.ticket.sell,
                    badge.text,
                  )}
                  onClick={() => onOpen(r)}
                >
                  {copy.details}
                </Button>
              </li>
            );
          })}
        </ul>
      )}
      <Link to={allOrdersHref} className={styles.allOrders}>
        {copy.all}
      </Link>
    </section>
  );
}
