import type { MarketDetail } from '@timescales/sdk/api';
import { hex } from '@timescales/sdk/core';
import type { OrderRecord } from '@timescales/sdk/orders';
import { useState } from 'react';

import { DirectionGlyph } from '../../components/motif';
import { componentsCopy } from '../../components/copy';
import { Button, CopyHash, Drawer, VisuallyHidden } from '../../components/primitives';
import { unitsOf } from '../trade/data';
import type { JournalPort, NumberFormat, OrdersPort } from '../trade/services';
import { localize, lotsToBaseText, priceOf } from '../trade/units';
import { CancelDialog } from './CancelDialog';
import { ordersCopy } from './copy';
import { saveFile } from './download';
import { lanesOf, LifecycleTimeline } from './LifecycleTimeline';
import { resolveBadge } from './lifecycleUi';
import { OrderBadge } from './OrderBadge';
import styles from './orders.module.css';
import { VerificationChecklist } from './VerificationChecklist';

const CANCELLABLE = new Set<OrderRecord['state']['kind']>([
  'working',
  'paused_needs_app',
  'reseal_needs_consent',
  'submit_failed',
  'cancel_pending',
]);

export function cancellable(r: OrderRecord): boolean {
  return r.body.kind === 'place' && CANCELLABLE.has(r.state.kind);
}

export interface OrderDrawerProps {
  record: OrderRecord;
  detail: MarketDetail | undefined;
  numberFormat: NumberFormat;
  orders: OrdersPort | null;
  journal: JournalPort | null;
  /** Epoch a cancel would seal into now, or null when it is not known. */
  cancelEpoch: bigint | null;
  maskByDefault: boolean;
  onClose: () => void;
  onReseal?: ((record: OrderRecord) => void) | undefined;
}

/**
 * Order details in memory only (never in the URL): one lane per
 * participation, the verification checklist of the chosen lane, and the actions.
 */
export function OrderDrawer({
  record,
  detail,
  numberFormat,
  orders,
  journal,
  cancelEpoch,
  maskByDefault,
  onClose,
  onReseal,
}: OrderDrawerProps) {
  const copy = ordersCopy.drawer;
  const units = detail ? unitsOf(detail) : null;
  const lanes = lanesOf(record);
  const [selected, setSelected] = useState<bigint | null>(lanes[lanes.length - 1]?.epoch ?? null);
  const [revealed, setRevealed] = useState(!maskByDefault);
  const [cancelling, setCancelling] = useState(false);
  const [exportError, setExportError] = useState(false);
  const lane = lanes.find((p) => p.epoch === selected) ?? null;
  const order = record.body.kind === 'place' ? record.body.order : null;
  const badge = resolveBadge(record, units, numberFormat);
  const hidden = (
    <>
      <span aria-hidden="true">••••</span>
      <VisuallyHidden>{componentsCopy.hiddenValue}</VisuallyHidden>
    </>
  );

  const exportEvidence = async () => {
    if (journal === null) return;
    try {
      const all = await journal.listEvidence();
      const mine = all.filter((e) => record.evidence.includes(e.id));
      for (const e of mine) {
        saveFile(e.bytes, `evidence-${e.kind}-${e.epoch}.json`, 'application/json');
      }
      setExportError(mine.length === 0);
    } catch {
      setExportError(true);
    }
  };

  return (
    <>
      <Drawer open onClose={onClose} title={copy.title} description={copy.privateNote}>
        <section className={styles.drawerSummary} aria-label={copy.summary}>
          <p className={styles.drawerMarket}>
            {detail?.name ?? record.market}
            {order ? <DirectionGlyph side={order.side === 0 ? 'buy' : 'sell'} /> : null}
          </p>
          <OrderBadge badge={badge} />
          {order ? (
            <dl className={styles.facts}>
              <div>
                <dt>{ordersCopy.table.role}</dt>
                <dd>{order.role === 0 ? ordersCopy.table.maker : ordersCopy.table.taker}</dd>
              </div>
              <div>
                <dt>{ordersCopy.table.qty}</dt>
                <dd className={styles.mono}>
                  {revealed && units
                    ? `${localize(lotsToBaseText(units, order.quantity), numberFormat)} ${detail?.baseSymbol ?? ''}`
                    : hidden}
                </dd>
              </div>
              <div>
                <dt>{ordersCopy.table.limit}</dt>
                <dd className={styles.mono}>
                  {order.kind === 1
                    ? ordersCopy.table.market_order
                    : revealed && units
                      ? localize(priceOf(units, order.limit), numberFormat)
                      : hidden}
                </dd>
              </div>
              <div>
                <dt>{ordersCopy.table.epochs}</dt>
                <dd className={styles.mono}>
                  {ordersCopy.table.epochRange(
                    order.validFrom.toString(),
                    order.expiresAt.toString(),
                  )}
                </dd>
              </div>
            </dl>
          ) : null}
          <div className={styles.hash}>
            <span className={styles.muted}>{copy.commitment}</span>
            <CopyHash value={hex.encode(record.commitment)} label={copy.commitment} />
          </div>
        </section>

        <h3>{copy.timeline}</h3>
        <LifecycleTimeline
          record={record}
          units={units}
          numberFormat={numberFormat}
          selected={selected}
          onSelect={setSelected}
        />
        {lane ? (
          <VerificationChecklist
            record={record}
            participation={lane}
            epochHref={`/epochs/${record.market}/${lane.epoch}`}
          />
        ) : null}

        <div className={styles.drawerActions}>
          <Button aria-pressed={revealed} onClick={() => setRevealed((v) => !v)}>
            {revealed ? copy.hide : copy.reveal}
          </Button>
          {record.evidence.length > 0 && journal ? (
            <Button onClick={() => void exportEvidence()}>{copy.exportEvidence}</Button>
          ) : null}
          {record.state.kind === 'reseal_needs_consent' && onReseal ? (
            <Button variant="primary" onClick={() => onReseal(record)}>
              {ordersCopy.reseal.replace}
            </Button>
          ) : null}
          {orders && cancellable(record) ? (
            <Button variant="danger" onClick={() => setCancelling(true)}>
              {copy.cancel}
            </Button>
          ) : null}
        </div>
        {exportError ? (
          <p role="alert" className={styles.result}>
            {ordersCopy.evidence.loadFailed}
          </p>
        ) : null}
      </Drawer>
      {orders && cancelling ? (
        <CancelDialog
          open
          record={record}
          orders={orders}
          epoch={cancelEpoch ?? order?.validFrom ?? 0n}
          onClose={() => setCancelling(false)}
        />
      ) : null}
    </>
  );
}
