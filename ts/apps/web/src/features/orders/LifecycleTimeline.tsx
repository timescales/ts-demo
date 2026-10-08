import type { UnitContext } from '@timescales/sdk/core';
import type { OrderRecord, Participation } from '@timescales/sdk/orders';

import type { NumberFormat } from '../trade/services';
import { ordersCopy } from './copy';
import { participationBadge } from './lifecycleUi';
import { OrderBadge } from './OrderBadge';
import styles from './orders.module.css';

export function lanesOf(record: OrderRecord): Participation[] {
  return [...record.epochs.values()].sort((a, b) =>
    a.epoch < b.epoch ? -1 : a.epoch > b.epoch ? 1 : 0,
  );
}

export interface LifecycleTimelineProps {
  record: OrderRecord;
  units: UnitContext | null;
  numberFormat: NumberFormat;
  selected: bigint | null;
  onSelect: (epoch: bigint) => void;
}

/** One lane per epoch the order was sealed for: a resting order is often settling, sealed and queued at once. */
export function LifecycleTimeline({
  record,
  units,
  numberFormat,
  selected,
  onSelect,
}: LifecycleTimelineProps) {
  const lanes = lanesOf(record);
  if (lanes.length === 0) return <p className={styles.muted}>{ordersCopy.drawer.noLanes}</p>;
  return (
    <ol className={styles.timeline} aria-label={ordersCopy.drawer.timeline}>
      {lanes.map((p) => {
        const isSelected = selected === p.epoch;
        return (
          <li
            key={p.epoch.toString()}
            className={styles.lane}
            data-selected={isSelected || undefined}
          >
            <button
              type="button"
              className={styles.laneButton}
              aria-pressed={isSelected}
              onClick={() => onSelect(p.epoch)}
            >
              {ordersCopy.drawer.lane(p.epoch.toString())}
            </button>
            <OrderBadge badge={participationBadge(record, p, units, numberFormat)} />
          </li>
        );
      })}
    </ol>
  );
}
