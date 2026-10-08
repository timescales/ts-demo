import { Slats } from '../../components/motif';
import { Badge, Tooltip } from '../../components/primitives';
import { ordersCopy } from './copy';
import type { ResolvedBadge } from './lifecycleUi';
import styles from './orders.module.css';

/** Glyph + text, never colour alone. "Not filled" carries the "Why?" explanation. */
export function OrderBadge({ badge }: { badge: ResolvedBadge }) {
  const Icon = badge.spec.icon;
  return (
    <span className={styles.badgeWrap}>
      {badge.spec.slats ? (
        <Slats count={3} state={badge.spec.slats} className={styles.badgeSlats} />
      ) : null}
      <Badge tone={badge.spec.tone} icon={<Icon aria-hidden="true" />}>
        {badge.text}
      </Badge>
      {badge.notFilled ? (
        <Tooltip content={ordersCopy.whyNotFilledText}>
          <button type="button" className={styles.why}>
            {ordersCopy.whyNotFilled}
          </button>
        </Tooltip>
      ) : null}
    </span>
  );
}
