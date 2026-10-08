import type { LucideIcon } from 'lucide-react';
import { ChevronDown, FlaskConical, Info, OctagonAlert, TriangleAlert, X } from 'lucide-react';
import type { ReactNode } from 'react';
import { useId } from 'react';

import { componentsCopy } from '../copy';
import { cx } from '../cx';
import styles from './Banner.module.css';
import { IconButton } from './IconButton';

export type BannerSeverity = 'critical' | 'warning' | 'info' | 'simulated';

const ICONS: Record<BannerSeverity, LucideIcon> = {
  critical: OctagonAlert,
  warning: TriangleAlert,
  info: Info,
  simulated: FlaskConical,
};

export interface BannerProps {
  severity: BannerSeverity;
  title: ReactNode;
  children?: ReactNode;
  actions?: ReactNode;
  /** Non-critical banners only: hides the body behind a toggle. */
  collapsed?: boolean | undefined;
  onToggle?: (() => void) | undefined;
  /** Non-critical banners only. */
  onDismiss?: (() => void) | undefined;
  className?: string | undefined;
}

/**
 * A persistent notice. Critical banners ignore `collapsed` and
 * `onDismiss`: they are always expanded and cannot be dismissed.
 */
export function Banner({
  severity,
  title,
  children,
  actions,
  collapsed = false,
  onToggle,
  onDismiss,
  className,
}: BannerProps) {
  const titleId = useId();
  const bodyId = useId();
  const critical = severity === 'critical';
  const isCollapsed = !critical && collapsed;
  const Icon = ICONS[severity];
  const hasBody = Boolean(children) || Boolean(actions);
  return (
    <section
      className={cx(styles.banner, styles[severity], className)}
      aria-labelledby={titleId}
      data-severity={severity}
    >
      <Icon className={styles.icon} size={20} aria-hidden="true" />
      <div className={styles.content}>
        <p className={styles.title} id={titleId}>
          {title}
        </p>
        {hasBody ? (
          <div className={styles.body} id={bodyId} hidden={isCollapsed}>
            {children ? <div className={styles.text}>{children}</div> : null}
            {actions ? <div className={styles.actions}>{actions}</div> : null}
          </div>
        ) : null}
      </div>
      <div className={styles.controls}>
        {!critical && onToggle && hasBody ? (
          <IconButton
            label={isCollapsed ? componentsCopy.expand : componentsCopy.collapse}
            aria-expanded={!isCollapsed}
            aria-controls={bodyId}
            className={styles.toggle}
            icon={<ChevronDown size={18} aria-hidden="true" />}
            onClick={onToggle}
          />
        ) : null}
        {!critical && onDismiss ? (
          <IconButton
            label={componentsCopy.dismiss}
            icon={<X size={18} aria-hidden="true" />}
            onClick={onDismiss}
          />
        ) : null}
      </div>
    </section>
  );
}
