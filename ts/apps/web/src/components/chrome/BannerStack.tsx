import type { ReactNode } from 'react';
import { Fragment, useState } from 'react';

import { componentsCopy } from '../copy';
import type { BannerSeverity } from '../primitives/Banner';
import { Banner } from '../primitives/Banner';
import { Button } from '../primitives/Button';
import styles from './BannerStack.module.css';

interface StackBannerBase {
  id: string;
  /** Orders the stack: critical banners first, and only they never collapse behind "+N". */
  severity: BannerSeverity;
  /** What the assertive live region says when a critical banner appears. Defaults to a text title. */
  spoken?: string | undefined;
}

/** A banner described as data, rendered with the shared Banner. */
export interface StackBannerData extends StackBannerBase {
  title: ReactNode;
  body?: ReactNode;
  actions?: ReactNode;
  /** Ignored for critical banners. */
  dismissible?: boolean | undefined;
  /** Hides the body behind a toggle. Ignored for critical banners. */
  collapsed?: boolean | undefined;
  onToggle?: (() => void) | undefined;
}

/**
 * A banner component placed in the stack as it is (VerificationBanner,
 * GovernanceWatch, SimulatedBanner, PersistenceWarning). It keeps its own
 * copy, actions and toggle. `severity` must be the one it renders.
 */
export interface StackBannerElement extends StackBannerBase {
  element: ReactNode;
}

export type StackBanner = StackBannerData | StackBannerElement;

export interface BannerStackProps {
  /** In  order. Critical banners are moved to the top, otherwise order is kept. */
  banners: readonly StackBanner[];
  /** Non-critical banners shown before the rest collapse behind "+N". */
  maxExpanded?: number | undefined;
  onDismiss?: ((id: string) => void) | undefined;
}

/** Orders the stack: critical first, the rest in the given order. */
export function orderBanners(banners: readonly StackBanner[]): StackBanner[] {
  return [
    ...banners.filter((b) => b.severity === 'critical'),
    ...banners.filter((b) => b.severity !== 'critical'),
  ];
}

/**
 * Critical banners are always expanded and never dismissible. At most
 * `maxExpanded` others are shown, the rest behind a "+N" toggle.
 */
export function BannerStack({ banners, maxExpanded = 2, onDismiss }: BannerStackProps) {
  const [showAll, setShowAll] = useState(false);
  if (banners.length === 0) return null;
  const ordered = orderBanners(banners);
  const critical = ordered.filter((b) => b.severity === 'critical');
  const others = ordered.filter((b) => b.severity !== 'critical');
  const visibleOthers = showAll ? others : others.slice(0, maxExpanded);
  const hidden = others.length - visibleOthers.length;
  const copy = componentsCopy.bannerStack;
  return (
    <div className={styles.stack} role="region" aria-label={copy.label}>
      {[...critical, ...visibleOthers].map((banner) =>
        'element' in banner ? (
          <Fragment key={banner.id}>{banner.element}</Fragment>
        ) : (
          <Banner
            key={banner.id}
            severity={banner.severity}
            title={banner.title}
            actions={banner.actions}
            collapsed={banner.collapsed}
            onToggle={banner.onToggle}
            onDismiss={
              banner.severity !== 'critical' && banner.dismissible && onDismiss
                ? () => onDismiss(banner.id)
                : undefined
            }
          >
            {banner.body}
          </Banner>
        ),
      )}
      {hidden > 0 ? (
        <Button variant="ghost" size="sm" aria-expanded={false} onClick={() => setShowAll(true)}>
          {copy.more(hidden)}
        </Button>
      ) : null}
      {showAll && others.length > maxExpanded ? (
        <Button variant="ghost" size="sm" aria-expanded onClick={() => setShowAll(false)}>
          {copy.fewer}
        </Button>
      ) : null}
    </div>
  );
}
