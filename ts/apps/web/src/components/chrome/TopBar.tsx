import type { ReactNode } from 'react';

import { Wordmark } from '../../design/Wordmark';
import { componentsCopy } from '../copy';
import { cx } from '../cx';
import type { RenderLink } from './links';
import { renderAnchor } from './links';
import styles from './TopBar.module.css';

export interface NavItem {
  href: string;
  label: string;
  current?: boolean | undefined;
}

export interface TopBarProps {
  homeHref: string;
  nav: readonly NavItem[];
  /** MarketSelector. Hidden below 600 px. */
  market?: ReactNode;
  /** SessionChip. Hidden below 600 px. */
  session?: ReactNode;
  wallet?: ReactNode;
  /** EpochPill. Shown only below 600 px, where the epoch strip is hidden. */
  epochPill?: ReactNode;
  renderLink?: RenderLink | undefined;
}

/** The 56 px top bar: wordmark, navigation, market, session and wallet. */
export function TopBar({
  homeHref,
  nav,
  market,
  session,
  wallet,
  epochPill,
  renderLink = renderAnchor,
}: TopBarProps) {
  return (
    <header className={styles.bar}>
      {renderLink({
        href: homeHref,
        className: styles.home,
        children: (
          <>
            <Wordmark height={24} decorative />
            <span className={styles.srOnly}>{componentsCopy.topBar.home}</span>
          </>
        ),
      })}
      <nav className={styles.nav} aria-label={componentsCopy.topBar.nav}>
        <ul className={styles.navList}>
          {nav.map((item) => (
            <li key={item.href}>
              {renderLink({
                href: item.href,
                className: cx(styles.navLink, item.current && styles.current),
                'aria-current': item.current ? 'page' : undefined,
                children: item.label,
              })}
            </li>
          ))}
        </ul>
      </nav>
      {market ? <div className={styles.market}>{market}</div> : null}
      {epochPill ? <div className={styles.pill}>{epochPill}</div> : null}
      <div className={styles.actions}>
        {session ? <div className={styles.session}>{session}</div> : null}
        {wallet}
      </div>
    </header>
  );
}
