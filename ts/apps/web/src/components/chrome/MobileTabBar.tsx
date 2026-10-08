import type { ReactNode } from 'react';

import { componentsCopy } from '../copy';
import { cx } from '../cx';
import type { RenderLink } from './links';
import { renderAnchor } from './links';
import styles from './MobileTabBar.module.css';

export interface TabBarItem {
  href: string;
  label: string;
  icon: ReactNode;
  current?: boolean | undefined;
}

export interface MobileTabBarProps {
  /** Trade, Orders, Funds, Epochs, More. */
  items: readonly TabBarItem[];
  renderLink?: RenderLink | undefined;
}

/** Bottom navigation below 600 px. Hidden on wider layouts. */
export function MobileTabBar({ items, renderLink = renderAnchor }: MobileTabBarProps) {
  return (
    <nav className={styles.bar} aria-label={componentsCopy.tabBar.label}>
      <ul className={styles.list}>
        {items.map((item) => (
          <li key={item.href} className={styles.cell}>
            {renderLink({
              href: item.href,
              className: cx(styles.tab, item.current && styles.current),
              'aria-current': item.current ? 'page' : undefined,
              children: (
                <>
                  {item.icon}
                  <span>{item.label}</span>
                </>
              ),
            })}
          </li>
        ))}
      </ul>
    </nav>
  );
}
