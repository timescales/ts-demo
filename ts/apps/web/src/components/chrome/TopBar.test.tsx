import { render, screen } from '@testing-library/react';
import { describe, expect, it } from 'vitest';

import { NAV } from '../gallery/fixtures';
import { expectNoSeriousAxeViolations } from '../testing/a11y';
import { TopBar } from './TopBar';
import { WalletButton } from './WalletButton';

describe('TopBar', () => {
  it('renders the wordmark link, navigation and current page', async () => {
    render(
      <TopBar
        homeHref="/"
        nav={NAV}
        wallet={<WalletButton state="disconnected" onClick={() => undefined} />}
      />,
    );
    expect(screen.getByRole('banner')).toBeTruthy();
    expect(screen.getByRole('link', { name: 'Timescales home' }).getAttribute('href')).toBe('/');
    const nav = screen.getByRole('navigation', { name: 'Main' });
    expect(nav.querySelectorAll('a')).toHaveLength(4);
    expect(screen.getByRole('link', { name: 'Trade' }).getAttribute('aria-current')).toBe('page');
    expect(screen.getByRole('link', { name: 'Orders' }).getAttribute('aria-current')).toBeNull();
    expect(screen.getByRole('button', { name: 'Connect wallet' })).toBeTruthy();
    await expectNoSeriousAxeViolations();
  });

  it('uses a router link renderer when given one', async () => {
    render(
      <TopBar
        homeHref="/"
        nav={NAV}
        renderLink={({ children, ...props }) => (
          <a {...props} data-router="yes">
            {children}
          </a>
        )}
      />,
    );
    expect(screen.getAllByRole('link').every((a) => a.getAttribute('data-router') === 'yes')).toBe(
      true,
    );
    await expectNoSeriousAxeViolations();
  });
});
