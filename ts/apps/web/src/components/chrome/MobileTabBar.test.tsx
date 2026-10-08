import { render, screen } from '@testing-library/react';
import { describe, expect, it } from 'vitest';

import { TABS } from '../gallery/fixtures';
import { expectNoSeriousAxeViolations } from '../testing/a11y';
import { MobileTabBar } from './MobileTabBar';

describe('MobileTabBar', () => {
  it('renders the five sections with the current one marked', async () => {
    render(<MobileTabBar items={TABS} />);
    const nav = screen.getByRole('navigation', { name: 'Sections' });
    const links = [...nav.querySelectorAll('a')];
    expect(links.map((a) => a.textContent)).toEqual(['Trade', 'Orders', 'Funds', 'Epochs', 'More']);
    expect(links.map((a) => a.getAttribute('aria-current'))).toEqual([
      'page',
      null,
      null,
      null,
      null,
    ]);
    await expectNoSeriousAxeViolations();
  });
});
