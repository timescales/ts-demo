import { render, screen } from '@testing-library/react';
import { describe, expect, it } from 'vitest';

import { expectNoSeriousAxeViolations } from '../testing/a11y';
import { Tabs } from './Tabs';

const ITEMS = [
  { value: 'working', label: 'Working', content: <p>Working orders</p> },
  { value: 'history', label: 'History', content: <p>Past orders</p> },
];

describe('Tabs', () => {
  it('selects the first tab by default', async () => {
    render(<Tabs label="Orders" items={ITEMS} />);
    expect(screen.getByRole('tablist', { name: 'Orders' })).toBeTruthy();
    expect(screen.getByRole('tab', { name: 'Working' }).getAttribute('aria-selected')).toBe('true');
    expect(screen.getByRole('tabpanel').textContent).toBe('Working orders');
    await expectNoSeriousAxeViolations();
  });

  it('follows a controlled value', async () => {
    render(<Tabs label="Orders" items={ITEMS} value="history" onValueChange={() => undefined} />);
    expect(screen.getByRole('tab', { name: 'History' }).getAttribute('aria-selected')).toBe('true');
    expect(screen.getByRole('tabpanel').textContent).toBe('Past orders');
    await expectNoSeriousAxeViolations();
  });
});
