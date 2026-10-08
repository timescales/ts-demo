import { render, screen, within } from '@testing-library/react';
import { describe, expect, it } from 'vitest';

import { ACTIVITY } from '../gallery/fixtures';
import { expectNoSeriousAxeViolations } from '../testing/a11y';
import { ActivityDrawer } from './ActivityDrawer';

describe('ActivityDrawer', () => {
  it('lists jobs with status in words', async () => {
    render(<ActivityDrawer open onClose={() => undefined} items={ACTIVITY} />);
    const drawer = screen.getByRole('dialog', { name: 'Activity' });
    const items = within(drawer).getAllByRole('listitem');
    expect(items).toHaveLength(4);
    expect(
      items.map((li) => within(li).getByText(/In progress|Done|Failed|Needs action/).textContent),
    ).toEqual(['In progress', 'Done', 'Failed', 'Needs action']);
    await expectNoSeriousAxeViolations();
  });

  it('shows the empty state', async () => {
    render(<ActivityDrawer open onClose={() => undefined} items={[]} />);
    expect(screen.getByText('Nothing in progress.')).toBeTruthy();
    await expectNoSeriousAxeViolations();
  });
});
