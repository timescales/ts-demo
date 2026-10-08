import { render, screen } from '@testing-library/react';
import { describe, expect, it } from 'vitest';

import { expectNoSeriousAxeViolations } from '../testing/a11y';
import { Button } from './Button';
import { EmptyState } from './EmptyState';

describe('EmptyState', () => {
  it('renders a headline, body and action', async () => {
    render(
      <EmptyState
        title="Nothing yet."
        body="Sealed orders appear here."
        action={<Button>Trade</Button>}
      />,
    );
    expect(screen.getByRole('heading', { level: 2, name: 'Nothing yet.' })).toBeTruthy();
    expect(screen.getByText('Sealed orders appear here.')).toBeTruthy();
    expect(screen.getByRole('button', { name: 'Trade' })).toBeTruthy();
    await expectNoSeriousAxeViolations();
  });

  it('can render its headline as a paragraph', async () => {
    render(<EmptyState as="p" title="No evidence." />);
    expect(screen.queryByRole('heading')).toBeNull();
    await expectNoSeriousAxeViolations();
  });
});
