import { render, screen } from '@testing-library/react';
import { describe, expect, it } from 'vitest';

import { expectNoSeriousAxeViolations } from '../testing/a11y';
import { InlineError } from './InlineError';
import { Stepper } from './Stepper';

describe('Stepper', () => {
  it('marks the current step and states every status in text', async () => {
    render(
      <Stepper
        label="Seal order"
        steps={[
          { id: 'a', label: 'Confirm in wallet', status: 'done' },
          { id: 'b', label: 'Encrypting', status: 'current' },
          { id: 'c', label: 'Submitting', status: 'upcoming' },
        ]}
      />,
    );
    const list = screen.getByRole('list', { name: 'Seal order' });
    const items = screen.getAllByRole('listitem');
    expect(list.tagName).toBe('OL');
    expect(items.map((li) => li.getAttribute('aria-current'))).toEqual([null, 'step', null]);
    expect(items.map((li) => li.textContent)).toEqual([
      'Confirm in wallet (done)',
      '2Encrypting (current step)',
      '3Submitting (not started)',
    ]);
    await expectNoSeriousAxeViolations();
  });

  it('shows an error step with its detail', async () => {
    render(
      <Stepper
        label="Seal order"
        steps={[
          {
            id: 'a',
            label: 'Confirm in wallet',
            status: 'error',
            detail: <InlineError>Nothing was sent</InlineError>,
          },
        ]}
      />,
    );
    expect(screen.getByText(/needs attention/)).toBeTruthy();
    expect(screen.getByText('Nothing was sent')).toBeTruthy();
    await expectNoSeriousAxeViolations();
  });
});
