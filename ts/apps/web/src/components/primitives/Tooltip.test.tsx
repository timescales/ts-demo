import { render, screen } from '@testing-library/react';
import { describe, expect, it } from 'vitest';

import { expectNoSeriousAxeViolations } from '../testing/a11y';
import { Button } from './Button';
import { Dialog } from './Dialog';
import { Tooltip } from './Tooltip';

describe('Tooltip', () => {
  it('renders only the trigger while closed', async () => {
    render(
      <Tooltip content="Possible causes">
        <Button>Why?</Button>
      </Tooltip>,
    );
    expect(screen.getByRole('button', { name: 'Why?' })).toBeTruthy();
    expect(screen.queryByRole('tooltip')).toBeNull();
    await expectNoSeriousAxeViolations();
  });

  it('describes the trigger while open', async () => {
    render(
      <Tooltip content="Possible causes" open>
        <Button>Why?</Button>
      </Tooltip>,
    );
    const tooltip = await screen.findByRole('tooltip');
    expect(tooltip.textContent).toBe('Possible causes');
    expect(screen.getByRole('button', { name: 'Why?' }).getAttribute('aria-describedby')).toBe(
      tooltip.id,
    );
    await expectNoSeriousAxeViolations();
  });

  it('opens inside a modal dialog, which covers anything portalled to <body>', async () => {
    render(
      <Dialog open onClose={() => undefined} title="Order details">
        <Tooltip content="Possible causes" open>
          <Button>Why?</Button>
        </Tooltip>
      </Dialog>,
    );
    const tooltip = await screen.findByRole('tooltip');
    const dialog = screen.getByRole('dialog', { name: 'Order details' });
    expect(dialog.contains(tooltip)).toBe(true);
    await expectNoSeriousAxeViolations();
  });
});
