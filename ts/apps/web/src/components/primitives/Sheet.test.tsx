import { fireEvent, render, screen } from '@testing-library/react';
import { describe, expect, it, vi } from 'vitest';

import { expectNoSeriousAxeViolations } from '../testing/a11y';
import { Sheet } from './Sheet';

describe('Sheet', () => {
  it('opens as a modal dialog and closes on a backdrop click', async () => {
    const onClose = vi.fn();
    render(
      <Sheet open onClose={onClose} title="Deposit">
        <p>Amount</p>
      </Sheet>,
    );
    const dialog = screen.getByRole('dialog', { name: 'Deposit' }) as HTMLDialogElement;
    expect(dialog.open).toBe(true);
    await expectNoSeriousAxeViolations();
    fireEvent.click(dialog);
    expect(onClose).toHaveBeenCalledOnce();
  });

  it('renders closed', async () => {
    render(<Sheet open={false} onClose={() => undefined} title="Deposit" />);
    expect((document.querySelector('dialog') as HTMLDialogElement).open).toBe(false);
    await expectNoSeriousAxeViolations();
  });
});
