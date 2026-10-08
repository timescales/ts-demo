import { fireEvent, render, screen } from '@testing-library/react';
import { describe, expect, it, vi } from 'vitest';

import { expectNoSeriousAxeViolations } from '../testing/a11y';
import { Button } from './Button';
import { Dialog } from './Dialog';

function dialogElement(): HTMLDialogElement {
  const dialog = document.querySelector('dialog');
  if (!dialog) throw new Error('no dialog');
  return dialog;
}

describe('Dialog', () => {
  it('stays closed until opened', async () => {
    render(<Dialog open={false} onClose={() => undefined} title="Cancel order" />);
    expect(dialogElement().open).toBe(false);
    await expectNoSeriousAxeViolations();
  });

  it('opens as a native modal dialog, labelled and described', async () => {
    render(
      <Dialog
        open
        onClose={() => undefined}
        title="Cancel order"
        description="One wallet signature."
        footer={<Button>Keep order</Button>}
      >
        <p>Body</p>
      </Dialog>,
    );
    const dialog = dialogElement();
    expect(dialog.open).toBe(true);
    expect(screen.getByRole('dialog', { name: 'Cancel order' })).toBe(dialog);
    expect(
      document.getElementById(dialog.getAttribute('aria-describedby') ?? '')?.textContent,
    ).toBe('One wallet signature.');
    await expectNoSeriousAxeViolations();
  });

  it('reports the close button and Escape, and closes when the prop turns false', async () => {
    const onClose = vi.fn();
    const { rerender } = render(<Dialog open onClose={onClose} title="Cancel order" />);
    fireEvent.click(screen.getByRole('button', { name: 'Close' }));
    expect(onClose).toHaveBeenCalledTimes(1);
    // The browser closes the dialog on Escape and fires `close`.
    dialogElement().close();
    expect(onClose).toHaveBeenCalledTimes(2);
    rerender(<Dialog open={false} onClose={onClose} title="Cancel order" />);
    expect(dialogElement().open).toBe(false);
    expect(onClose).toHaveBeenCalledTimes(2);
    await expectNoSeriousAxeViolations();
  });

  it('does not close a centred dialog on a backdrop click', () => {
    const onClose = vi.fn();
    render(<Dialog open onClose={onClose} title="Cancel order" />);
    fireEvent.click(dialogElement());
    expect(onClose).not.toHaveBeenCalled();
  });
});
