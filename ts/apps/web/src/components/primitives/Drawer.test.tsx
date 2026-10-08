import { fireEvent, render, screen } from '@testing-library/react';
import { describe, expect, it, vi } from 'vitest';

import { expectNoSeriousAxeViolations } from '../testing/a11y';
import { Drawer } from './Drawer';

describe('Drawer', () => {
  it('opens as a modal dialog; its content does not close it', async () => {
    const onClose = vi.fn();
    render(
      <Drawer open onClose={onClose} title="Order details">
        <p>Timeline</p>
      </Drawer>,
    );
    const dialog = screen.getByRole('dialog', { name: 'Order details' }) as HTMLDialogElement;
    expect(dialog.open).toBe(true);
    fireEvent.click(screen.getByText('Timeline'));
    expect(onClose).not.toHaveBeenCalled();
    fireEvent.click(dialog);
    expect(onClose).toHaveBeenCalledOnce();
    await expectNoSeriousAxeViolations();
  });

  it('renders closed', async () => {
    render(<Drawer open={false} onClose={() => undefined} title="Order details" />);
    expect((document.querySelector('dialog') as HTMLDialogElement).open).toBe(false);
    await expectNoSeriousAxeViolations();
  });
});
