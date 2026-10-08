import { fireEvent, render, screen } from '@testing-library/react';
import { describe, expect, it, vi } from 'vitest';

import { expectNoSeriousAxeViolations } from '../testing/a11y';
import { Button } from './Button';

describe('Button', () => {
  it.each(['primary', 'secondary', 'ghost', 'danger'] as const)(
    'renders the %s variant',
    async (variant) => {
      const onClick = vi.fn();
      render(
        <Button variant={variant} onClick={onClick}>
          Seal order
        </Button>,
      );
      const button = screen.getByRole('button', { name: 'Seal order' });
      expect(button.getAttribute('type')).toBe('button');
      fireEvent.click(button);
      expect(onClick).toHaveBeenCalledOnce();
      await expectNoSeriousAxeViolations();
    },
  );

  it('marks a busy button and keeps its name', async () => {
    render(<Button busy>Submitting</Button>);
    const button = screen.getByRole('button', { name: 'Submitting' });
    expect(button.getAttribute('aria-busy')).toBe('true');
    await expectNoSeriousAxeViolations();
  });

  it('does not fire when disabled', async () => {
    const onClick = vi.fn();
    render(
      <Button disabled onClick={onClick}>
        Seal order
      </Button>,
    );
    fireEvent.click(screen.getByRole('button'));
    expect(onClick).not.toHaveBeenCalled();
    await expectNoSeriousAxeViolations();
  });
});
