import { fireEvent, render, screen } from '@testing-library/react';
import { describe, expect, it, vi } from 'vitest';

import { expectNoSeriousAxeViolations } from '../testing/a11y';
import { MaskedValue } from './MaskedValue';

describe('MaskedValue', () => {
  it('is named "hidden value" and not pressed while masked', async () => {
    const onRevealedChange = vi.fn();
    render(
      <MaskedValue revealed={false} onRevealedChange={onRevealedChange}>
        12.5 SOL
      </MaskedValue>,
    );
    const button = screen.getByRole('button', { name: 'hidden value' });
    expect(button.getAttribute('aria-pressed')).toBe('false');
    expect(screen.queryByText('12.5 SOL')).toBeNull();
    fireEvent.click(button);
    expect(onRevealedChange).toHaveBeenCalledWith(true);
    await expectNoSeriousAxeViolations();
  });

  it('shows the value and is pressed while revealed', async () => {
    const onRevealedChange = vi.fn();
    render(
      <MaskedValue revealed onRevealedChange={onRevealedChange}>
        12.5 SOL
      </MaskedValue>,
    );
    const button = screen.getByRole('button', { name: '12.5 SOL' });
    expect(button.getAttribute('aria-pressed')).toBe('true');
    fireEvent.click(button);
    expect(onRevealedChange).toHaveBeenCalledWith(false);
    await expectNoSeriousAxeViolations();
  });
});
