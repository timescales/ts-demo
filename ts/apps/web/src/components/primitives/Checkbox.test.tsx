import { fireEvent, render, screen } from '@testing-library/react';
import { describe, expect, it, vi } from 'vitest';

import { expectNoSeriousAxeViolations } from '../testing/a11y';
import { Checkbox } from './Checkbox';

describe('Checkbox', () => {
  it('is labelled, described by its hint and reports changes', async () => {
    const onCheckedChange = vi.fn();
    render(
      <Checkbox
        label="Announce market phase changes"
        hint="Off by default."
        checked={false}
        onCheckedChange={onCheckedChange}
      />,
    );
    const box = screen.getByRole('checkbox', { name: 'Announce market phase changes' });
    expect(document.getElementById(box.getAttribute('aria-describedby') ?? '')?.textContent).toBe(
      'Off by default.',
    );
    fireEvent.click(box);
    expect(onCheckedChange).toHaveBeenCalledWith(true);
    await expectNoSeriousAxeViolations();
  });
});
