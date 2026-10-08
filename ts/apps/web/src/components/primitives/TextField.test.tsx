import { render, screen } from '@testing-library/react';
import { describe, expect, it } from 'vitest';

import { expectNoSeriousAxeViolations } from '../testing/a11y';
import { TextField } from './TextField';

describe('TextField', () => {
  it('has a visible label and links its hint', async () => {
    render(<TextField label="Note" hint="Shown only on this device" />);
    const input = screen.getByLabelText('Note');
    const hint = screen.getByText('Shown only on this device');
    expect(input.getAttribute('aria-describedby')).toBe(hint.id);
    expect(input.getAttribute('aria-invalid')).toBeNull();
    await expectNoSeriousAxeViolations();
  });

  it('links an error and marks the field invalid', async () => {
    render(<TextField label="Note" hint="Hint" error="Too long" />);
    const input = screen.getByLabelText('Note');
    expect(input.getAttribute('aria-invalid')).toBe('true');
    const ids = input.getAttribute('aria-describedby')?.split(' ') ?? [];
    expect(ids).toHaveLength(2);
    expect(document.getElementById(ids[1] ?? '')?.textContent).toContain('Too long');
    await expectNoSeriousAxeViolations();
  });
});
