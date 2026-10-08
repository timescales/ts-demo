import { fireEvent, render, screen } from '@testing-library/react';
import { describe, expect, it, vi } from 'vitest';

import { expectNoSeriousAxeViolations } from '../testing/a11y';
import { Select } from './Select';

const OPTIONS = [
  { value: 'dot', label: '1,234.56' },
  { value: 'comma', label: '1.234,56' },
  { value: 'space', label: '1 234,56', disabled: true },
];

describe('Select', () => {
  it('is a labelled native select', async () => {
    const onValueChange = vi.fn();
    render(
      <Select label="Number format" options={OPTIONS} value="dot" onValueChange={onValueChange} />,
    );
    const select = screen.getByLabelText('Number format') as HTMLSelectElement;
    expect(select.tagName).toBe('SELECT');
    fireEvent.change(select, { target: { value: 'comma' } });
    expect(onValueChange).toHaveBeenCalledWith('comma');
    await expectNoSeriousAxeViolations();
  });

  it('shows an error', async () => {
    render(
      <Select
        label="Market"
        options={OPTIONS}
        value="dot"
        onValueChange={() => undefined}
        error="Pick a market"
      />,
    );
    expect(screen.getByLabelText('Market').getAttribute('aria-invalid')).toBe('true');
    await expectNoSeriousAxeViolations();
  });
});
