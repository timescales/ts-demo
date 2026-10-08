import { fireEvent, render, screen } from '@testing-library/react';
import { describe, expect, it, vi } from 'vitest';

import { expectNoSeriousAxeViolations } from '../testing/a11y';
import { NumberField } from './NumberField';

describe('NumberField', () => {
  it('passes the typed text through unchanged (no float conversion)', async () => {
    const onValueChange = vi.fn();
    render(<NumberField label="Quantity" unit="SOL" value="" onValueChange={onValueChange} />);
    const input = screen.getByLabelText('Quantity') as HTMLInputElement;
    expect(input.inputMode).toBe('decimal');
    fireEvent.change(input, { target: { value: '18446744073709551615.000000001' } });
    expect(onValueChange).toHaveBeenCalledWith('18446744073709551615.000000001');
    await expectNoSeriousAxeViolations();
  });

  it('describes the exact signed value, the hint and the error', async () => {
    render(
      <NumberField
        label="Limit price"
        value="182.371"
        onValueChange={() => undefined}
        exact="Signed price: 182.37"
        hint="Band 180.00 - 185.00"
        error="Outside the band"
      />,
    );
    const input = screen.getByLabelText('Limit price');
    const described = (input.getAttribute('aria-describedby') ?? '')
      .split(' ')
      .map((id) => document.getElementById(id)?.textContent ?? '');
    expect(described).toEqual([
      'Signed price: 182.37',
      'Band 180.00 - 185.00',
      'Error: Outside the band',
    ]);
    expect(input.getAttribute('aria-invalid')).toBe('true');
    await expectNoSeriousAxeViolations();
  });
});
