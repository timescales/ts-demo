import { fireEvent, render, screen } from '@testing-library/react';
import { describe, expect, it, vi } from 'vitest';

import { expectNoSeriousAxeViolations } from '../testing/a11y';
import { ToggleGroup } from './ToggleGroup';

const OPTIONS = [
  { value: 'buy', label: 'Buy ▲', tone: 'buy' },
  { value: 'sell', label: 'Sell ▼', tone: 'sell' },
] as const;

describe('ToggleGroup', () => {
  it('renders nothing selected', async () => {
    render(<ToggleGroup label="Side" options={OPTIONS} value="" onValueChange={() => undefined} />);
    expect(screen.getByRole('radiogroup', { name: 'Side' })).toBeTruthy();
    await expectNoSeriousAxeViolations();
  });

  it('reports a new selection and ignores a click on the selected option', async () => {
    const onValueChange = vi.fn();
    render(
      <ToggleGroup label="Side" options={OPTIONS} value="buy" onValueChange={onValueChange} />,
    );
    const sell = screen.getByText('Sell ▼').closest('button');
    const buy = screen.getByText('Buy ▲').closest('button');
    expect(buy?.getAttribute('data-state')).toBe('on');
    if (!sell || !buy) throw new Error('missing toggle items');
    fireEvent.click(buy);
    expect(onValueChange).not.toHaveBeenCalled();
    fireEvent.click(sell);
    expect(onValueChange).toHaveBeenCalledWith('sell');
    await expectNoSeriousAxeViolations();
  });

  it('renders disabled', async () => {
    render(
      <ToggleGroup
        label="Side"
        options={OPTIONS}
        value="sell"
        disabled
        onValueChange={() => undefined}
      />,
    );
    for (const button of screen.getAllByRole('radio')) {
      expect((button as HTMLButtonElement).disabled).toBe(true);
    }
    await expectNoSeriousAxeViolations();
  });
});
