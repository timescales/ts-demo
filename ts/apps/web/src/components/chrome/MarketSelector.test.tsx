import { fireEvent, render, screen } from '@testing-library/react';
import { describe, expect, it, vi } from 'vitest';

import { MARKETS } from '../gallery/fixtures';
import { expectNoSeriousAxeViolations } from '../testing/a11y';
import { MarketSelector } from './MarketSelector';

describe('MarketSelector', () => {
  it('lists markets with their flow mode and reports the address', async () => {
    const onChange = vi.fn();
    render(<MarketSelector markets={MARKETS} value="market-a" onChange={onChange} />);
    const select = screen.getByLabelText('Market') as HTMLSelectElement;
    expect([...select.options].map((o) => o.textContent)).toEqual([
      'SOL/USDC (dual-flow)',
      'JUP/USDC (single book)',
    ]);
    fireEvent.change(select, { target: { value: 'market-b' } });
    expect(onChange).toHaveBeenCalledWith('market-b');
    await expectNoSeriousAxeViolations();
  });
});

describe('MarketSelector (compact)', () => {
  it('keeps a visible label beside the select', async () => {
    render(
      <MarketSelector markets={MARKETS} value="market-a" onChange={() => undefined} compact />,
    );
    const select = screen.getByLabelText('Market');
    expect(select.parentElement?.className).toMatch(/inline/);
    await expectNoSeriousAxeViolations();
  });
});

describe('MarketSelector (loading parameters)', () => {
  it('names a market without a flow mode until its parameters load', () => {
    render(
      <MarketSelector
        markets={[{ address: 'market-c', label: 'BONK/USDC', flow: null }]}
        value="market-c"
        onChange={() => undefined}
      />,
    );
    const select = screen.getByLabelText('Market') as HTMLSelectElement;
    expect([...select.options].map((o) => o.textContent)).toEqual(['BONK/USDC']);
  });
});
