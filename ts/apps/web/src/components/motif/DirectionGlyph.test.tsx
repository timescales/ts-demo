import { render, screen } from '@testing-library/react';
import { describe, expect, it } from 'vitest';

import { expectNoSeriousAxeViolations } from '../testing/a11y';
import { DirectionGlyph } from './DirectionGlyph';

describe('DirectionGlyph', () => {
  it.each([
    ['buy', '▲', 'Buy'],
    ['sell', '▼', 'Sell'],
  ] as const)('shows %s as glyph and word', async (side, glyph, word) => {
    const { container } = render(<DirectionGlyph side={side} />);
    expect(container.textContent).toBe(`${glyph}${word}`);
    expect(screen.getByText(glyph).getAttribute('aria-hidden')).toBe('true');
    await expectNoSeriousAxeViolations();
  });

  it('keeps the word for screen readers when it is not shown', async () => {
    render(<DirectionGlyph side="sell" showWord={false} />);
    expect(screen.getByText('Sell')).toBeTruthy();
    await expectNoSeriousAxeViolations();
  });
});
