import { render, screen } from '@testing-library/react';
import { describe, expect, it } from 'vitest';

import { expectNoSeriousAxeViolations } from '../testing/a11y';
import { SealGlyph } from './SealGlyph';

describe('SealGlyph', () => {
  it('names the epoch it is sealed for', async () => {
    render(<SealGlyph epoch={18422n} />);
    const seal = screen.getByRole('img', { name: 'Sealed for epoch 18422' });
    expect(seal.textContent).toBe('18422');
    await expectNoSeriousAxeViolations();
  });

  it('can be decorative', async () => {
    const { container } = render(<SealGlyph epoch="7" decorative />);
    expect(screen.queryByRole('img')).toBeNull();
    expect(container.querySelector('svg')?.getAttribute('aria-hidden')).toBe('true');
    await expectNoSeriousAxeViolations();
  });
});
