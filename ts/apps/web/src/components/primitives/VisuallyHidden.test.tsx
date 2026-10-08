import { render, screen } from '@testing-library/react';
import { describe, expect, it } from 'vitest';

import { expectNoSeriousAxeViolations } from '../testing/a11y';
import { VisuallyHidden } from './VisuallyHidden';

describe('VisuallyHidden', () => {
  it('keeps its text in the accessibility tree', async () => {
    render(
      <button type="button">
        <span aria-hidden="true">▲</span>
        <VisuallyHidden>Buy</VisuallyHidden>
      </button>,
    );
    expect(screen.getByRole('button', { name: 'Buy' })).toBeTruthy();
    await expectNoSeriousAxeViolations();
  });
});
