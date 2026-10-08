import { render, screen } from '@testing-library/react';
import { describe, expect, it } from 'vitest';

import { SimulatedLabel } from '../primitives/SimulatedLabel';
import { expectNoSeriousAxeViolations } from '../testing/a11y';
import { SimStripe } from './SimStripe';

describe('SimStripe', () => {
  it.each(['div', 'span'] as const)('wraps content as a %s', async (as) => {
    const { container } = render(
      <SimStripe as={as}>
        <SimulatedLabel /> Modelled reference price
      </SimStripe>,
    );
    expect(container.firstElementChild?.tagName).toBe(as.toUpperCase());
    expect(screen.getByText('Simulated')).toBeTruthy();
    await expectNoSeriousAxeViolations();
  });
});
