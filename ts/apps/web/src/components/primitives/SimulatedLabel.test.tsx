import { render, screen } from '@testing-library/react';
import { describe, expect, it } from 'vitest';

import { expectNoSeriousAxeViolations } from '../testing/a11y';
import { SimulatedLabel } from './SimulatedLabel';

describe('SimulatedLabel', () => {
  it.each([
    ['simulated', 'Simulated'],
    ['modelled', 'Modelled'],
    ['untested', 'Untested'],
  ] as const)('says %s in words', async (kind, word) => {
    render(<SimulatedLabel kind={kind} />);
    expect(screen.getByText(word)).toBeTruthy();
    await expectNoSeriousAxeViolations();
  });

  it('accepts a longer label', async () => {
    render(<SimulatedLabel>Enclave: SIMULATED</SimulatedLabel>);
    expect(screen.getByText('Enclave: SIMULATED')).toBeTruthy();
    await expectNoSeriousAxeViolations();
  });
});
