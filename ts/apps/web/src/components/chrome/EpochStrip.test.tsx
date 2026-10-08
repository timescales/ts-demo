import { render, screen } from '@testing-library/react';
import { describe, expect, it } from 'vitest';

import { expectNoSeriousAxeViolations } from '../testing/a11y';
import { EpochStrip } from './EpochStrip';

describe('EpochStrip', () => {
  it('shows market, epoch, phase and a silent timer', async () => {
    render(
      <EpochStrip
        market="SOL/USDC"
        epoch={18422n}
        phase="open"
        secondsToCutoff={83}
        progress={0.3}
        inFlight={{ epoch: '18421', phase: 'executing' }}
        lastResult="#18420 cleared 182.37 - settled"
      />,
    );
    const strip = screen.getByRole('region', { name: 'Epoch status' });
    expect(strip.textContent).toContain('SOL/USDC');
    expect(strip.textContent).toContain('#18422');
    const timer = screen.getByRole('timer', { name: 'Time to cutoff of epoch 18422' });
    expect(timer.textContent).toBe('01:23');
    expect(timer.getAttribute('aria-live')).toBe('off');
    expect(screen.getByText('Open')).toBeTruthy();
    expect(screen.getByText('In flight: #18421')).toBeTruthy();
    expect(screen.getByText('Executing')).toBeTruthy();
    expect(screen.getByText('#18420 cleared 182.37 - settled')).toBeTruthy();
    expect(strip.dataset.warning).toBeUndefined();
    await expectNoSeriousAxeViolations();
  });

  it('marks the warning state and the absence of an epoch in flight', async () => {
    render(
      <EpochStrip
        market="SOL/USDC"
        epoch="18422"
        phase="open"
        secondsToCutoff={6}
        progress={0.9}
        warning
        inFlight={null}
      />,
    );
    expect(screen.getByRole('region', { name: 'Epoch status' }).dataset.warning).toBe('true');
    expect(screen.getByText('Nothing in flight')).toBeTruthy();
    await expectNoSeriousAxeViolations();
  });
});
