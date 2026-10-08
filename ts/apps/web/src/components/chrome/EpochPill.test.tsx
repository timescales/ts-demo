import { render, screen } from '@testing-library/react';
import { describe, expect, it } from 'vitest';

import { expectNoSeriousAxeViolations } from '../testing/a11y';
import { EpochPill } from './EpochPill';

describe('EpochPill', () => {
  it.each([false, true])('shows market - #N - mm:ss - phase (warning %s)', async (warning) => {
    const { container } = render(
      <EpochPill
        market="SOL/USDC"
        epoch="18422"
        phase="closed"
        secondsToCutoff={9}
        progress={0.85}
        warning={warning}
      />,
    );
    const pill = container.firstElementChild as HTMLElement;
    expect(pill.textContent).toBe('SOL/USDC#1842200:09Closed');
    expect(screen.getByRole('timer').getAttribute('aria-live')).toBe('off');
    expect(pill.dataset.warning).toBe(warning ? 'true' : undefined);
    await expectNoSeriousAxeViolations();
  });
});
