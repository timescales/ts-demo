import { render, screen } from '@testing-library/react';
import { describe, expect, it } from 'vitest';

import { expectNoSeriousAxeViolations } from '../testing/a11y';
import { EpochRing, RING_TICKS, elapsedTicks, epochRingLabel } from './EpochRing';

describe('EpochRing', () => {
  it('rounds progress down to whole ticks and clamps', () => {
    expect(elapsedTicks(0)).toBe(0);
    expect(elapsedTicks(0.499)).toBe(29);
    expect(elapsedTicks(1)).toBe(RING_TICKS);
    expect(elapsedTicks(1.5)).toBe(RING_TICKS);
    expect(elapsedTicks(-1)).toBe(0);
    expect(elapsedTicks(Number.NaN)).toBe(0);
    expect(epochRingLabel(0.25)).toBe('15 of 60 ticks elapsed');
  });

  it('draws 60 ticks with the elapsed ones marked, decorative by default', async () => {
    const { container } = render(<EpochRing progress={0.25} />);
    const svg = container.querySelector('svg');
    expect(svg?.getAttribute('aria-hidden')).toBe('true');
    const lines = [...(svg?.querySelectorAll('line') ?? [])];
    expect(lines).toHaveLength(60);
    const elapsedClass = lines[0]?.getAttribute('class');
    expect(lines.filter((l) => l.getAttribute('class') === elapsedClass)).toHaveLength(15);
    await expectNoSeriousAxeViolations();
  });

  it('takes the warning state and an optional label', async () => {
    const { container } = render(
      <EpochRing progress={0.9} warning label="54 of 60 ticks elapsed" />,
    );
    expect((container.firstElementChild as HTMLElement).dataset.warning).toBe('true');
    expect(screen.getByRole('img', { name: '54 of 60 ticks elapsed' })).toBeTruthy();
    await expectNoSeriousAxeViolations();
  });
});
