import { render, screen } from '@testing-library/react';
import { CircleCheck } from 'lucide-react';
import { describe, expect, it } from 'vitest';

import { expectNoSeriousAxeViolations } from '../testing/a11y';
import type { Tone } from '../types';
import { Badge } from './Badge';

const TONES: Tone[] = [
  'neutral',
  'accent',
  'buy',
  'sell',
  'info',
  'warning',
  'danger',
  'simulated',
];

describe('Badge', () => {
  it.each(TONES)('renders the %s tone with glyph and text', async (tone) => {
    render(
      <Badge tone={tone} icon={<CircleCheck aria-hidden="true" />}>
        Settled
      </Badge>,
    );
    const badge = screen.getByText('Settled').parentElement;
    expect(badge?.querySelector('svg')).not.toBeNull();
    await expectNoSeriousAxeViolations();
  });
});
