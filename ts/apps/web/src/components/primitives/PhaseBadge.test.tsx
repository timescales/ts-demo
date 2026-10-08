import { render, screen } from '@testing-library/react';
import { describe, expect, it } from 'vitest';

import { componentsCopy } from '../copy';
import { expectNoSeriousAxeViolations } from '../testing/a11y';
import type { PublicPhase } from '../types';
import { PhaseBadge } from './PhaseBadge';

const PHASES = Object.keys(componentsCopy.phase) as PublicPhase[];

describe('PhaseBadge', () => {
  it('covers every public phase and a phase a newer node adds', () => {
    expect(PHASES).toHaveLength(11);
    expect(PHASES).toContain('unknown');
  });

  it.each(PHASES)('renders %s as glyph and word', async (phase) => {
    render(<PhaseBadge phase={phase} />);
    const word = screen.getByText(componentsCopy.phase[phase]);
    expect(word.parentElement?.querySelector('svg[aria-hidden="true"]')).not.toBeNull();
    await expectNoSeriousAxeViolations();
  });
});
