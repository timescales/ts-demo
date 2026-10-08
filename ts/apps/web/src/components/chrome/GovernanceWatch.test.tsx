import { render, screen } from '@testing-library/react';
import { describe, expect, it } from 'vitest';

import { componentsCopy } from '../copy';
import { expectNoSeriousAxeViolations } from '../testing/a11y';
import type { GovernanceKind } from './GovernanceWatch';
import { GovernanceWatch } from './GovernanceWatch';

const KINDS = Object.keys(componentsCopy.governance.kinds) as GovernanceKind[];

function banner() {
  return screen.getByRole('region', { name: componentsCopy.governance.title });
}

describe('GovernanceWatch', () => {
  it('renders nothing when nothing is pending', () => {
    const { container } = render(
      <GovernanceWatch changes={[]} reviewHref="/status" fundsHref="/funds" />,
    );
    expect(container.innerHTML).toBe('');
  });

  it.each(KINDS)('announces a pending %s change with its eta', async (kind) => {
    render(
      <GovernanceWatch changes={[{ kind, eta: '23 h' }]} reviewHref="/status" fundsHref="/funds" />,
    );
    expect(banner().dataset.severity).toBe('warning');
    expect(banner().textContent).toContain(
      `In 23 h, this market's ${componentsCopy.governance.kinds[kind]} changes. You can withdraw before then.`,
    );
    expect(screen.getByRole('link', { name: 'Review' }).getAttribute('href')).toBe('/status');
    expect(screen.getByRole('link', { name: 'Funds' }).getAttribute('href')).toBe('/funds');
    await expectNoSeriousAxeViolations();
  });

  it('flags a timelock decrease, a missing timelock and a recent upgrade', async () => {
    render(
      <GovernanceWatch
        changes={[{ kind: 'timelock', eta: '2 days', decrease: true }]}
        noEffectiveTimelock
        recentUpgradeAgo="3 h"
        reviewHref="/status"
        fundsHref="/funds"
      />,
    );
    const text = banner().textContent ?? '';
    expect(text).toContain(componentsCopy.governance.decrease);
    expect(text).toContain(componentsCopy.governance.noTimelock);
    expect(text).toContain('The settlement program was upgraded 3 h ago.');
    expect(banner().dataset.severity).toBe('warning');
    await expectNoSeriousAxeViolations();
  });

  it('is critical when the upgrade authority is unexpected', async () => {
    render(
      <GovernanceWatch changes={[]} unexpectedAuthority reviewHref="/status" fundsHref="/funds" />,
    );
    expect(banner().dataset.severity).toBe('critical');
    expect(banner().textContent).toContain(componentsCopy.governance.unexpectedAuthority);
    await expectNoSeriousAxeViolations();
  });
});
