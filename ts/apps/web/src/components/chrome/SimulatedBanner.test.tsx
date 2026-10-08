import { fireEvent, render, screen } from '@testing-library/react';
import { describe, expect, it, vi } from 'vitest';

import { expectNoSeriousAxeViolations } from '../testing/a11y';
import { SimulatedBanner } from './SimulatedBanner';

const BODY =
  'Simulated enclave: the operator of this deployment can read sealed orders. Use test tokens only.';

describe('SimulatedBanner', () => {
  it('states that the operator can read sealed orders and links to Privacy', async () => {
    render(<SimulatedBanner privacyHref="/privacy" collapsed={false} onToggle={() => undefined} />);
    const banner = screen.getByRole('region', { name: 'Simulated enclave' });
    expect(banner.dataset.severity).toBe('simulated');
    expect(screen.getByText(BODY).closest('[hidden]')).toBeNull();
    expect(screen.getByRole('link', { name: 'Read who sees what' }).getAttribute('href')).toBe(
      '/privacy',
    );
    await expectNoSeriousAxeViolations();
  });

  it('collapses behind a toggle', async () => {
    const onToggle = vi.fn();
    render(<SimulatedBanner privacyHref="/privacy" collapsed onToggle={onToggle} />);
    expect(screen.getByText(BODY).closest('[hidden]')).not.toBeNull();
    fireEvent.click(screen.getByRole('button', { name: 'Show details' }));
    expect(onToggle).toHaveBeenCalledOnce();
    await expectNoSeriousAxeViolations();
  });
});
