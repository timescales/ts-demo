import { fireEvent, render, screen } from '@testing-library/react';
import { describe, expect, it, vi } from 'vitest';

import { expectNoSeriousAxeViolations } from '../testing/a11y';
import { VerificationBanner } from './VerificationBanner';

describe('VerificationBanner', () => {
  it('is critical, names the failed check and offers Re-check and Export', async () => {
    const onRecheck = vi.fn();
    const onExport = vi.fn();
    render(
      <VerificationBanner
        thing="the receipt for epoch #18421"
        onRecheck={onRecheck}
        onExport={onExport}
      />,
    );
    const banner = screen.getByRole('region', {
      name: 'Could not verify the receipt for epoch #18421.',
    });
    expect(banner.dataset.severity).toBe('critical');
    expect(banner.textContent).toContain(
      "Don't rely on this result. Trading in this market is paused on this device.",
    );
    expect(screen.queryByRole('button', { name: 'Dismiss' })).toBeNull();
    fireEvent.click(screen.getByRole('button', { name: 'Re-check' }));
    fireEvent.click(screen.getByRole('button', { name: 'Export details' }));
    expect(onRecheck).toHaveBeenCalledOnce();
    expect(onExport).toHaveBeenCalledOnce();
    await expectNoSeriousAxeViolations();
  });
});
