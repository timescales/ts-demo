import { fireEvent, render, screen } from '@testing-library/react';
import { describe, expect, it, vi } from 'vitest';

import { expectNoSeriousAxeViolations } from '../testing/a11y';
import { Banner } from './Banner';

describe('Banner', () => {
  it('keeps a critical banner expanded and not dismissible', async () => {
    render(
      <Banner
        severity="critical"
        title="Could not verify"
        collapsed
        onToggle={() => undefined}
        onDismiss={() => undefined}
      >
        Trading is paused.
      </Banner>,
    );
    expect(screen.getByRole('region', { name: 'Could not verify' })).toBeTruthy();
    expect(screen.getByText('Trading is paused.').closest('[hidden]')).toBeNull();
    expect(screen.queryByRole('button', { name: 'Dismiss' })).toBeNull();
    expect(screen.queryByRole('button', { name: 'Show details' })).toBeNull();
    await expectNoSeriousAxeViolations();
  });

  it.each(['warning', 'info', 'simulated'] as const)(
    'lets a %s banner collapse and be dismissed',
    async (severity) => {
      const onToggle = vi.fn();
      const onDismiss = vi.fn();
      render(
        <Banner
          severity={severity}
          title="Notice"
          collapsed
          onToggle={onToggle}
          onDismiss={onDismiss}
        >
          Details
        </Banner>,
      );
      expect(screen.getByText('Details').closest('[hidden]')).not.toBeNull();
      const toggle = screen.getByRole('button', { name: 'Show details' });
      expect(toggle.getAttribute('aria-expanded')).toBe('false');
      fireEvent.click(toggle);
      fireEvent.click(screen.getByRole('button', { name: 'Dismiss' }));
      expect(onToggle).toHaveBeenCalledOnce();
      expect(onDismiss).toHaveBeenCalledOnce();
      await expectNoSeriousAxeViolations();
    },
  );

  it('renders an expanded banner with actions', async () => {
    render(
      <Banner
        severity="warning"
        title="Notice"
        onToggle={() => undefined}
        actions={<a href="/funds">Funds</a>}
      >
        Details
      </Banner>,
    );
    expect(screen.getByRole('button', { name: 'Hide details' }).getAttribute('aria-expanded')).toBe(
      'true',
    );
    expect(screen.getByRole('link', { name: 'Funds' })).toBeTruthy();
    await expectNoSeriousAxeViolations();
  });
});
