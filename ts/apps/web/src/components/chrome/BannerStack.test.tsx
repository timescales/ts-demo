import { fireEvent, render, screen } from '@testing-library/react';
import { describe, expect, it, vi } from 'vitest';

import { BANNERS, stackBanners } from '../gallery/fixtures';
import { expectNoSeriousAxeViolations } from '../testing/a11y';
import type { StackBanner } from './BannerStack';
import { BannerStack, orderBanners } from './BannerStack';

function titles(): string[] {
  return screen
    .getAllByRole('region')
    .filter((r) => r.dataset.severity)
    .map((r) => r.dataset.severity ?? '');
}

describe('BannerStack', () => {
  it('renders nothing without banners', () => {
    const { container } = render(<BannerStack banners={[]} />);
    expect(container.innerHTML).toBe('');
  });

  it('puts critical banners first and keeps the rest in order', () => {
    expect(orderBanners(BANNERS).map((b) => b.id)).toEqual([
      'verify',
      'gov',
      'sim',
      'stream',
      'rpc',
    ]);
  });

  it('shows every critical banner and at most two others, the rest behind "+N"', async () => {
    const onDismiss = vi.fn();
    render(<BannerStack banners={BANNERS} onDismiss={onDismiss} />);
    expect(titles()).toEqual(['critical', 'warning', 'simulated']);
    const more = screen.getByRole('button', { name: '+2 more notices' });
    expect(more.getAttribute('aria-expanded')).toBe('false');
    await expectNoSeriousAxeViolations();

    fireEvent.click(more);
    expect(titles()).toEqual(['critical', 'warning', 'simulated', 'info', 'warning']);
    // Only banners marked dismissible get a Dismiss button.
    const dismiss = screen.getAllByRole('button', { name: 'Dismiss' });
    expect(dismiss).toHaveLength(2);
    fireEvent.click(dismiss[0] as HTMLElement);
    expect(onDismiss).toHaveBeenCalledWith('stream');
    await expectNoSeriousAxeViolations();

    fireEvent.click(screen.getByRole('button', { name: 'Show fewer notices' }));
    expect(titles()).toHaveLength(3);
  });

  it('places the banner components as they are, ordered and collapsed by severity', async () => {
    const onToggle = vi.fn();
    render(<BannerStack banners={stackBanners({ collapsed: true, onToggle })} maxExpanded={1} />);
    // VerificationBanner moves to the top. GovernanceWatch is the one other
    // banner shown. SimulatedBanner and the rest wait behind "+3".
    expect(titles()).toEqual(['critical', 'warning']);
    expect(screen.getByRole('button', { name: 'Re-check' })).toBeTruthy();
    fireEvent.click(screen.getByRole('button', { name: '+3 more notices' }));
    expect(titles()).toEqual(['critical', 'warning', 'simulated', 'info', 'warning']);
    // SimulatedBanner keeps its own toggle inside the stack.
    const toggle = screen.getByRole('button', { name: 'Show details' });
    expect(toggle.getAttribute('aria-expanded')).toBe('false');
    fireEvent.click(toggle);
    expect(onToggle).toHaveBeenCalledOnce();
    await expectNoSeriousAxeViolations();
  });

  it('passes collapsed and onToggle through for banners described as data', async () => {
    const onToggle = vi.fn();
    render(
      <BannerStack
        banners={[
          {
            id: 'sim',
            severity: 'simulated',
            title: 'Simulated enclave',
            body: 'The operator of this deployment can read sealed orders.',
            collapsed: true,
            onToggle,
          },
        ]}
      />,
    );
    expect(
      screen.getByText('The operator of this deployment can read sealed orders.'),
    ).toBeTruthy();
    expect(
      screen
        .getByText('The operator of this deployment can read sealed orders.')
        .closest('[hidden]'),
    ).not.toBeNull();
    fireEvent.click(screen.getByRole('button', { name: 'Show details' }));
    expect(onToggle).toHaveBeenCalledOnce();
    await expectNoSeriousAxeViolations();
  });

  it('never collapses or dismisses critical banners, however many there are', async () => {
    const critical: StackBanner[] = [1, 2, 3, 4].map((n) => ({
      id: `c${n}`,
      severity: 'critical',
      title: `Critical ${n}`,
      dismissible: true,
    }));
    render(<BannerStack banners={critical} maxExpanded={1} onDismiss={() => undefined} />);
    expect(titles()).toEqual(['critical', 'critical', 'critical', 'critical']);
    expect(screen.queryByRole('button')).toBeNull();
    await expectNoSeriousAxeViolations();
  });
});
