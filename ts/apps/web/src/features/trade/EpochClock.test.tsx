import type { CurrentEpoch } from '@timescales/sdk/api';
import { render, screen } from '@testing-library/react';
import { describe, expect, it, vi } from 'vitest';

import { expectNoSeriousAxeViolations } from '../../components/testing/a11y';
import { tradeCopy } from './copy';
import { EpochClock } from './EpochClock';

function current(epoch: bigint, opensAtMs: number, cutoffMs: number): CurrentEpoch {
  return {
    market: 'M',
    serverTimeMs: opensAtMs,
    intake: 'open',
    open: { epoch, opensAtMs, cutoffMs },
    parkWindow: [],
    previous: null,
    inflight: { epoch: epoch - 2n, phase: 'posted' },
    contextSlot: 1n,
  } as unknown as CurrentEpoch;
}

describe('EpochClock', () => {
  it('shows mm:ss to cutoff as a silent timer and the epoch in flight', async () => {
    render(
      <EpochClock
        current={current(42n, 0, 60_000)}
        intervalMs={60_000}
        now={15_000}
        draftActive={false}
      />,
    );
    const timer = screen.getByRole('timer', { name: 'Time to cutoff of epoch 42' });
    expect(timer.textContent).toBe('00:45');
    expect(timer.getAttribute('aria-live')).toBe('off');
    expect(screen.getByText('In flight: #40')).toBeTruthy();
    expect(screen.queryByText(tradeCopy.clock.nearCutoff)).toBeNull();
    await expectNoSeriousAxeViolations();
  });

  it('warns at min(10 s, interval / 3) and announces once while a draft is active', async () => {
    const announce = vi.fn();
    const props = { current: current(42n, 0, 60_000), intervalMs: 60_000, announce };
    const { rerender } = render(<EpochClock {...props} now={49_000} draftActive />);
    expect(screen.queryByText(tradeCopy.clock.nearCutoff)).toBeNull();
    rerender(<EpochClock {...props} now={50_000} draftActive />);
    expect(screen.getByText(tradeCopy.clock.nearCutoff)).toBeTruthy();
    expect(announce).toHaveBeenCalledExactlyOnceWith('Epoch 42 closes in 10 seconds.');
    rerender(<EpochClock {...props} now={51_000} draftActive />);
    expect(announce).toHaveBeenCalledTimes(1);
    await expectNoSeriousAxeViolations();
  });

  it('uses interval / 3 for short intervals', async () => {
    const props = { current: current(7n, 0, 21_000), intervalMs: 21_000, draftActive: false };
    const { rerender } = render(<EpochClock {...props} now={13_900} />);
    expect(screen.queryByText(tradeCopy.clock.nearCutoff)).toBeNull();
    rerender(<EpochClock {...props} now={14_000} />);
    expect(screen.getByText(tradeCopy.clock.nearCutoff)).toBeTruthy();
    await expectNoSeriousAxeViolations();
  });

  it('suppresses the warning under a 20 s interval', async () => {
    render(
      <EpochClock current={current(7n, 0, 10_000)} intervalMs={10_000} now={9_500} draftActive />,
    );
    expect(screen.queryByText(tradeCopy.clock.nearCutoff)).toBeNull();
    await expectNoSeriousAxeViolations();
  });

  it('does not announce without a focused or edited draft', async () => {
    const announce = vi.fn();
    render(
      <EpochClock
        current={current(42n, 0, 60_000)}
        intervalMs={60_000}
        now={55_000}
        draftActive={false}
        announce={announce}
      />,
    );
    expect(screen.getByText(tradeCopy.clock.nearCutoff)).toBeTruthy();
    expect(announce).not.toHaveBeenCalled();
    await expectNoSeriousAxeViolations();
  });

  it('keeps announcements within the budget at a 10 s interval with no draft', () => {
    vi.useFakeTimers();
    const announce = vi.fn();
    const { rerender } = render(
      <EpochClock
        current={current(1n, 0, 10_000)}
        intervalMs={10_000}
        now={0}
        draftActive={false}
        announce={announce}
      />,
    );
    for (let t = 0; t < 60_000; t += 1_000) {
      const epoch = BigInt(1 + Math.floor(t / 10_000));
      const start = Number(epoch - 1n) * 10_000;
      rerender(
        <EpochClock
          current={current(epoch, start, start + 10_000)}
          intervalMs={10_000}
          now={t}
          draftActive={false}
          announce={announce}
        />,
      );
    }
    expect(announce.mock.calls.length).toBeLessThanOrEqual(6);
    vi.useRealTimers();
  });

  it('says when no epoch is open', async () => {
    render(
      <EpochClock
        current={{ ...current(1n, 0, 1), open: null } as CurrentEpoch}
        intervalMs={10_000}
        now={0}
        draftActive={false}
      />,
    );
    expect(screen.getByText(tradeCopy.clock.noOpen)).toBeTruthy();
    await expectNoSeriousAxeViolations();
  });
});
