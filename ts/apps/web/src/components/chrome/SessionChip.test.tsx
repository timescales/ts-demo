import { fireEvent, render, screen } from '@testing-library/react';
import { describe, expect, it, vi } from 'vitest';

import { expectNoSeriousAxeViolations } from '../testing/a11y';
import { SessionChip } from './SessionChip';

describe('SessionChip', () => {
  it('offers to start a session', async () => {
    const onAction = vi.fn();
    render(<SessionChip state="none" onAction={onAction} />);
    fireEvent.click(screen.getByRole('button', { name: 'Start session' }));
    expect(onAction).toHaveBeenCalledOnce();
    await expectNoSeriousAxeViolations();
  });

  it.each([
    [4520, '1h 15m', 'ok'],
    [120, '02:00', 'warning'],
  ])('counts down an active session (%i s)', async (seconds, remaining, tone) => {
    render(<SessionChip state="active" remainingSeconds={seconds} onAction={() => undefined} />);
    const chip = screen.getByRole('button', { name: `Session expires in ${remaining}. Renew` });
    expect(chip.textContent).toBe(`Session ${remaining}`);
    expect(chip.className).toContain(tone);
    await expectNoSeriousAxeViolations();
  });

  it.each([
    ['expired', 'Session expired. Renew (1 wallet signature).'],
    ['revoked', 'You signed in elsewhere, so this session ended. Renew (1 wallet signature).'],
  ] as const)('asks to renew when %s', async (state, text) => {
    render(<SessionChip state={state} onAction={() => undefined} />);
    expect(screen.getByRole('button', { name: text })).toBeTruthy();
    await expectNoSeriousAxeViolations();
  });
});
