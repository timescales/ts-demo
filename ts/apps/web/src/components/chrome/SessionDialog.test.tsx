import { fireEvent, render, screen } from '@testing-library/react';
import { describe, expect, it, vi } from 'vitest';

import { expectNoSeriousAxeViolations } from '../testing/a11y';
import { SessionDialog } from './SessionDialog';

const base = {
  open: true,
  onClose: () => undefined,
  scope: 'market' as const,
  onScopeChange: () => undefined,
  onStart: () => undefined,
  onRevoke: () => undefined,
};

describe('SessionDialog', () => {
  it('explains the one sign-in prompt and starts a session', async () => {
    const onStart = vi.fn();
    render(<SessionDialog {...base} state="none" marketLabel="SOL/USDC" onStart={onStart} />);
    expect(screen.getByRole('dialog', { name: 'Trading session' })).toBeTruthy();
    expect(screen.getByText(/Each order still needs its own signature/)).toBeTruthy();
    fireEvent.click(screen.getByRole('button', { name: 'Start session (1 wallet signature)' }));
    expect(onStart).toHaveBeenCalledOnce();
    expect(screen.getByRole('radio', { name: 'SOL/USDC only' }).getAttribute('aria-checked')).toBe(
      'true',
    );
    await expectNoSeriousAxeViolations();
  });

  it('shows the expiry and offers to end an active session', async () => {
    const onRevoke = vi.fn();
    render(<SessionDialog {...base} state="active" remainingSeconds={3900} onRevoke={onRevoke} />);
    expect(screen.getByText('Expires in 1h 05m.')).toBeTruthy();
    fireEvent.click(screen.getByRole('button', { name: 'End session' }));
    expect(onRevoke).toHaveBeenCalledOnce();
    expect(screen.queryByRole('radiogroup')).toBeNull();
    await expectNoSeriousAxeViolations();
  });

  it('asks to renew after eviction and shows the failure inline', async () => {
    render(<SessionDialog {...base} state="revoked" error="This sign-in was for another site." />);
    expect(screen.getByText(/You signed in elsewhere/)).toBeTruthy();
    expect(screen.getByText('This sign-in was for another site.')).toBeTruthy();
    expect(screen.getByRole('button', { name: 'Renew (1 wallet signature)' })).toBeTruthy();
    await expectNoSeriousAxeViolations();
  });

  it('waits for the wallet without a second click', async () => {
    const onStart = vi.fn();
    render(<SessionDialog {...base} state="none" busy onStart={onStart} />);
    const button = screen.getByRole('button', { name: 'Confirm in your wallet...' });
    expect(button.getAttribute('aria-busy')).toBe('true');
    await expectNoSeriousAxeViolations();
  });
});
