import { fireEvent, render, screen } from '@testing-library/react';
import { describe, expect, it, vi } from 'vitest';

import { SAMPLE_ADDRESS } from '../gallery/fixtures';
import { expectNoSeriousAxeViolations } from '../testing/a11y';
import { WalletButton } from './WalletButton';

describe('WalletButton', () => {
  it('asks to connect', async () => {
    const onClick = vi.fn();
    render(<WalletButton state="disconnected" onClick={onClick} />);
    fireEvent.click(screen.getByRole('button', { name: 'Connect wallet' }));
    expect(onClick).toHaveBeenCalledOnce();
    await expectNoSeriousAxeViolations();
  });

  it('shows progress while connecting', async () => {
    render(<WalletButton state="connecting" onClick={() => undefined} />);
    expect(screen.getByRole('button', { name: 'Connecting...' }).getAttribute('aria-busy')).toBe(
      'true',
    );
    await expectNoSeriousAxeViolations();
  });

  it('shows the connected wallet and short address', async () => {
    render(
      <WalletButton
        state="connected"
        walletName="Wallet A"
        address={SAMPLE_ADDRESS}
        icon="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg'/%3E"
        onClick={() => undefined}
      />,
    );
    const button = screen.getByRole('button', { name: 'Wallet A: 7xKX...gAsU' });
    expect(button.textContent).toBe('7xKX...gAsU');
    expect(button.querySelector('img')?.getAttribute('alt')).toBe('');
    await expectNoSeriousAxeViolations();
  });
});
