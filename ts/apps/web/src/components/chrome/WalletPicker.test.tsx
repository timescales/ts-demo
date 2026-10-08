import { fireEvent, render, screen, within } from '@testing-library/react';
import { describe, expect, it, vi } from 'vitest';

import { WALLETS } from '../gallery/fixtures';
import { expectNoSeriousAxeViolations } from '../testing/a11y';
import { WalletPicker } from './WalletPicker';

describe('WalletPicker', () => {
  it('badges every wallet: untested unless signed off, unsupported ones disabled', async () => {
    const onSelect = vi.fn();
    render(<WalletPicker open onClose={() => undefined} wallets={WALLETS} onSelect={onSelect} />);
    const dialog = screen.getByRole('dialog', { name: 'Connect a wallet' });
    const options = within(dialog)
      .getAllByRole('listitem')
      .map((li) => li.querySelector('button') as HTMLButtonElement);
    expect(options.map((b) => b.textContent)).toEqual([
      'Wallet AUntested with Timescales',
      'Wallet BTested with Timescales',
      "Wallet CThis wallet can't sign Timescales orders",
    ]);
    expect(options.map((b) => b.disabled)).toEqual([false, false, true]);
    expect(
      within(options[0] as HTMLElement)
        .getByText('Untested with Timescales')
        .closest('[data-kind="untested"]'),
    ).not.toBeNull();
    fireEvent.click(options[0] as HTMLElement);
    expect(onSelect).toHaveBeenCalledWith('a');
    await expectNoSeriousAxeViolations();
  });

  it('says when no wallet is installed', async () => {
    render(<WalletPicker open onClose={() => undefined} wallets={[]} onSelect={() => undefined} />);
    expect(screen.getByText('No wallets found in this browser.')).toBeTruthy();
    await expectNoSeriousAxeViolations();
  });
});
