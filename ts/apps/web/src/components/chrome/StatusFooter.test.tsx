import { act, render, screen } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { componentsCopy } from '../copy';
import { expectNoSeriousAxeViolations } from '../testing/a11y';
import type { EnclaveTrust, StatusFooterProps } from './StatusFooter';
import { StatusFooter } from './StatusFooter';

const BASE: Omit<StatusFooterProps, 'enclave'> = {
  cluster: 'localnet',
  slot: 1234567n,
  rpc: 'ok',
  apiVersion: 'v1.0',
  api: 'ok',
  stream: 'live',
  reference: 'operator',
  links: { status: '/status', privacy: '/privacy', help: '/help' },
};

const VARIANTS: [EnclaveTrust, string][] = [
  ['simulated', componentsCopy.footer.enclaveSimulated],
  [
    'tdx_vouched',
    `${componentsCopy.footer.enclaveTdxVouched}*${componentsCopy.footer.quoteUntested}`,
  ],
  ['tdx_reported', componentsCopy.footer.enclaveTdxReported],
];

describe('StatusFooter', () => {
  afterEach(() => {
    vi.restoreAllMocks();
    vi.unstubAllGlobals();
  });

  it.each(VARIANTS)('puts the %s enclave label first', async (enclave, label) => {
    const { container } = render(<StatusFooter enclave={enclave} {...BASE} />);
    const footer = screen.getByRole('contentinfo', { name: 'System status' });
    expect(footer.firstElementChild?.textContent).toBe(label);
    // The label is outside the wrapping list, so it never moves.
    expect(footer.firstElementChild?.tagName).toBe('DIV');
    expect(container.querySelector('ul')?.textContent).not.toContain('Enclave');
    await expectNoSeriousAxeViolations();
  });

  it('labels the simulated enclave with the plum label', () => {
    render(<StatusFooter enclave="simulated" {...BASE} />);
    expect(
      screen.getByText('Enclave: SIMULATED').closest('[data-kind="simulated"]'),
    ).not.toBeNull();
  });

  it('marks TDX quote generation with the plum Untested label (K)', async () => {
    render(<StatusFooter enclave="tdx_vouched" {...BASE} />);
    const footer = screen.getByRole('contentinfo', { name: 'System status' });
    const label = footer.firstElementChild as HTMLElement;
    expect(label.firstElementChild?.textContent).toBe(componentsCopy.footer.enclaveTdxVouched);
    expect(
      screen.getByText(componentsCopy.footer.quoteUntested).closest('[data-kind="untested"]'),
    ).not.toBeNull();
    expect(
      screen.queryByText(componentsCopy.footer.enclaveTdxVouched)?.closest('[data-kind]'),
    ).toBe(null);
    await expectNoSeriousAxeViolations();
  });

  it('publishes its measured height as --footer-h and removes it on unmount', () => {
    let height = 108.4;
    let notify = () => undefined as void;
    vi.spyOn(HTMLElement.prototype, 'getBoundingClientRect').mockImplementation(
      () => ({ height }) as DOMRect,
    );
    vi.stubGlobal(
      'ResizeObserver',
      class {
        constructor(callback: () => void) {
          notify = callback;
        }
        observe() {}
        disconnect() {}
      },
    );
    const root = document.documentElement;
    const { unmount } = render(<StatusFooter enclave="simulated" {...BASE} />);
    expect(root.style.getPropertyValue('--footer-h')).toBe('109px');
    height = 53;
    act(() => notify());
    expect(root.style.getPropertyValue('--footer-h')).toBe('53px');
    unmount();
    expect(root.style.getPropertyValue('--footer-h')).toBe('');

    // A footer shown in place leaves the property alone.
    render(<StatusFooter enclave="simulated" {...BASE} publishHeight={false} />);
    expect(root.style.getPropertyValue('--footer-h')).toBe('');
  });

  it('keeps the items in the same order and states health in words', async () => {
    render(
      <StatusFooter
        enclave="simulated"
        {...BASE}
        rpc="down"
        api="degraded"
        stream="reconnecting"
        reference="modelled"
      />,
    );
    const items = screen.getAllByRole('listitem').map((li) => li.textContent);
    expect(items).toEqual([
      'localnet - Slot 1234567 - ●RPC down',
      '●API v1.0 degraded',
      '●Stream reconnecting',
      'Keys: trusted dealer',
      'Reference: modelled',
      'StatusPrivacyHelp',
    ]);
    expect(
      screen.getByText('Reference: modelled').closest('[data-kind="modelled"]'),
    ).not.toBeNull();
    await expectNoSeriousAxeViolations();
  });

  it('omits the slot until it is known', () => {
    render(<StatusFooter enclave="tdx_reported" {...BASE} slot={null} />);
    expect(screen.getAllByRole('listitem')[0]?.textContent).toBe('localnet - ●RPC ok');
  });
});
