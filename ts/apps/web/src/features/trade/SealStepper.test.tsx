import type { OrderRecord, PreparedOrder } from '@timescales/sdk/orders';
import { act, fireEvent, render, screen, within } from '@testing-library/react';
import type { ComponentProps } from 'react';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { expectNoSeriousAxeViolations } from '../../components/testing/a11y';
import { ordersCopy } from '../orders/copy';
import { tradeCopy } from './copy';
import { errorMessage } from './errors';
import { SealStepper, WALLET_WAIT_MS } from './SealStepper';
import { startSeal } from './sealRun';
import { FakeOrders, fixtureParams, placeRecord } from './testing/fakes';
import { orderFingerprint } from './units';

const MARKET = 'Market1111111111111111111111111111111111111';
const params = fixtureParams();
const band = { lo: 14_968n, hi: 15_032n, reference: 15_000n };
const s = tradeCopy.seal;

afterEach(() => vi.useRealTimers());

function prepared(orders: FakeOrders): PreparedOrder {
  return orders.prepare({
    market: MARKET as never,
    side: 0,
    role: 0,
    kind: 0,
    limitTick: 15_000n,
    quantityLots: 1000n,
    lifetimeEpochs: 2,
  });
}

function setup(over: Partial<ComponentProps<typeof SealStepper>> = {}) {
  const orders = new FakeOrders(params, band);
  const run = startSeal(orders, prepared(orders), () => 0);
  const call = orders.submits[0]!;
  const props = {
    run,
    records: [] as OrderRecord[],
    now: () => 0,
    onClose: vi.fn(),
    onRetry: vi.fn(),
    onRetrySubmit: vi.fn<(record: OrderRecord) => Promise<void>>(() => Promise.resolve()),
    ...over,
  };
  const view = render(<SealStepper {...props} />);
  return { ...view, orders, run, call, props };
}

const live = () => document.querySelector('[data-state]') as HTMLElement;
/** The live step's text without the decorative seal glyph's numerals. */
const liveText = () => live().lastChild?.textContent;
const steps = () => screen.getByRole('list', { name: s.stepsLabel });

function waiting(market = MARKET): OrderRecord {
  return placeRecord({
    market: market as never,
    params,
    state: { kind: 'awaiting_wallet' },
    commitment: new Uint8Array(32).fill(9),
  });
}

describe('SealStepper', () => {
  it('asks for the wallet and shows the order fingerprint of the prompted order', async () => {
    const record = waiting();
    const { call, rerender, props } = setup();
    act(() => call.step('awaiting_wallet'));
    rerender(<SealStepper {...props} records={[record]} />);
    const code = orderFingerprint(record.commitment);
    expect(screen.getByText(s.fingerprint(code))).toBeTruthy();
    expect(within(steps()).getByText(s.confirm).closest('li')?.getAttribute('aria-current')).toBe(
      'step',
    );
    expect(live().textContent).toBe(s.confirm);
    await expectNoSeriousAxeViolations();
  });

  it('walks through encrypting, submitting and the verified relay receipt', async () => {
    const { call } = setup();
    act(() => call.step('sealing'));
    expect(live().textContent).toBe(s.encrypting('42'));
    act(() => call.step('submitting'));
    expect(live().textContent).toBe(s.submitting);
    act(() => call.step('verifying_promise'));
    expect(live().textContent).toBe(s.receipt);
    const done = placeRecord({
      market: MARKET as never,
      params,
      epochs: [
        [42n, { kind: 'sealed' }],
        [43n, { kind: 'parked' }],
      ],
    });
    await act(async () => call.result.resolve(done));
    expect(liveText()).toBe(s.sealed('42'));
    expect(within(live()).getByText('42').closest('svg')?.getAttribute('aria-hidden')).toBe('true');
    expect(screen.getByText(`${s.receipt} ✓`)).toBeTruthy();
    expect(screen.getByText(`${s.encrypting('42')} ✓ (${s.keyVerified})`)).toBeTruthy();
    await expectNoSeriousAxeViolations();
  });

  it('says "Queued" when only later epochs were reached', async () => {
    const { call } = setup();
    await act(async () =>
      call.result.resolve(
        placeRecord({
          market: MARKET as never,
          params,
          epochs: [
            [43n, { kind: 'parked' }],
            [44n, { kind: 'parked' }],
          ],
        }),
      ),
    );
    expect(liveText()).toBe(s.queued('43', '44'));
    await expectNoSeriousAxeViolations();
  });

  it('declined in the wallet: nothing was sent, Retry starts a new signature', async () => {
    const { call, props } = setup();
    await act(async () =>
      call.result.resolve(
        placeRecord({ market: MARKET as never, params, state: { kind: 'wallet_rejected' } }),
      ),
    );
    expect(live().textContent).toBe(s.rejected);
    fireEvent.click(screen.getByRole('button', { name: s.retry }));
    expect(props.onRetry).toHaveBeenCalledTimes(1);
    await expectNoSeriousAxeViolations();
  });

  it('closing while the wallet is open abandons the order', () => {
    const { call, props } = setup();
    act(() => call.step('awaiting_wallet'));
    fireEvent.click(screen.getByRole('button', { name: s.cancel }));
    expect(call.signal?.aborted).toBe(true);
    expect(props.onClose).toHaveBeenCalledTimes(1);
  });

  it('signed too late: "Sign again" asks before a second prompt', async () => {
    const { call, props } = setup();
    await act(async () =>
      call.result.resolve(
        placeRecord({ market: MARKET as never, params, state: { kind: 'signed_too_late' } }),
      ),
    );
    expect(live().textContent).toBe(s.tooLate);
    fireEvent.click(screen.getByRole('button', { name: s.signAgain }));
    expect(props.onRetry).not.toHaveBeenCalled();
    const dialog = screen.getByRole('dialog', { name: ordersCopy.secondPrompt.title });
    expect(dialog.textContent).toContain(s.secondPrompt(s.secondPromptWhyClosed));
    await expectNoSeriousAxeViolations();
    fireEvent.click(within(dialog).getByRole('button', { name: ordersCopy.secondPrompt.sign }));
    expect(props.onRetry).toHaveBeenCalledTimes(1);
  });

  it('a declined second prompt signs nothing', async () => {
    const { call, props } = setup();
    await act(async () =>
      call.result.resolve(
        placeRecord({ market: MARKET as never, params, state: { kind: 'signed_too_late' } }),
      ),
    );
    fireEvent.click(screen.getByRole('button', { name: s.signAgain }));
    const dialog = screen.getByRole('dialog', { name: ordersCopy.secondPrompt.title });
    fireEvent.click(within(dialog).getByRole('button', { name: ordersCopy.secondPrompt.cancel }));
    expect(props.onRetry).not.toHaveBeenCalled();
  });

  it('a failed submission is retried with the same bytes', async () => {
    const { call, props } = setup();
    const failed = placeRecord({
      market: MARKET as never,
      params,
      state: { kind: 'submit_failed', code: 'OVERLOADED', retryable: true },
    });
    await act(async () => call.result.resolve(failed));
    expect(live().textContent).toBe(s.failed('Busy, retrying in 1s.'));
    expect(within(steps()).getByText(s.submitting).closest('li')?.getAttribute('data-status')).toBe(
      'error',
    );
    await expectNoSeriousAxeViolations();
    fireEvent.click(screen.getByRole('button', { name: s.retry }));
    expect(props.onRetrySubmit).toHaveBeenCalledWith(failed);
    expect(props.onRetry).not.toHaveBeenCalled();
  });

  it('follows the stored record once the re-sent submission lands', async () => {
    let resolveResend = () => {};
    const onRetrySubmit = vi.fn(
      () =>
        new Promise<void>((resolve) => {
          resolveResend = resolve;
        }),
    );
    const { call, props, rerender } = setup({ onRetrySubmit });
    const failed = placeRecord({
      market: MARKET as never,
      params,
      state: { kind: 'submit_failed', code: 'OVERLOADED', retryable: true },
    });
    await act(async () => call.result.resolve(failed));
    fireEvent.click(screen.getByRole('button', { name: s.retry }));
    const retry = screen.getByRole('button', { name: s.retry }) as HTMLButtonElement;
    expect(retry.disabled).toBe(true);
    expect(retry.getAttribute('aria-busy')).toBe('true');
    await expectNoSeriousAxeViolations();
    const working = placeRecord({
      id: failed.id,
      market: MARKET as never,
      params,
      state: { kind: 'working' },
      epochs: [[42n, { kind: 'sealed' }]],
    });
    rerender(<SealStepper {...props} records={[working]} />);
    await act(async () => resolveResend());
    expect(liveText()).toBe(s.sealed('42'));
    expect(screen.queryByRole('button', { name: s.retry })).toBeNull();
    await expectNoSeriousAxeViolations();
  });

  it('says so when the re-sent submission fails again', async () => {
    const error = Object.assign(new Error('x'), { kind: 'api', code: 'MARKET_UNAVAILABLE' });
    const onRetrySubmit = vi.fn(() => Promise.reject(error));
    const { call } = setup({ onRetrySubmit });
    await act(async () =>
      call.result.resolve(
        placeRecord({
          market: MARKET as never,
          params,
          state: { kind: 'submit_failed', code: 'OVERLOADED', retryable: true },
        }),
      ),
    );
    await act(async () => {
      fireEvent.click(screen.getByRole('button', { name: s.retry }));
    });
    expect(live().textContent).toBe(s.resendFailed(errorMessage(error, 42n)));
    const retry = screen.getByRole('button', { name: s.retry }) as HTMLButtonElement;
    expect(retry.disabled).toBe(false);
    await expectNoSeriousAxeViolations();
  });

  it('a wallet that cannot sign orders gets no Retry', async () => {
    const { call } = setup();
    await act(async () =>
      call.result.resolve(
        placeRecord({ market: MARKET as never, params, state: { kind: 'unsupported_wallet' } }),
      ),
    );
    expect(live().textContent).toBe(s.unsupported);
    expect(screen.queryByRole('button', { name: s.retry })).toBeNull();
    await expectNoSeriousAxeViolations();
  });

  it('a thrown error shows its inline copy at the step that failed', async () => {
    const { call } = setup();
    act(() => call.step('sealing'));
    await act(async () =>
      call.result.reject(
        Object.assign(new Error('x'), { kind: 'api', code: 'EPOCH_KEY_UNAVAILABLE' }),
      ),
    );
    expect(live().textContent).toBe(
      'The encryption key for #42 could not be verified, so nothing was sealed.',
    );
    expect(
      within(steps()).getByText(s.encrypting('42')).closest('li')?.getAttribute('data-status'),
    ).toBe('error');
    await expectNoSeriousAxeViolations();
  });

  it('offers to stop waiting after 20 s without an answer', async () => {
    vi.useFakeTimers();
    const { call } = setup();
    act(() => call.step('awaiting_wallet'));
    expect(live().textContent).toBe(s.confirm);
    act(() => vi.advanceTimersByTime(WALLET_WAIT_MS));
    expect(live().textContent).toBe(s.stillWaiting);
    expect(screen.getByRole('button', { name: s.cancel })).toBeTruthy();
    vi.useRealTimers();
    await expectNoSeriousAxeViolations();
  });

  it('returns focus to the live step when the wallet pop-up gives focus back', () => {
    const { call } = setup();
    act(() => call.step('awaiting_wallet'));
    (document.body as HTMLElement).focus();
    act(() => {
      window.dispatchEvent(new FocusEvent('focus'));
    });
    expect(document.activeElement).toBe(live());
  });

  it('reports progress through the app’s polite region when it has one', async () => {
    const announce = vi.fn();
    const { call } = setup({ announce });
    expect(live().getAttribute('role')).toBeNull();
    act(() => call.step('sealing'));
    await act(async () =>
      call.result.resolve(
        placeRecord({ market: MARKET as never, params, epochs: [[42n, { kind: 'sealed' }]] }),
      ),
    );
    expect(announce.mock.calls.map((c) => c[0])).toEqual([
      s.confirm,
      s.encrypting('42'),
      s.sealed('42'),
    ]);
    await expectNoSeriousAxeViolations();
  });
});
