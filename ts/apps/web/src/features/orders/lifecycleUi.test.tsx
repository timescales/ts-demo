import type { OrderState, ParticipationState } from '@timescales/sdk/orders';
import { ORDER_LIFECYCLE, PARTICIPATION_LIFECYCLE } from '@timescales/sdk/orders';
import { render, screen } from '@testing-library/react';
import { describe, expect, it } from 'vitest';

import { expectNoSeriousAxeViolations } from '../../components/testing/a11y';
import { DEFAULT_NUMBER_FORMAT } from '../trade/services';
import { fixtureParams, FIXTURE_UNITS, placeRecord } from '../trade/testing/fakes';
import { ordersCopy } from './copy';
import {
  ORDER_BADGES,
  PARTICIPATION_BADGES,
  participationBadge,
  resolveBadge,
} from './lifecycleUi';
import { OrderBadge } from './OrderBadge';

const MARKET = 'Market1111111111111111111111111111111111111' as never;
const params = fixtureParams();
const units = { params, ...FIXTURE_UNITS };
const b = ordersCopy.badge;

const SAMPLE_ORDER_STATES: Record<OrderState['kind'], OrderState> = {
  draft: { kind: 'draft' },
  awaiting_wallet: { kind: 'awaiting_wallet' },
  wallet_rejected: { kind: 'wallet_rejected' },
  unsupported_wallet: { kind: 'unsupported_wallet' },
  abandoned: { kind: 'abandoned' },
  signed_too_late: { kind: 'signed_too_late' },
  submitting: { kind: 'submitting' },
  submit_failed: { kind: 'submit_failed', code: 'BATCH_FULL', retryable: true },
  working: { kind: 'working' },
  paused_needs_app: { kind: 'paused_needs_app' },
  reseal_needs_consent: { kind: 'reseal_needs_consent', epoch: 41n },
  filled: { kind: 'filled' },
  expired: { kind: 'expired' },
  cancel_pending: { kind: 'cancel_pending', epoch: 43n },
  cancelled: { kind: 'cancelled' },
  cancel_too_late: { kind: 'cancel_too_late' },
  verification_failed: { kind: 'verification_failed', check: 'V-7 receipt' },
};

const SAMPLE_PARTICIPATIONS: Record<ParticipationState['kind'], ParticipationState> = {
  sealed: { kind: 'sealed' },
  parked: { kind: 'parked' },
  locked: { kind: 'locked' },
  included: { kind: 'included' },
  excluded: { kind: 'excluded', evidenceId: 'e1' },
  clearing: { kind: 'clearing', delayed: false },
  provisional: { kind: 'provisional', have: 1, need: 2 },
  verified: { kind: 'verified', filled: 40n },
  settling: { kind: 'settling', done: 1, total: 3 },
  settled: { kind: 'settled', filled: 40n },
  voided: { kind: 'voided', outcomeWasPublic: false },
  not_submitted: { kind: 'not_submitted', reason: 'quota' },
};

const orderKinds = new Set(ORDER_LIFECYCLE.flatMap((r) => [r.from, r.to]));
const participationKinds = new Set(PARTICIPATION_LIFECYCLE.flatMap((r) => [r.from, r.to]));

describe('mapping, driven by the SDK lifecycle tables', () => {
  it('has a badge for every state the tables can produce', () => {
    for (const k of orderKinds) expect(ORDER_BADGES[k], k).toBeTruthy();
    for (const k of participationKinds) expect(PARTICIPATION_BADGES[k], k).toBeTruthy();
  });

  for (const kind of orderKinds) {
    it(`order state ${kind} renders a glyph and words`, async () => {
      const record = placeRecord({ market: MARKET, params, state: SAMPLE_ORDER_STATES[kind] });
      render(<OrderBadge badge={resolveBadge(record, units, DEFAULT_NUMBER_FORMAT)} />);
      const icon = document.querySelector('svg')!;
      expect(icon).toBeTruthy();
      expect(icon.parentElement!.textContent!.trim().length).toBeGreaterThan(2);
      await expectNoSeriousAxeViolations();
    });
  }

  for (const kind of participationKinds) {
    it(`participation ${kind} renders a glyph and words`, async () => {
      const record = placeRecord({
        market: MARKET,
        params,
        quantity: 100n,
        epochs: [[42n, SAMPLE_PARTICIPATIONS[kind]]],
        history: [{ atMs: 1, kind: 'fills', epoch: 42n, filled: 40n }],
        fills: [
          {
            commitment: new Uint8Array(32),
            book: 2,
            side: 0,
            role: 0,
            quantity: 40n,
            tick: 14_990n,
            feeQuote: 6n,
          },
        ],
      });
      const p = record.epochs.get(42n)!;
      render(<OrderBadge badge={participationBadge(record, p, units, DEFAULT_NUMBER_FORMAT)} />);
      expect(document.querySelector('svg')).toBeTruthy();
      await expectNoSeriousAxeViolations();
    });
  }
});

describe('badge texts', () => {
  const lane = (
    state: ParticipationState,
    extra: Partial<Parameters<typeof placeRecord>[0]> = {},
  ) => {
    const record = placeRecord({ market: MARKET, params, epochs: [[42n, state]], ...extra });
    return participationBadge(record, record.epochs.get(42n)!, units, DEFAULT_NUMBER_FORMAT);
  };

  it('shows "Filled - settling" with the price and improvement only once verified', () => {
    const r = lane(
      { kind: 'verified', filled: 40n },
      {
        limit: 15_000n,
        quantity: 100n,
        history: [{ atMs: 1, kind: 'fills', epoch: 42n, filled: 40n }],
        fills: [
          {
            commitment: new Uint8Array(32),
            book: 2,
            side: 0,
            role: 0,
            quantity: 40n,
            tick: 14_990n,
            feeQuote: 6n,
          },
        ],
      },
    );
    expect(r.text).toBe(`${b.verifiedFilled('40', '149.9')} (${b.betterThanLimit('0.06')})`);
  });

  it('never shows a price improvement for a market order', () => {
    const r = lane(
      { kind: 'verified', filled: 40n },
      {
        kind: 1,
        quantity: 100n,
        history: [{ atMs: 1, kind: 'fills', epoch: 42n, filled: 40n }],
        fills: [
          {
            commitment: new Uint8Array(32),
            book: 2,
            side: 0,
            role: 0,
            quantity: 40n,
            tick: 14_990n,
            feeQuote: 6n,
          },
        ],
      },
    );
    expect(r.text).toBe(b.verifiedFilled('40', '149.9'));
  });

  it('shows no fill amount while provisional', () => {
    expect(lane({ kind: 'provisional', have: 1, need: 2 }).text).toBe(b.provisional(1, 2));
  });

  it('opens the slats only at settled', () => {
    expect(lane({ kind: 'settled', filled: 40n }).spec.slats).toBe('open');
    expect(lane({ kind: 'settled', filled: 40n }).text).toBe(b.settledFilled);
    expect(lane({ kind: 'verified', filled: 40n }).spec.slats).toBeUndefined();
    expect(lane({ kind: 'settled', filled: 0n }).text).toBe(b.settled);
  });

  it('explains "Not filled" with a Why? tooltip', async () => {
    const r = lane({ kind: 'verified', filled: 0n });
    expect(r.text).toBe(b.verifiedNone('42'));
    render(<OrderBadge badge={r} />);
    expect(screen.getByRole('button', { name: ordersCopy.whyNotFilled })).toBeTruthy();
    await expectNoSeriousAxeViolations();
  });

  it('says whether the order continues after a voided epoch', () => {
    const continues = placeRecord({
      market: MARKET,
      params,
      epochs: [
        [42n, { kind: 'voided', outcomeWasPublic: false }],
        [43n, { kind: 'sealed' }],
      ],
    });
    expect(
      participationBadge(continues, continues.epochs.get(42n)!, units, DEFAULT_NUMBER_FORMAT).text,
    ).toBe(b.voidedContinues('42', '43'));
    expect(
      lane({ kind: 'voided', outcomeWasPublic: false }, { state: { kind: 'expired' } }).text,
    ).toBe(b.voidedEnded('42'));
  });

  it('marks delayed clearing', () => {
    expect(lane({ kind: 'clearing', delayed: true }).text).toBe(b.clearingDelayed);
  });
});

describe('badge precedence', () => {
  it('verification failure, then exclusion, then the order state, then the earliest in flight', () => {
    const many = (state: OrderState, epochs: [bigint, ParticipationState][]) =>
      resolveBadge(
        placeRecord({ market: MARKET, params, state, epochs }),
        units,
        DEFAULT_NUMBER_FORMAT,
      );
    expect(
      many({ kind: 'verification_failed', check: 'V-6' }, [
        [42n, { kind: 'excluded', evidenceId: 'e' }],
      ]).kind,
    ).toBe('verification_failed');
    expect(
      many({ kind: 'cancel_pending', epoch: 43n }, [[42n, { kind: 'excluded', evidenceId: 'e' }]])
        .kind,
    ).toBe('excluded');
    expect(many({ kind: 'cancel_pending', epoch: 43n }, [[42n, { kind: 'sealed' }]]).text).toBe(
      b.cancel_pending('43'),
    );
    const working = many({ kind: 'working' }, [
      [42n, { kind: 'settling', done: 1, total: 2 }],
      [43n, { kind: 'sealed' }],
      [44n, { kind: 'parked' }],
    ]);
    expect(working.kind).toBe('settling');
    expect(
      many({ kind: 'working' }, [
        [43n, { kind: 'sealed' }],
        [44n, { kind: 'parked' }],
      ]).text,
    ).toBe(b.sealed('43'));
  });
});
