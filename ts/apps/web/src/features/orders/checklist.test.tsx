import type { ParticipationState } from '@timescales/sdk/orders';
import { render, screen } from '@testing-library/react';
import { MemoryRouter } from 'react-router';
import { describe, expect, it } from 'vitest';

import { expectNoSeriousAxeViolations } from '../../components/testing/a11y';
import { fixtureParams, placeRecord } from '../trade/testing/fakes';
import { checkOfFailure, checklist } from './checklist';
import { ordersCopy } from './copy';
import { VerificationChecklist } from './VerificationChecklist';

const MARKET = 'Market1111111111111111111111111111111111111' as never;
const params = fixtureParams();

function rows(
  state: ParticipationState,
  over: Parameters<typeof placeRecord>[0] extends infer T ? Partial<T> : never = {},
) {
  const r = placeRecord({ market: MARKET, params, epochs: [[42n, state]], ...over });
  return checklist(r, r.epochs.get(42n)!).map((x) => `${x.id}:${x.status}`);
}

describe('checklist (per participation)', () => {
  it('a sealed envelope has its key, binding and promise checked and waits for its epoch', () => {
    expect(rows({ kind: 'sealed' })).toEqual([
      'key:passed',
      'binding:passed',
      'promise:passed',
      'root:pending',
      'executor:pending',
      'quorum:pending',
      'fills:pending',
      'balance:pending',
      'settled:pending',
    ]);
  });

  it('shows "checking..." for the next check of an epoch in flight', () => {
    expect(rows({ kind: 'locked' })[3]).toBe('root:checking');
    expect(rows({ kind: 'provisional', have: 1, need: 2 }).slice(4, 6)).toEqual([
      'executor:passed',
      'quorum:checking',
    ]);
    expect(rows({ kind: 'settling', done: 1, total: 2 })[8]).toBe('settled:checking');
    expect(rows({ kind: 'settled', filled: 1n }).every((x) => x.endsWith(':passed'))).toBe(true);
  });

  it('fails the batch-root check for an excluded envelope', () => {
    expect(rows({ kind: 'excluded', evidenceId: 'e' }).slice(2, 5)).toEqual([
      'promise:passed',
      'root:failed',
      'executor:not_reached',
    ]);
  });

  it('fails the check a verification failure names', () => {
    expect(checkOfFailure('V-7 receipt quorum')).toBe('executor');
    expect(
      rows({ kind: 'included' }, { state: { kind: 'verification_failed', check: 'V-7' } })[4],
    ).toBe('executor:failed');
  });

  it('keeps what passed before an epoch was voided', () => {
    expect(
      rows(
        { kind: 'voided', outcomeWasPublic: false },
        {
          history: [
            { atMs: 1, kind: 'promise_verified', epoch: 42n },
            { atMs: 2, kind: 'inclusion', epoch: 42n, inclusion: 'included' },
          ],
        },
      ).slice(3, 5),
    ).toEqual(['root:passed', 'executor:not_reached']);
  });

  it('renders each row with its status and technical detail, linking to the epoch', async () => {
    const r = placeRecord({
      market: MARKET,
      params,
      epochs: [[42n, { kind: 'provisional', have: 1, need: 2 }]],
    });
    render(
      <MemoryRouter>
        <VerificationChecklist
          record={r}
          participation={r.epochs.get(42n)!}
          epochHref="/epochs/m/42"
        />
      </MemoryRouter>,
    );
    expect(screen.getByRole('heading', { name: ordersCopy.drawer.checklist('42') })).toBeTruthy();
    expect(screen.getByText('Quorum 1/2:')).toBeTruthy();
    expect(screen.getAllByText(ordersCopy.checks.checking)).toHaveLength(1);
    expect(screen.getByText(ordersCopy.checks.detail.executor)).toBeTruthy();
    expect(
      screen.getByRole('link', { name: ordersCopy.drawer.epochLink('42') }).getAttribute('href'),
    ).toBe('/epochs/m/42');
    await expectNoSeriousAxeViolations();
  });

  const states: [string, ParticipationState, Partial<Parameters<typeof placeRecord>[0]>][] = [
    ['sealed', { kind: 'sealed' }, {}],
    ['locked', { kind: 'locked' }, {}],
    ['settling', { kind: 'settling', done: 1, total: 2 }, {}],
    ['settled', { kind: 'settled', filled: 1n }, {}],
    ['excluded', { kind: 'excluded', evidenceId: 'e' }, {}],
    [
      'verification failed',
      { kind: 'included' },
      { state: { kind: 'verification_failed', check: 'V-7' } },
    ],
    ['voided', { kind: 'voided', outcomeWasPublic: false }, {}],
  ];

  it.each(states)('renders the %s checklist accessibly', async (_, state, over) => {
    const r = placeRecord({ market: MARKET, params, epochs: [[42n, state]], ...over });
    render(
      <MemoryRouter>
        <VerificationChecklist record={r} participation={r.epochs.get(42n)!} epochHref="/e/42" />
      </MemoryRouter>,
    );
    expect(screen.getByRole('heading', { name: ordersCopy.drawer.checklist('42') })).toBeTruthy();
    await expectNoSeriousAxeViolations();
  });
});
