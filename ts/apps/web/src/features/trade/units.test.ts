import { describe, expect, it } from 'vitest';

import type { NumberFormat } from './services';
import { fixtureParams, FIXTURE_UNITS } from './testing/fakes';
import {
  atomsToDecimal,
  decimalToAtoms,
  deviationPercent,
  localize,
  lotsForShare,
  orderFingerprint,
  parseLimit,
  parseQuantity,
  reserveTick,
} from './units';

const u = { params: fixtureParams(), ...FIXTURE_UNITS };
const dot: NumberFormat = { decimal: '.', group: ',' };
const comma: NumberFormat = { decimal: ',', group: '.' };

describe('parseQuantity', () => {
  it('rounds down to whole lots and echoes the exact base amount', () => {
    expect(parseQuantity('1.2345', dot, u)).toEqual({
      ok: true,
      lots: 1234n,
      base: '1.234',
      exact: false,
    });
    expect(parseQuantity('2', dot, u)).toEqual({ ok: true, lots: 2000n, base: '2', exact: true });
  });

  it('parses in the declared number format and rejects ambiguous separators', () => {
    expect(parseQuantity('1.234,5', comma, u)).toEqual({ ok: false, error: 'too_large' });
    expect(parseQuantity('12,5', comma, u)).toMatchObject({
      ok: true,
      lots: 12_500n,
      base: '12.5',
    });
    expect(parseQuantity('1,5', dot, u)).toEqual({ ok: false, error: 'ambiguous' });
    expect(parseQuantity('1.5', comma, u)).toEqual({ ok: false, error: 'ambiguous' });
    expect(parseQuantity('abc', dot, u)).toEqual({ ok: false, error: 'syntax' });
    expect(parseQuantity('', dot, u)).toEqual({ ok: false, error: 'empty' });
  });

  it('refuses less than one lot and anything from 2^b lots up', () => {
    expect(parseQuantity('0.0009', dot, u)).toEqual({ ok: false, error: 'zero' });
    // b = 20: at most 2^20 - 1 = 1,048,575 lots = 1048.575 SOL.
    expect(parseQuantity('1048.575', dot, u)).toMatchObject({ ok: true, lots: 1_048_575n });
    expect(parseQuantity('1048.576', dot, u)).toEqual({ ok: false, error: 'too_large' });
  });
});

describe('parseLimit', () => {
  it('signs the nearest tick in the trader’s favour: buys round down, sells round up', () => {
    expect(parseLimit('150.005', dot, u, 0)).toEqual({
      ok: true,
      tick: 15_000n,
      typed: '150.005',
      price: '150',
      exact: false,
    });
    expect(parseLimit('150.005', dot, u, 1)).toMatchObject({ tick: 15_001n, price: '150.01' });
    expect(parseLimit('150.01', dot, u, 1)).toMatchObject({ tick: 15_001n, exact: true });
  });

  it('refuses a price below one tick', () => {
    expect(parseLimit('0.001', dot, u, 0)).toEqual({ ok: false, error: 'zero' });
  });
});

describe('amount helpers', () => {
  it('converts atoms and decimals exactly', () => {
    expect(atomsToDecimal(1_500_000n, 6)).toBe('1.5');
    expect(atomsToDecimal(-25n, 6)).toBe('-0.000025');
    expect(decimalToAtoms('1.5', 6)).toBe(1_500_000n);
    expect(decimalToAtoms('1.1234567', 6)).toBeNull();
  });

  it('formats in the declared number format', () => {
    expect(localize('1234567.25', dot)).toBe('1,234,567.25');
    expect(localize('1234567.25', comma)).toBe('1.234.567,25');
    expect(localize('-12', dot)).toBe('−12');
  });

  it('gives the deviation from the last clearing price with two decimals', () => {
    expect(deviationPercent(15_150n, 15_000n)).toBe('+1.00');
    expect(deviationPercent(14_925n, 15_000n)).toBe('−0.50');
    expect(deviationPercent(15_000n, 15_000n)).toBe('0.00');
  });
});

describe('lotsForShare', () => {
  const params = fixtureParams();
  it('sells a share of the available base', () => {
    expect(
      lotsForShare({
        params,
        side: 1,
        feeBps: 1,
        available: { base: 2_000_000_000n, quote: 0n },
        tick: 15_000n,
        percent: 50,
      }),
    ).toBe(1000n);
  });

  it('buys what the available quote covers at the reserving tick, fee included', () => {
    // One lot at tick 15,000 costs 150,000 quote atoms plus a 1 bps fee of 15.
    expect(
      lotsForShare({
        params,
        side: 0,
        feeBps: 1,
        available: { base: 0n, quote: 150_015n * 10n },
        tick: 15_000n,
        percent: 100,
      }),
    ).toBe(10n);
  });

  it('reserves a market buy at the band top and clamps a limit into the band', () => {
    const band = { lo: 14_968n, hi: 15_032n, reference: 15_000n };
    expect(reserveTick(band, 0, 1, 0n)).toBe(15_032n);
    expect(reserveTick(band, 1, 1, 0n)).toBe(14_968n);
    expect(reserveTick(band, 0, 0, 20_000n)).toBe(15_032n);
    expect(reserveTick(band, 0, 0, 15_010n)).toBe(15_010n);
  });
});

describe('orderFingerprint', () => {
  it('is the first 8 hex characters of the intent digest', () => {
    const fp = orderFingerprint(new Uint8Array(32));
    expect(fp).toMatch(/^[0-9a-f]{8}$/);
    expect(orderFingerprint(new Uint8Array(32).fill(1))).not.toBe(fp);
  });
});
