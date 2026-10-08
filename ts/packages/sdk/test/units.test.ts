import fc from 'fast-check';
import { describe, expect, it } from 'vitest';
import {
  UnitsError,
  baseToLots,
  lotsToBase,
  parseDecimal,
  priceToTick,
  tickToPrice,
  type MarketParams,
  type UnitContext,
} from '../src/core/index.js';

const params: MarketParams = {
  market: 1n,
  baseLotSize: 1000n,
  tickSize: 100n,
  bandHalfWidth: 3,
  maxOrderLotsLog2: 20,
  maxOrdersPerTrader: 1024,
  maxBatchEnvelopes: 1024,
  maxOrderLifetime: 8,
  makerFeeBps: 1,
  takerFeeBps: 5,
  flow: 0,
  rationing: 0,
  commitmentScheme: 0,
};

// 9-decimal base token, 6-decimal quote token: one lot = 1e-6 base tokens,
// one tick = 100 quote atoms per lot = 1e-4 quote per 1e-6 base = 100 quote per base.
const u: UnitContext = { params, baseDecimals: 9, quoteDecimals: 6 };

describe('tick ↔ price', () => {
  it.each([
    [0n, '0'],
    [1n, '100'],
    [10003n, '1000300'],
  ])('tick %s is price %s', (tick, price) => {
    expect(tickToPrice(u, tick)).toBe(price);
    expect(priceToTick(u, price, 0, 'down')).toEqual({ tick, exact: true });
  });

  it('gives exact fractional prices', () => {
    const v: UnitContext = {
      params: { ...params, baseLotSize: 1_000_000n, tickSize: 25n },
      baseDecimals: 6,
      quoteDecimals: 6,
    };
    expect(tickToPrice(v, 1n)).toBe('0.000025');
    expect(tickToPrice(v, 40000n)).toBe('1');
    expect(priceToTick(v, '1.5', 0, 'down')).toEqual({ tick: 60000n, exact: true });
  });

  it('rounds by mode, with ties in the trader’s favour for nearest', () => {
    const v: UnitContext = {
      params: { ...params, baseLotSize: 1_000_000n, tickSize: 10n },
      baseDecimals: 6,
      quoteDecimals: 6,
    };
    // One tick is 0.00001. 0.000015 is exactly between ticks 1 and 2.
    expect(priceToTick(v, '0.000015', 0, 'down')).toEqual({ tick: 1n, exact: false });
    expect(priceToTick(v, '0.000015', 0, 'up')).toEqual({ tick: 2n, exact: false });
    expect(priceToTick(v, '0.000015', 0, 'nearest')).toEqual({ tick: 1n, exact: false });
    expect(priceToTick(v, '0.000015', 1, 'nearest')).toEqual({ tick: 2n, exact: false });
    expect(priceToTick(v, '0.000016', 0, 'nearest')).toEqual({ tick: 2n, exact: false });
    expect(priceToTick(v, '0.000014', 1, 'nearest')).toEqual({ tick: 1n, exact: false });
  });

  it('refuses a price with no finite decimal expansion instead of approximating', () => {
    const v: UnitContext = {
      params: { ...params, baseLotSize: 3n, tickSize: 1n },
      baseDecimals: 0,
      quoteDecimals: 0,
    };
    expect(() => tickToPrice(v, 1n)).toThrow(UnitsError);
    expect(tickToPrice(v, 3n)).toBe('1');
  });

  it('rejects ticks beyond u64', () => {
    expect(() => priceToTick(u, '1' + '0'.repeat(30), 0, 'down')).toThrow(UnitsError);
    expect(() => tickToPrice(u, 1n << 64n)).toThrow(UnitsError);
  });

  it('round-trips every tick (property)', () => {
    fc.assert(
      fc.property(
        fc.bigInt({ min: 0n, max: (1n << 64n) - 1n }),
        fc.integer({ min: 0, max: 12 }),
        fc.integer({ min: 0, max: 12 }),
        (tick, bd, qd) => {
          const v: UnitContext = { params, baseDecimals: bd, quoteDecimals: qd };
          const price = tickToPrice(v, tick);
          for (const mode of ['down', 'up', 'nearest'] as const) {
            expect(priceToTick(v, price, 0, mode)).toEqual({ tick, exact: true });
          }
        },
      ),
    );
  });

  it('down <= nearest <= up and they differ by at most one (property)', () => {
    fc.assert(
      fc.property(
        fc.bigInt({ min: 0n, max: 10n ** 12n }),
        fc.integer({ min: 0, max: 9 }),
        (v, scale) => {
          const s = v.toString().padStart(scale + 1, '0');
          const price =
            scale === 0 ? s : `${s.slice(0, s.length - scale)}.${s.slice(s.length - scale)}`;
          const canonical = parseDecimal(price, { decimal: '.', group: '' });
          const down = priceToTick(u, canonical, 0, 'down').tick;
          const up = priceToTick(u, canonical, 1, 'up').tick;
          const near = priceToTick(u, canonical, 0, 'nearest').tick;
          expect(down <= near && near <= up && up - down <= 1n).toBe(true);
        },
      ),
    );
  });
});

describe('lots ↔ base', () => {
  it.each([
    [0n, '0'],
    [1n, '0.000001'],
    [1_000_000n, '1'],
    [1_500_000n, '1.5'],
  ])('%s lots is %s base', (lots, base) => {
    expect(lotsToBase(u, lots)).toBe(base);
    expect(baseToLots(u, base, 'down')).toEqual({ lots, exact: true });
  });

  it('rounds partial lots by mode (ties up)', () => {
    expect(baseToLots(u, '0.0000015', 'down')).toEqual({ lots: 1n, exact: false });
    expect(baseToLots(u, '0.0000015', 'up')).toEqual({ lots: 2n, exact: false });
    expect(baseToLots(u, '0.0000015', 'nearest')).toEqual({ lots: 2n, exact: false });
    expect(baseToLots(u, '0.0000014', 'nearest')).toEqual({ lots: 1n, exact: false });
  });

  it('round-trips every lot count (property)', () => {
    fc.assert(
      fc.property(
        fc.bigInt({ min: 0n, max: (1n << 48n) - 1n }),
        fc.integer({ min: 0, max: 18 }),
        (lots, bd) => {
          const v: UnitContext = { params, baseDecimals: bd, quoteDecimals: 6 };
          expect(baseToLots(v, lotsToBase(v, lots), 'nearest')).toEqual({ lots, exact: true });
        },
      ),
    );
  });

  it('accepts only canonical decimals', () => {
    for (const bad of ['', '1,5', '-1', '1e3', '.5', '1.', ' 1', '0x10']) {
      expect(() => baseToLots(u, bad, 'down')).toThrow(UnitsError);
    }
  });
});

describe('parseDecimal', () => {
  const dot = { decimal: '.', group: ',' } as const;
  const comma = { decimal: ',', group: '.' } as const;
  const space = { decimal: ',', group: ' ' } as const;
  const plain = { decimal: '.', group: '' } as const;

  it.each([
    ['1,234.5', dot, '1234.5'],
    ['1,234,567', dot, '1234567'],
    ['0.50', dot, '0.5'],
    ['007', dot, '7'],
    ['.5', dot, '0.5'],
    ['5.', dot, '5'],
    ['1.234,5', comma, '1234.5'],
    ['1,5', comma, '1.5'],
    ['1 234,5', space, '1234.5'],
    ['1 234,5', space, '1234.5'],
    ['1 234', space, '1234'],
    ['  42  ', plain, '42'],
    ['0.000', plain, '0'],
  ])('%j parses to %s', (input, locale, out) => {
    expect(parseDecimal(input, locale)).toBe(out);
  });

  it.each([
    ['1,23', dot],
    ['1,2345', dot],
    [',123', dot],
    ['1.234.5', dot],
    ['1.2,3', dot],
    ['1,5', plain],
    ['1.5', { decimal: ',', group: '' } as const],
    ['1.5', space],
    ["1'000", dot],
    ['1_000', dot],
  ])('%j is ambiguous', (input, locale) => {
    expect(() => parseDecimal(input, locale)).toThrow(
      expect.objectContaining({ reason: 'ambiguous' }) as UnitsError,
    );
  });

  it.each([
    ['', dot],
    ['-1', dot],
    ['1e3', dot],
    ['abc', dot],
    [',', comma],
    ['+1', dot],
  ])('%j is not a number', (input, locale) => {
    expect(() => parseDecimal(input, locale)).toThrow(UnitsError);
  });

  it('refuses a locale whose separators coincide', () => {
    expect(() => parseDecimal('1', { decimal: '.', group: '.' })).toThrow(UnitsError);
  });

  it('round-trips formatted numbers (property)', () => {
    fc.assert(
      fc.property(
        fc.bigInt({ min: 0n, max: 10n ** 30n }),
        fc.integer({ min: 0, max: 12 }),
        (v, scale) => {
          const digits = v.toString().padStart(scale + 1, '0');
          const int = digits.slice(0, digits.length - scale);
          const frac = digits.slice(digits.length - scale);
          const grouped = int.replace(/\B(?=(\d{3})+(?!\d))/g, '.');
          const text = scale === 0 ? grouped : `${grouped},${frac}`;
          const expected = (scale === 0 ? int : `${int}.${frac}`)
            .replace(/^0+(?=\d)/, '')
            .replace(/(\.\d*?)0+$/, '$1')
            .replace(/\.$/, '');
          expect(parseDecimal(text, comma)).toBe(expected);
        },
      ),
    );
  });
});
