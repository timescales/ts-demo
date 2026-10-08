import type { MarketDetail } from '@timescales/sdk/api';
import { describe, expect, it } from 'vitest';

import { fixtureParams, FIXTURE_UNITS, placeRecord } from '../trade/testing/fakes';
import { fillRows, fillsCsv } from './FillsTable';
import { fillsByEpoch, toCsv } from './fills';

const MARKET = 'Market1111111111111111111111111111111111111' as never;
const params = fixtureParams();
const fill = (quantity: bigint, tick: bigint) => ({
  commitment: new Uint8Array(32),
  book: 2 as const,
  side: 0 as const,
  role: 0 as const,
  quantity,
  tick,
  feeQuote: 15n,
});

const record = placeRecord({
  market: MARKET,
  params,
  epochs: [
    [41n, { kind: 'settled', filled: 3n }],
    [42n, { kind: 'voided', outcomeWasPublic: false }],
    [43n, { kind: 'verified', filled: 2n }],
  ],
  history: [
    { atMs: 1, kind: 'fills', epoch: 41n, filled: 3n },
    { atMs: 2, kind: 'fills', epoch: 42n, filled: 5n },
    { atMs: 3, kind: 'fills', epoch: 43n, filled: 2n },
  ],
  // The voided epoch's fills were removed by the SDK, so only 41 and 43 remain.
  fills: [fill(1n, 15_000n), fill(2n, 15_000n), fill(2n, 15_010n)],
});

describe('fillsByEpoch', () => {
  it('attributes fills to epochs in event order and skips voided epochs', () => {
    expect(fillsByEpoch(record).map((f) => [f.epoch, f.quantity, f.settled])).toEqual([
      [41n, 1n, true],
      [41n, 2n, true],
      [43n, 2n, false],
    ]);
  });
});

describe('fills CSV', () => {
  const detail = {
    market: MARKET,
    name: 'SOL/USDC',
    baseSymbol: 'SOL',
    quoteSymbol: 'USDC',
    params,
    books: [{ book: 2, label: 'Maker bids, taker asks' }],
    ...FIXTURE_UNITS,
  } as unknown as MarketDetail;

  it('writes one row per verified fill, newest epoch first, with plain decimals', () => {
    const csv = fillsCsv(fillRows([record], new Map([[MARKET, detail]])));
    expect(csv.split('\r\n')).toEqual([
      'Market,Epoch,Book,Side,Role,Quantity,Base,Price,Fee,Quote,Status',
      'SOL/USDC,43,"Maker bids, taker asks",Buy,Maker,0.002,SOL,150.1,0.000015,USDC,Provisional',
      'SOL/USDC,41,"Maker bids, taker asks",Buy,Maker,0.001,SOL,150,0.000015,USDC,Settled',
      'SOL/USDC,41,"Maker bids, taker asks",Buy,Maker,0.002,SOL,150,0.000015,USDC,Settled',
      '',
    ]);
  });

  it('quotes fields as RFC 4180 requires', () => {
    expect(toCsv(['a'], [['x"y'], ['1\n2']])).toBe('a\r\n"x""y"\r\n"1\n2"\r\n');
  });

  it('keeps operator-supplied text from being read as a spreadsheet formula', () => {
    const csv = fillsCsv(
      fillRows(
        [record],
        new Map([
          [
            MARKET,
            {
              ...detail,
              name: '=HYPERLINK("http://x","y")',
              baseSymbol: '@SUM(A1)',
              quoteSymbol: '+1',
              books: [{ book: 2, label: '-2+3' }],
            } as MarketDetail,
          ],
        ]),
      ),
    );
    expect(csv.split('\r\n')[1]).toBe(
      `"'=HYPERLINK(""http://x"",""y"")",43,'-2+3,Buy,Maker,0.002,'@SUM(A1),150.1,0.000015,'+1,Provisional`,
    );
    expect(toCsv(['a'], [['\tx'], ['-1.5'], ['7']])).toBe("a\r\n'\tx\r\n-1.5\r\n7\r\n");
  });
});
