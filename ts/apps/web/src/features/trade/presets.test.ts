import { describe, expect, it } from 'vitest';

import { durationPresets } from './presets';
import { fixtureParams } from './testing/fakes';

describe('durationPresets', () => {
  it('labels the SDK presets with their duration (example: lifetime cap 8)', () => {
    const presets = durationPresets(fixtureParams({ maxOrderLifetime: 8 }), 10_000, 18_000);
    expect(presets).toEqual([
      { epochs: 2, label: 'Next clearing (2 epochs) ~ 0:20' },
      { epochs: 4, label: '4 epochs ~ 0:40' },
      { epochs: 9, label: 'Max: 9 epochs ~ 1:30' },
    ]);
  });

  it('never offers more than max_order_lifetime + 1 epochs', () => {
    for (const cap of [0, 1, 2, 3, 8, 16]) {
      const presets = durationPresets(fixtureParams({ maxOrderLifetime: cap }), 10_000, 18_000);
      expect(Math.max(...presets.map((p) => p.epochs))).toBe(cap + 1);
    }
  });

  it('offers "This epoch" only for intervals of 30 s or more', () => {
    const short = durationPresets(fixtureParams(), 29_999, 1_000);
    expect(short.some((p) => p.epochs === 1)).toBe(false);
    const long = durationPresets(fixtureParams(), 30_000, 18_000);
    expect(long[0]).toEqual({ epochs: 1, label: 'This epoch ~ 0:30' });
  });
});
