import { describe, expect, it } from 'vitest';

import { formatCountdown, formatRemaining, shortAddress } from './time';

describe('time formatting', () => {
  it('formats countdowns as mm:ss and clamps', () => {
    expect(formatCountdown(7)).toBe('00:07');
    expect(formatCountdown(65.9)).toBe('01:05');
    expect(formatCountdown(-3)).toBe('00:00');
    expect(formatCountdown(Number.NaN)).toBe('00:00');
    expect(formatCountdown(4500)).toBe('75:00');
  });

  it('switches to hours from one hour up', () => {
    expect(formatRemaining(3599)).toBe('59:59');
    expect(formatRemaining(3600)).toBe('1h 00m');
    expect(formatRemaining(4520)).toBe('1h 15m');
  });

  it('shortens addresses', () => {
    expect(shortAddress('7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU')).toBe('7xKX...gAsU');
    expect(shortAddress('abc')).toBe('abc');
  });
});
