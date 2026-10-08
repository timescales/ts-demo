import { describe, expect, it } from 'vitest';

import { epochProgress, formatDuration, warningThresholdMs } from './clock';

describe('warningThresholdMs', () => {
  it('is min(10 s, interval / 3)', () => {
    expect(warningThresholdMs(20_000)).toBeCloseTo(6_666.67, 1);
    expect(warningThresholdMs(30_000)).toBe(10_000);
    expect(warningThresholdMs(120_000)).toBe(10_000);
  });

  it('is suppressed under a 20 s interval', () => {
    expect(warningThresholdMs(19_999)).toBeNull();
    expect(warningThresholdMs(10_000)).toBeNull();
  });
});

describe('clock helpers', () => {
  it('clamps the elapsed fraction', () => {
    expect(epochProgress(5, 0, 10)).toBe(0.5);
    expect(epochProgress(-5, 0, 10)).toBe(0);
    expect(epochProgress(50, 0, 10)).toBe(1);
  });

  it('formats lifetime estimates as m:ss', () => {
    expect(formatDuration(20_000)).toBe('0:20');
    expect(formatDuration(90_000)).toBe('1:30');
    expect(formatDuration(3_725_000)).toBe('1:02:05');
  });
});
