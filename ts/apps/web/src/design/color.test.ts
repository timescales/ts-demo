import { describe, expect, it } from 'vitest';

import {
  composite,
  contrastRatio,
  deltaE76,
  minDeltaE76UnderCvd,
  mix,
  parseColor,
  simulateVision,
  toHex,
  toLab,
} from './color';

describe('colour arithmetic', () => {
  it('parses hex and rgba', () => {
    expect(parseColor('#fff')).toEqual({ r: 1, g: 1, b: 1, a: 1 });
    expect(toHex(parseColor('#0b0c10'))).toBe('#0B0C10');
    expect(parseColor('rgba(237, 232, 221, 0.12)').a).toBe(0.12);
    expect(toHex(parseColor('rgb(255,0,0)'))).toBe('#FF0000');
    expect(() => parseColor('blue')).toThrow();
  });

  it('parses the alpha hex forms and the space, slash, hsl and oklch syntaxes', () => {
    expect(parseColor('#d3a65780')).toEqual({ ...parseColor('#d3a657'), a: 0x80 / 255 });
    expect(parseColor('#f008').a).toBeCloseTo(0x88 / 255, 10);
    expect(toHex(parseColor('#f008'))).toBe('#FF0000');
    expect(parseColor('rgb(211 166 87)')).toEqual(parseColor('#d3a657'));
    expect(parseColor('rgb(211 166 87 / 50%)').a).toBe(0.5);
    expect(toHex(parseColor('rgb(100% 0% 50%)'))).toBe('#FF0080');
    expect(toHex(parseColor('hsl(0, 100%, 50%)'))).toBe('#FF0000');
    expect(toHex(parseColor('hsl(120deg 100% 25% / 0.5)'))).toBe('#008000');
    expect(toHex(parseColor('hsla(0.5turn, 100%, 50%, 1)'))).toBe('#00FFFF');
    expect(toHex(parseColor('oklch(62.8% 0.2577 29.23)'))).toBe('#FF0000');
    expect(toHex(parseColor('oklab(0.8664 -0.2339 0.1795)'))).toBe('#00FF00');
    for (const bad of [
      'rgb(1 2)',
      'rgb(1, 2, 3, 4, 5)',
      'hsl(10px 50% 50%)',
      'rgb(1 2 3 / 4 / 5)',
    ]) {
      expect(() => parseColor(bad), bad).toThrow();
    }
  });

  it('computes WCAG contrast', () => {
    expect(contrastRatio(parseColor('#000000'), parseColor('#ffffff'))).toBeCloseTo(21, 10);
    expect(contrastRatio(parseColor('#777777'), parseColor('#ffffff'))).toBeCloseTo(4.48, 2);
  });

  it('composites and mixes', () => {
    const white = parseColor('#ffffff');
    const black = parseColor('#000000');
    expect(toHex(composite({ ...white, a: 0.5 }, black))).toBe('#808080');
    expect(toHex(mix(parseColor('#e9d46a'), parseColor('#111318'), 0.14))).toBe('#2F2E23');
  });

  it('converts to CIELAB and measures ΔE76', () => {
    const [l, a, b] = toLab(parseColor('#ffffff'));
    expect(l).toBeCloseTo(100, 3);
    expect(a).toBeCloseTo(0, 2);
    expect(b).toBeCloseTo(0, 2);
    expect(deltaE76(parseColor('#123456'), parseColor('#123456'))).toBe(0);
  });

  it('leaves greys unchanged under dichromacy simulation and merges red and green', () => {
    const grey = parseColor('#808080');
    for (const vision of ['deuteranopia', 'protanopia'] as const) {
      expect(deltaE76(simulateVision(grey, vision), grey)).toBeLessThan(1);
    }
    const red = parseColor('#d03030');
    const green = parseColor('#30a030');
    expect(minDeltaE76UnderCvd(red, green)).toBeLessThan(deltaE76(red, green) / 2);
  });
});
