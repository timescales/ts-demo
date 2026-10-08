// Recomputes the colour table from tokens.css: every listed contrast
// ratio, the tint tokens, the slat and stripe overlays, and the deltaE76
// minimums under colour-vision-deficiency simulation (WCAG 2.x formula,
// Machado 2009).
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { describe, expect, it } from 'vitest';

import type { Rgba } from '../design/color';
import {
  composite,
  contrastRatio,
  minDeltaE76UnderCvd,
  mix,
  parseColor,
  toHex,
} from '../design/color';
import type { TokenMap } from '../design/cssTokens';
import { declarationsOf } from '../design/cssTokens';

const css = readFileSync(join(dirname(fileURLToPath(import.meta.url)), 'tokens.css'), 'utf8');

const THEMES = {
  dark: declarationsOf(css, ":root[data-theme='dark']"),
  light: declarationsOf(css, ":root[data-theme='light']"),
} as const;
type Theme = keyof typeof THEMES;

function color(theme: Theme, token: string): Rgba {
  const value = THEMES[theme][token];
  if (!value) throw new Error(`${token} is not defined for ${theme}`);
  return parseColor(value);
}

/** The surfaces each theme's tokens are used on ("min" column). */
function surfaces(theme: Theme): Rgba[] {
  return theme === 'dark'
    ? ['--bg', '--surface', '--surface-raised', '--surface-overlay'].map((t) => color('dark', t))
    : [color('light', '--bg'), color('light', '--surface'), parseColor('#FFFFFF')];
}

function minContrast(fg: Rgba, backgrounds: Rgba[]): number {
  return Math.min(...backgrounds.map((bg) => contrastRatio(fg, bg)));
}

const round2 = (x: number) => Math.round(x * 100) / 100;

// [token, dark min, light min, WCAG threshold]
const RATIOS: [string, number, number, number][] = [
  ['--control-border', 3.19, 3.47, 3],
  ['--text', 12.72, 15.9, 4.5],
  ['--text-muted', 5.82, 5.99, 4.5],
  ['--accent', 6.93, 5.16, 4.5],
  ['--buy-standard', 7.63, 5.14, 4.5],
  ['--sell-standard', 5.73, 5.46, 4.5],
  ['--info', 7.22, 5.73, 4.5],
  ['--warning', 10.42, 8.34, 4.5],
  ['--danger', 6.25, 6.86, 4.5],
  ['--simulated', 6.77, 6.23, 4.5],
  ['--buy-cvd', 6.59, 5.25, 4.5],
  ['--sell-cvd', 7.28, 5.1, 4.5],
];

// The tint table: 14 % of the token over --surface.
const TINTS: [string, string, string, string][] = [
  ['--warning-bg', '--warning', '#2F2E23', '#E5E0D4'],
  ['--danger-bg', '--danger', '#322228', '#EFDADC'],
  ['--info-bg', '--info', '#232A2C', '#E1E5E0'],
  ['--simulated-bg', '--simulated', '#292731', '#E7E2E5'],
  ['--buy-bg-standard', '--buy-standard', '#192D2A', '#DCE7DF'],
  ['--accent-bg', '--accent', '#2C2821', '#EAE4D8'],
  ['--buy-bg-cvd', '--buy-cvd', '#172A31', '#DAE6E5'],
];

const THEME_NAMES: Theme[] = ['dark', 'light'];

describe('tokens.css colour table', () => {
  it.each(RATIOS)('%s meets its listed minimum contrast', (token, dark, light, threshold) => {
    for (const [theme, listed] of [
      ['dark', dark],
      ['light', light],
    ] as const) {
      const min = minContrast(color(theme, token), surfaces(theme));
      expect(round2(min), `${token} ${theme}`).toBe(listed);
      expect(min).toBeGreaterThanOrEqual(threshold);
    }
  });

  it('keeps text on brass fills legible', () => {
    expect(round2(contrastRatio(color('dark', '--on-accent'), color('dark', '--accent')))).toBe(
      8.71,
    );
    expect(round2(contrastRatio(color('light', '--on-accent'), color('light', '--accent')))).toBe(
      5.57,
    );
  });

  it('draws the focus ring at 3:1 or more on every surface', () => {
    for (const theme of THEME_NAMES) {
      expect(minContrast(color(theme, '--accent'), surfaces(theme))).toBeGreaterThanOrEqual(3);
    }
  });

  it.each(TINTS)('%s is 14 %% of its token over --surface', (tint, token, dark, light) => {
    for (const [theme, listed] of [
      ['dark', dark],
      ['light', light],
    ] as const) {
      expect(toHex(color(theme, tint))).toBe(listed);
      expect(toHex(mix(color(theme, token), color(theme, '--surface'), 0.14))).toBe(listed);
    }
  });

  it.each(TINTS)('text, muted text and the token stay legible on %s', (tint, token) => {
    for (const theme of THEME_NAMES) {
      const bg = color(theme, tint);
      expect(round2(contrastRatio(color(theme, '--text'), bg))).toBeGreaterThanOrEqual(11.19);
      expect(round2(contrastRatio(color(theme, token), bg))).toBeGreaterThanOrEqual(4.57);
      expect(contrastRatio(color(theme, '--text-muted'), bg)).toBeGreaterThanOrEqual(4.5);
    }
  });

  it('keeps text legible on the louvre slats over every surface', () => {
    for (const theme of THEME_NAMES) {
      const slat = color(theme, '--slat');
      for (const surface of surfaces(theme)) {
        const blended = composite(slat, surface);
        for (const token of ['--text', '--text-muted', '--accent']) {
          expect(
            contrastRatio(color(theme, token), blended),
            `${token} on slat ${theme}`,
          ).toBeGreaterThanOrEqual(4.5);
        }
      }
    }
  });

  it('keeps the plum label and text legible on the simulated stripe', () => {
    for (const theme of THEME_NAMES) {
      const striped = composite(color(theme, '--sim-stripe'), color(theme, '--simulated-bg'));
      expect(contrastRatio(color(theme, '--simulated'), striped)).toBeGreaterThanOrEqual(4.5);
      expect(contrastRatio(color(theme, '--text'), striped)).toBeGreaterThanOrEqual(4.5);
      // The --simulated border is a UI boundary on its tint.
      expect(
        contrastRatio(color(theme, '--simulated'), color(theme, '--simulated-bg')),
      ).toBeGreaterThanOrEqual(3);
    }
  });

  it.each([
    ['--sell-standard', '--danger'],
    ['--sell-cvd', '--warning'],
    ['--accent', '--warning'],
    ['--warning', '--danger'],
  ])('%s and %s differ by ΔE76 >= 10 under normal, deuteranopia and protanopia', (a, b) => {
    for (const theme of THEME_NAMES) {
      expect(minDeltaE76UnderCvd(color(theme, a), color(theme, b)), theme).toBeGreaterThanOrEqual(
        10,
      );
    }
  });

  it('has no saturated blue anywhere', () => {
    for (const theme of THEME_NAMES) {
      for (const [token, value] of Object.entries(THEMES[theme])) {
        if (!/^(#|rgba?\()/.test(value)) continue;
        const { r, g, b } = parseColor(value);
        const max = Math.max(r, g, b);
        const min = Math.min(r, g, b);
        const saturation = max === 0 ? 0 : (max - min) / max;
        const blueDominant = b === max && b - Math.max(r, g) > 0.25;
        expect(blueDominant && saturation > 0.5, `${token} ${theme}`).toBe(false);
      }
    }
  });
});

describe('tokens.css structure', () => {
  it('repeats the light theme exactly for data-theme="system" under a light preference', () => {
    expect(declarationsOf(css, ":root[data-theme='system']")).toEqual(THEMES.light);
    expect(css).toMatch(/@media \(prefers-color-scheme: light\) \{\s*:root\[data-theme='system'\]/);
  });

  it('defines the same tokens in both themes, dark being the default', () => {
    expect(Object.keys(THEMES.light).sort()).toEqual(Object.keys(THEMES.dark).sort());
    expect(css).toMatch(/:root,\s*:root\[data-theme='dark'\] \{/);
  });

  it('switches buy and sell to the CVD-safe pair on data-palette="cvd"', () => {
    const base = declarationsOf(css, ':root');
    expect(base['--buy']).toBe('var(--buy-standard)');
    expect(base['--sell']).toBe('var(--sell-standard)');
    expect(base['--buy-bg']).toBe('var(--buy-bg-standard)');
    expect(declarationsOf(css, ":root[data-palette='cvd']")).toEqual({
      '--buy': 'var(--buy-cvd)',
      '--sell': 'var(--sell-cvd)',
      '--buy-bg': 'var(--buy-bg-cvd)',
    });
  });

  it('defines the slat and stripe overlays', () => {
    const base = declarationsOf(css, ':root');
    expect(base['--slat-pattern']).toBe(
      'repeating-linear-gradient(180deg, var(--slat) 0 1px, transparent 1px 5px)',
    );
    expect(base['--sim-pattern']).toMatch(
      /^repeating-linear-gradient\(135deg, var\(--sim-stripe\)/,
    );
    expect(THEMES.dark['--slat']).toBe('rgba(237, 232, 221, 0.07)');
    expect(THEMES.light['--slat']).toBe('rgba(21, 23, 28, 0.06)');
  });

  it('defines the scale, spacing, radii, elevation and motion', () => {
    const base: TokenMap = declarationsOf(css, ':root');
    const expected: TokenMap = {
      '--fs-100': '12px',
      '--lh-100': '16px',
      '--fs-400': '16px',
      '--lh-400': '24px',
      '--fs-900': '64px',
      '--lh-900': '68px',
      '--space-0': '0',
      '--space-1': '2px',
      '--space-5': '16px',
      '--space-12': '80px',
      '--radius-xs': '4px',
      '--radius-sm': '8px',
      '--radius-md': '12px',
      '--radius-lg': '20px',
      '--radius-full': '999px',
      '--shadow-card': '0 1px 2px rgba(21, 23, 28, 0.06), 0 1px 3px rgba(21, 23, 28, 0.04)',
      '--shadow-raised': '0 8px 24px rgba(21, 23, 28, 0.12)',
      '--dur-fast': '120ms',
      '--dur-base': '180ms',
      '--dur-slow': '240ms',
      '--dur-slat': '420ms',
      '--slat-stagger': '12ms',
      '--ease-standard': 'cubic-bezier(0.2, 0, 0, 1)',
      '--ease-exit': 'cubic-bezier(0.4, 0, 1, 1)',
      '--label-tracking': '0.06em',
    };
    for (const [token, value] of Object.entries(expected)) expect(base[token], token).toBe(value);
    expect(THEMES.dark['--shadow-overlay']).toBe('0 24px 64px rgba(0, 0, 0, 0.5)');
    expect(THEMES.light['--shadow-overlay']).toBe('0 24px 64px rgba(21, 23, 28, 0.18)');
    expect(base['--font-display']).toMatch(/^'Instrument Serif'/);
    expect(base['--font-ui']).toMatch(/^'Inter Variable'/);
    expect(base['--font-mono']).toMatch(/^'IBM Plex Mono'/);
  });

  it('zeroes every duration under reduced motion, from the system or the setting', () => {
    const reduced = declarationsOf(css, ":root[data-motion='reduce']");
    expect(reduced).toEqual({
      '--dur-fast': '0ms',
      '--dur-base': '0ms',
      '--dur-slow': '0ms',
      '--dur-slat': '0ms',
      '--slat-stagger': '0ms',
    });
    const media = /@media \(prefers-reduced-motion: reduce\) \{\s*:root \{([^}]*)\}/.exec(css);
    expect(media?.[1]?.replace(/\s+/g, ' ').trim()).toBe(
      '--dur-fast: 0ms; --dur-base: 0ms; --dur-slow: 0ms; --dur-slat: 0ms; --slat-stagger: 0ms;',
    );
  });

  it('sets per-layout scroll padding for the chrome (desktop 96/32 px)', () => {
    const base = declarationsOf(css, ':root');
    expect(base['--topbar-h']).toBe('56px');
    expect(base['--epochstrip-h']).toBe('40px');
    expect(base['--chrome-top']).toBe('calc(var(--topbar-h) + var(--epochstrip-h))');
    // 28 + 4 = 32 px until StatusFooter publishes its measured --footer-h.
    expect(base['--footer-min-h']).toBe('28px');
    expect(base['--footer-h']).toBe('var(--footer-min-h)');
    expect(base['--space-2']).toBe('4px');
    expect(base['--chrome-bottom']).toBe('calc(var(--footer-h) + var(--space-2))');
    expect(css).toMatch(
      /@media \(max-width: 599px\) \{\s*:root \{[^}]*--target-min: 44px;[^}]*--chrome-bottom: calc\(var\(--tabbar-h\) \+ var\(--footer-h\) \+ var\(--fab-h\)/,
    );
  });
});
