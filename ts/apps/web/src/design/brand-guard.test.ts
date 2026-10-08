// Automated guard: nothing in tokens.css, src/ or a built dist/ may use
// HumidiFi's palette, fonts or vocabulary. CI re-runs this after a build so
// dist/ is covered too.
import { existsSync, readdirSync, readFileSync, statSync } from 'node:fs';
import { dirname, join, relative } from 'node:path';
import { fileURLToPath } from 'node:url';

import { describe, expect, it } from 'vitest';

import { deltaE76, parseColor } from './color';

const here = dirname(fileURLToPath(import.meta.url));
const appRoot = join(here, '..', '..');
const self = fileURLToPath(import.meta.url);

// Read from the captured humidifi.xyz stylesheets.
const FOREIGN_COLOURS = ['#1300FD', '#06A2FD'].map(parseColor);
const MIN_DELTA_E = 20;

const TEXT_FILE = /\.(ts|tsx|js|mjs|css|html|svg|json|md|txt)$/;

function walk(dir: string): string[] {
  if (!existsSync(dir)) return [];
  return readdirSync(dir).flatMap((name) => {
    const path = join(dir, name);
    if (statSync(path).isDirectory()) return walk(path);
    return TEXT_FILE.test(name) ? [path] : [];
  });
}

const FILES = [...walk(join(appRoot, 'src')), ...walk(join(appRoot, 'dist'))].filter(
  (f) => f !== self,
);

// Colour literals in every CSS syntax a source or a minifier may write: hex
// with or without alpha (#RRGGBBAA is what the build emits for translucent
// colours), and the colour functions with numeric arguments in either the
// comma or the space / slash syntax. Matches that parseColor cannot evaluate
// (lab, lch, hwb, color) fail the scan rather than being skipped.
const ARG = String.raw`\s*[+-]?(?:\d+\.?\d*|\.\d+)(?:e[+-]?\d+)?(?:%|deg|grad|rad|turn)?\s*`;
const COLOUR = new RegExp(
  String.raw`#(?:[0-9a-f]{8}|[0-9a-f]{6}|[0-9a-f]{4}|[0-9a-f]{3})\b` +
    String.raw`|\b(?:rgba?|hsla?|hwb|lab|lch|oklab|oklch)\(${ARG}(?:[,\s]${ARG}){2}(?:[,/]${ARG})?\)` +
    String.raw`|\bcolor\(\s*[a-z0-9-]+(?:${ARG}){3}(?:/${ARG})?\)`,
  'gi',
);

const WORDS: [string, RegExp][] = [
  ['humidifi', /humidifi/i],
  ['WET', /\bWET\b/],
  ['Weteran', /weteran/i],
  ['aquarium', /aquarium/i],
  ['APK Praktikal', /apk\s*praktikal/i],
  // "Cy" is a common minified identifier, so it is only a font name inside a
  // font-family declaration or a quoted family name.
  ['Cy', /font-family:[^;}]*\bCy\b|['"]Cy['"]/],
];

export function foreignColourHits(text: string): string[] {
  const hits: string[] = [];
  for (const match of text.matchAll(COLOUR)) {
    let colour;
    try {
      colour = parseColor(match[0]);
    } catch {
      hits.push(`${match[0]} (cannot evaluate)`);
      continue;
    }
    if (FOREIGN_COLOURS.some((f) => deltaE76(colour, f) < MIN_DELTA_E)) hits.push(match[0]);
  }
  return hits;
}

export function foreignWordHits(text: string): string[] {
  return WORDS.filter(([, pattern]) => pattern.test(text)).map(([name]) => name);
}

describe('brand guard', () => {
  it('scans tokens.css and the app sources', () => {
    const scanned = FILES.map((f) => relative(appRoot, f));
    expect(scanned).toContain(join('src', 'styles', 'tokens.css'));
    expect(scanned.length).toBeGreaterThan(50);
  });

  it('detects the foreign palette, fonts and vocabulary', () => {
    expect(foreignColourHits('color: #1300fd; border: rgb(10, 0, 250); x: #06A2FD')).toEqual([
      '#1300fd',
      'rgb(10, 0, 250)',
      '#06A2FD',
    ]);
    expect(foreignColourHits('color: #d3a657; background: #0b0c10')).toEqual([]);
    // Alpha hex as the minifier writes it, the space syntax, hsl and oklch.
    expect(
      foreignColourHits(
        'a{color:#1300fd80;fill:rgb(19 0 253);stroke:hsl(244.5deg 100% 49.6%);outline-color:oklch(45% 0.31 266)}',
      ),
    ).toEqual(['#1300fd80', 'rgb(19 0 253)', 'hsl(244.5deg 100% 49.6%)', 'oklch(45% 0.31 266)']);
    expect(foreignColourHits('a{color:#ede8dd1f;background:rgb(11 12 16 / 72%)}')).toEqual([]);
    // A colour the scan cannot evaluate is a failure, not a pass.
    expect(foreignColourHits('a{color:lab(30 40 -100)}')).toEqual([
      'lab(30 40 -100) (cannot evaluate)',
    ]);
    // Code that merely builds colour strings is not a colour literal.
    expect(
      foreignColourHits('const c = "rgb(" + r + "," + g + "," + b + ")"; issue #18421'),
    ).toEqual([]);
    expect(foreignWordHits("font-family: Cy, sans-serif; font-family: 'APK Praktikal'")).toEqual([
      'APK Praktikal',
      'Cy',
    ]);
    expect(foreignWordHits('Get WET at the Aquarium')).toEqual(['WET', 'aquarium']);
    expect(foreignWordHits('const Cy=1;wet paint;humid')).toEqual([]);
  });

  it.each(FILES.map((f) => [relative(appRoot, f), f]))('%s uses none of it', (_, file) => {
    const text = readFileSync(file, 'utf8');
    expect(foreignColourHits(text)).toEqual([]);
    expect(foreignWordHits(text)).toEqual([]);
  });
});
