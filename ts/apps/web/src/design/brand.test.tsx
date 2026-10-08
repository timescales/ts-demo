import { readdirSync, readFileSync, statSync } from 'node:fs';
import { dirname, join, relative } from 'node:path';
import { fileURLToPath } from 'node:url';

import { render, screen } from '@testing-library/react';
import { describe, expect, it } from 'vitest';

import { expectNoSeriousAxeViolations } from '../components/testing/a11y';
import { brand } from './brand';
import { Wordmark } from './Wordmark';

const src = join(dirname(fileURLToPath(import.meta.url)), '..');

function sources(dir: string): string[] {
  return readdirSync(dir).flatMap((name) => {
    const path = join(dir, name);
    if (statSync(path).isDirectory()) return sources(path);
    return /\.(ts|tsx|css|html|svg)$/.test(name) && !/\.test\.tsx?$/.test(name) ? [path] : [];
  });
}

// The rule is about the name as copy. Lowercase identifiers fixed in
// code (the '@timescales/sdk' package, the Trusted Types policy
// 'timescales', the E2E marker 'timescales-e2e-wallet') are not copy, and
// module specifiers are stripped so a package rename cannot trip the guard.
const MODULE_SPECIFIER = /\b(?:from|import)\s*\(?\s*(['"])[^'"\n]*\1/g;
const PRODUCT_NAME = new RegExp(`\\b(?:${brand.name}|${brand.name.toUpperCase()})\\b`, 'g');

function productNameHits(text: string): string[] {
  return [...text.replace(MODULE_SPECIFIER, '').matchAll(PRODUCT_NAME)].map((m) => m[0]);
}

describe('brand', () => {
  it('names the product once, here', () => {
    const offenders = sources(src)
      .filter((file) => productNameHits(readFileSync(file, 'utf8')).length > 0)
      .map((file) => relative(src, file));
    expect(offenders).toEqual([join('design', 'brand.ts')]);
  });

  it('flags the name in copy but not the identifiers code needs', () => {
    expect(productNameHits(`title: '${brand.name} does not publish reasons.'`)).toEqual([
      brand.name,
    ]);
    expect(productNameHits(`<h1>${brand.name.toUpperCase()}</h1>`)).toHaveLength(1);
    const code = [
      `import { createClient } from '@${brand.wordmark}/sdk';`,
      `import type { PublicPhase } from '@${brand.wordmark}/sdk/types';`,
      `const sdk = await import('@${brand.wordmark}/sdk/verify');`,
      `export * from '@${brand.wordmark}/sdk/stores';`,
      `trustedTypes.createPolicy('${brand.wordmark}', { createHTML: (s) => s });`,
      `if (marker === '${brand.wordmark}-e2e-wallet') enableTestWallet();`,
    ].join('\n');
    expect(productNameHits(code)).toEqual([]);
  });

  it('keeps the wordmark lowercase with a three-slat lock-up', () => {
    expect(brand.wordmark).toBe(brand.name.toLowerCase());
    expect(brand.slats).toBe(3);
  });
});

describe('Wordmark', () => {
  it('is one inline SVG named by the wordmark, with three slats', async () => {
    const { container } = render(<Wordmark />);
    const svg = screen.getByRole('img', { name: 'timescales' });
    expect(svg.tagName.toLowerCase()).toBe('svg');
    expect(svg.querySelector('text')?.textContent).toBe('timescales');
    // Three brass slats beside the word and three mask cut-outs across it.
    expect(container.querySelectorAll('svg > rect')).toHaveLength(3);
    expect(container.querySelectorAll('mask rect[fill="black"]')).toHaveLength(3);
    const maskId = svg.querySelector('mask')?.id ?? '';
    expect(maskId).toMatch(/^wordmark-[a-zA-Z0-9_-]+$/);
    expect(svg.querySelector('text')?.getAttribute('mask')).toBe(`url(#${maskId})`);
    await expectNoSeriousAxeViolations();
  });

  it('gives each instance its own mask and can be decorative', async () => {
    const { container } = render(
      <>
        <Wordmark />
        <Wordmark decorative />
      </>,
    );
    const ids = [...container.querySelectorAll('mask')].map((m) => m.id);
    expect(new Set(ids).size).toBe(2);
    expect(screen.getAllByRole('img')).toHaveLength(1);
    await expectNoSeriousAxeViolations();
  });
});
