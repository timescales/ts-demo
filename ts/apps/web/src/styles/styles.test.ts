import { readFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { describe, expect, it } from 'vitest';

const here = dirname(fileURLToPath(import.meta.url));
const read = (name: string) => readFileSync(join(here, name), 'utf8');
const require = createRequire(import.meta.url);

describe('global stylesheets', () => {
  it('self-hosts the three families from @fontsource', () => {
    const fonts = read('./fonts.css');
    const imports = [...fonts.matchAll(/@import '([^']+)';/g)].map((m) => m[1] ?? '');
    expect(imports).toEqual([
      '@fontsource/instrument-serif/400.css',
      '@fontsource-variable/inter/wght.css',
      '@fontsource/ibm-plex-mono/400.css',
      '@fontsource/ibm-plex-mono/500.css',
    ]);
    for (const path of imports) {
      const sheet = readFileSync(require.resolve(path), 'utf8');
      // Font files are relative package files, bundled as separate assets.
      for (const [, url] of sheet.matchAll(/url\(([^)]+)\)/g)) expect(url).toMatch(/^\.\/files\//);
    }
  });

  it('never inlines fonts and loads nothing from another origin', () => {
    for (const name of ['./fonts.css', './tokens.css', './base.css', './index.css']) {
      const sheet = read(name);
      expect(sheet).not.toMatch(/url\(\s*['"]?(data:|https?:|\/\/)/);
      expect(sheet).not.toMatch(/@import\s+(url\()?['"]?(https?:|\/\/)/);
    }
    const viteConfig = read('../../vite.config.ts');
    expect(viteConfig).toMatch(/assetsInlineLimit:\s*0/);
  });

  it('imports fonts, tokens and base styles from one entry', () => {
    expect([...read('./index.css').matchAll(/@import '([^']+)';/g)].map((m) => m[1])).toEqual([
      './fonts.css',
      './tokens.css',
      './base.css',
    ]);
  });

  it('draws a 2 px brass focus ring with a 2 px offset', () => {
    const base = read('./base.css');
    expect(base).toMatch(
      /:focus-visible \{\s*outline: var\(--focus-width\) solid var\(--accent\);\s*outline-offset: var\(--focus-offset\);/,
    );
    const tokens = read('./tokens.css');
    expect(tokens).toMatch(/--focus-width: 2px;/);
    expect(tokens).toMatch(/--focus-offset: 2px;/);
  });

  it('keeps focused elements clear of the chrome', () => {
    const base = read('./base.css');
    expect(base).toMatch(/scroll-padding-top: var\(--chrome-top\);/);
    expect(base).toMatch(/scroll-padding-bottom: var\(--chrome-bottom\);/);
  });

  it('draws Lucide icons at a 1.5 px stroke', () => {
    expect(read('./base.css')).toMatch(/svg\.lucide \{\s*stroke-width: 1\.5;\s*\}/);
  });

  it('locks page scroll with CSS while a dialog is open', () => {
    expect(read('./base.css')).toMatch(/:root:has\(dialog\[open\]\) \{\s*overflow: hidden;/);
  });

  it('stops animations under reduced motion, from the system or the setting', () => {
    const base = read('./base.css');
    expect(base).toMatch(/@media \(prefers-reduced-motion: reduce\)/);
    expect(base).toMatch(/:root\[data-motion='reduce'\] \*/);
  });
});
