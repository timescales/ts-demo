// Test-only helpers: imported by *.test.tsx files, never by app code.
import { cleanup } from '@testing-library/react';
import axe from 'axe-core';
import { afterEach, expect } from 'vitest';

// Vitest runs without globals, so Testing Library cannot register its own
// cleanup. Every test file that imports this module gets it.
afterEach(cleanup);

// happy-dom computes no layout or colour, so contrast, target size and
// focus visibility are checked in real browsers on the gallery route.
const LAYOUT_RULES = ['color-contrast', 'color-contrast-enhanced', 'target-size'];

/** Fails on any axe violation of impact serious or critical. */
export async function expectNoSeriousAxeViolations(root: Element = document.body) {
  const result = await axe.run(root, {
    resultTypes: ['violations'],
    rules: Object.fromEntries(LAYOUT_RULES.map((id) => [id, { enabled: false }])),
  });
  const serious = result.violations
    .filter((v) => v.impact === 'serious' || v.impact === 'critical')
    .map((v) => `${v.id} (${v.impact}): ${v.nodes.map((n) => n.target.join(' ')).join(', ')}`);
  expect(serious).toEqual([]);
}
