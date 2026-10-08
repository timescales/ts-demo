import { render } from '@testing-library/react';
import { describe, expect, it } from 'vitest';

import { expectNoSeriousAxeViolations } from '../testing/a11y';
import { KeyboardShortcut } from './KeyboardShortcut';

describe('KeyboardShortcut', () => {
  it('renders each key in a nested kbd', async () => {
    const { container } = render(<KeyboardShortcut keys={['Ctrl', 'Enter']} />);
    const outer = container.firstElementChild;
    expect(outer?.tagName).toBe('KBD');
    expect([...(outer?.querySelectorAll('kbd kbd') ?? [])].map((k) => k.textContent)).toEqual([
      'Ctrl',
      'Enter',
    ]);
    expect(outer?.textContent).toBe('Ctrl+Enter');
    await expectNoSeriousAxeViolations();
  });

  it('renders a single key', async () => {
    const { container } = render(<KeyboardShortcut keys={['B']} />);
    expect(container.textContent).toBe('B');
    await expectNoSeriousAxeViolations();
  });
});
