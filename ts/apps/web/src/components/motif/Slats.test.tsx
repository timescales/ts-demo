import { render } from '@testing-library/react';
import { describe, expect, it } from 'vitest';

import { expectNoSeriousAxeViolations } from '../testing/a11y';
import { Slats } from './Slats';

describe('Slats', () => {
  it.each(['closed', 'open'] as const)(
    'renders %s, hidden from assistive technology',
    async (state) => {
      const { container } = render(<Slats count={4} state={state} />);
      const root = container.firstElementChild as HTMLElement;
      expect(root.getAttribute('aria-hidden')).toBe('true');
      expect(root.dataset.state).toBe(state);
      expect(root.children).toHaveLength(4);
      expect((root.children[3] as HTMLElement).style.getPropertyValue('--i')).toBe('3');
      await expectNoSeriousAxeViolations();
    },
  );
});
