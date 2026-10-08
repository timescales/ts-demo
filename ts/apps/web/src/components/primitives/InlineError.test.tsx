import { render, screen } from '@testing-library/react';
import { describe, expect, it } from 'vitest';

import { expectNoSeriousAxeViolations } from '../testing/a11y';
import { InlineError } from './InlineError';

describe('InlineError', () => {
  it('carries an icon and an "Error:" prefix for screen readers', async () => {
    render(<InlineError id="qty-error">Declined in wallet. Nothing was sent.</InlineError>);
    const error = document.getElementById('qty-error');
    expect(error?.textContent).toBe('Error: Declined in wallet. Nothing was sent.');
    expect(error?.querySelector('svg[aria-hidden="true"]')).not.toBeNull();
    expect(
      screen.getByText('Declined in wallet. Nothing was sent.', { exact: false }),
    ).toBeTruthy();
    await expectNoSeriousAxeViolations();
  });
});
