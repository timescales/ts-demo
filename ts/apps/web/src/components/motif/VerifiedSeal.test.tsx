import { render, screen } from '@testing-library/react';
import { describe, expect, it } from 'vitest';

import { expectNoSeriousAxeViolations } from '../testing/a11y';
import { VerifiedSeal } from './VerifiedSeal';

describe('VerifiedSeal', () => {
  it('is an image named "Verified" by default', async () => {
    render(<VerifiedSeal />);
    expect(screen.getByRole('img', { name: 'Verified' })).toBeTruthy();
    await expectNoSeriousAxeViolations();
  });

  it('takes a label or can be decorative', async () => {
    const { container } = render(
      <>
        <VerifiedSeal label="Receipt verified" />
        <VerifiedSeal decorative />
      </>,
    );
    expect(screen.getByRole('img', { name: 'Receipt verified' })).toBeTruthy();
    expect(container.querySelectorAll('svg[aria-hidden="true"]')).toHaveLength(1);
    await expectNoSeriousAxeViolations();
  });
});
