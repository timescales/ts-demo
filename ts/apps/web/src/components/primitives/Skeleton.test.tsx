import { render, screen } from '@testing-library/react';
import { describe, expect, it } from 'vitest';

import { expectNoSeriousAxeViolations } from '../testing/a11y';
import { Skeleton } from './Skeleton';

describe('Skeleton', () => {
  it('hides its shapes and reads its label', async () => {
    const { container } = render(<Skeleton lines={4} label="Loading clearing tape" />);
    expect(screen.getByText('Loading clearing tape')).toBeTruthy();
    expect(container.querySelectorAll('[aria-hidden="true"]')).toHaveLength(4);
    await expectNoSeriousAxeViolations();
  });
});
