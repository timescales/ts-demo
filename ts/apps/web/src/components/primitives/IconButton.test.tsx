import { render, screen } from '@testing-library/react';
import { Lock } from 'lucide-react';
import { describe, expect, it } from 'vitest';

import { expectNoSeriousAxeViolations } from '../testing/a11y';
import { IconButton } from './IconButton';

describe('IconButton', () => {
  it.each(['ghost', 'secondary'] as const)('is named by its label (%s)', async (variant) => {
    render(<IconButton variant={variant} label="Lock values" icon={<Lock aria-hidden="true" />} />);
    expect(screen.getByRole('button', { name: 'Lock values' })).toBeTruthy();
    await expectNoSeriousAxeViolations();
  });
});
