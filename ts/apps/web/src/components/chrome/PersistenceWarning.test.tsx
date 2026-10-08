import { fireEvent, render, screen } from '@testing-library/react';
import { describe, expect, it, vi } from 'vitest';

import { componentsCopy } from '../copy';
import { expectNoSeriousAxeViolations } from '../testing/a11y';
import type { PersistenceProblem } from './PersistenceWarning';
import { PersistenceWarning } from './PersistenceWarning';

const PROBLEMS: PersistenceProblem[] = ['private_window', 'unreadable', 'not_persistent', 'full'];

describe('PersistenceWarning', () => {
  it.each(PROBLEMS)('explains %s as a persistent warning', async (problem) => {
    render(<PersistenceWarning problem={problem} />);
    const banner = screen.getByRole('region', { name: componentsCopy.persistence.title });
    expect(banner.dataset.severity).toBe('warning');
    expect(banner.textContent).toContain(componentsCopy.persistence[problem]);
    expect(screen.queryByRole('button', { name: 'Dismiss' })).toBeNull();
    await expectNoSeriousAxeViolations();
  });

  it('offers export and import', async () => {
    const onExport = vi.fn();
    const onImport = vi.fn();
    render(<PersistenceWarning problem="not_persistent" onExport={onExport} onImport={onImport} />);
    fireEvent.click(screen.getByRole('button', { name: 'Export' }));
    fireEvent.click(screen.getByRole('button', { name: 'Import' }));
    expect(onExport).toHaveBeenCalledOnce();
    expect(onImport).toHaveBeenCalledOnce();
    await expectNoSeriousAxeViolations();
  });
});
