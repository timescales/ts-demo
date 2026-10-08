import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { describe, expect, it, vi } from 'vitest';

import { expectNoSeriousAxeViolations } from '../testing/a11y';
import { CopyHash, truncateMiddle } from './CopyHash';

const HASH = '70ce57603071452b06ada713d60af73ae164138e2290a7942741a3f519174466';

describe('CopyHash', () => {
  it('truncates in the middle', () => {
    expect(truncateMiddle(HASH, 6, 4)).toBe('70ce57...4466');
    expect(truncateMiddle('short', 6, 4)).toBe('short');
  });

  it('exposes the full value to assistive technology', async () => {
    render(<CopyHash value={HASH} label="state root" onCopy={() => undefined} />);
    expect(screen.getByText(HASH)).toBeTruthy();
    expect(screen.getByText('70ce57...4466').getAttribute('aria-hidden')).toBe('true');
    await expectNoSeriousAxeViolations();
  });

  it('copies and announces "Copied"', async () => {
    const onCopy = vi.fn();
    render(<CopyHash value={HASH} label="state root" onCopy={onCopy} />);
    fireEvent.click(screen.getByRole('button', { name: 'Copy state root' }));
    expect(onCopy).toHaveBeenCalledWith(HASH);
    await waitFor(() => expect(screen.getByRole('status').textContent).toBe('Copied'));
    await expectNoSeriousAxeViolations();
  });

  it('announces nothing when copying fails', async () => {
    render(
      <CopyHash
        value={HASH}
        label="state root"
        onCopy={() => Promise.reject(new Error('denied'))}
      />,
    );
    fireEvent.click(screen.getByRole('button', { name: 'Copy state root' }));
    await waitFor(() => expect(screen.getByRole('status').textContent).toBe(''));
  });
});
