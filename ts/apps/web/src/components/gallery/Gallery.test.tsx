import { fireEvent, render, screen, within } from '@testing-library/react';
import { afterEach, describe, expect, it } from 'vitest';

import { loadGallery } from '../../app/gallery';
import { expectNoSeriousAxeViolations } from '../testing/a11y';
import Gallery from './Gallery';

// Primitives, motif and chrome owned by this layer. Each must appear in
// the gallery so the browser axe run sees it.
const COMPONENTS = [
  'Wordmark',
  'Button',
  'IconButton',
  'ToggleGroup',
  'TextField',
  'NumberField',
  'Select',
  'Tabs',
  'Tooltip',
  'Dialog / Sheet / Drawer',
  'Badge',
  'PhaseBadge',
  'SimulatedLabel',
  'Banner',
  'Skeleton',
  'CopyHash',
  'MaskedValue',
  'Stepper',
  'Table',
  'EmptyState',
  'InlineError',
  'KeyboardShortcut',
  'Slats',
  'SealGlyph',
  'VerifiedSeal',
  'EpochRing',
  'DirectionGlyph',
  'SimStripe',
  'BannerStack',
  'VerificationBanner',
  'GovernanceWatch',
  'SimulatedBanner',
  'PersistenceWarning',
  'WalletButton',
  'SessionChip',
  'ActivityDrawer',
  'StatusFooter (TDX variants)',
];

afterEach(() => {
  history.replaceState(null, '', '/');
  delete document.documentElement.dataset.theme;
  delete document.documentElement.dataset.palette;
});

describe('component gallery', () => {
  it('is what the test-mode /__gallery route loads', async () => {
    expect(await loadGallery()).toBe(Gallery);
  });

  it('shows every component, passes axe and injects no <style> element', async () => {
    render(<Gallery />);
    const names = screen.getAllByRole('heading', { level: 3 }).map((h) => h.textContent);
    expect(names).toEqual(COMPONENTS);
    // Chrome rendered around the page: top bar, epoch strip, tab bar, footer.
    expect(screen.getByRole('banner')).toBeTruthy();
    expect(screen.getByRole('region', { name: 'Epoch status' })).toBeTruthy();
    expect(screen.getByRole('navigation', { name: 'Sections' })).toBeTruthy();
    // The page footer is the simulated one. A TDX sample sits inside <main>.
    const footers = document.querySelectorAll('footer[aria-label="System status"]');
    expect(footers[footers.length - 1]?.textContent).toContain('Enclave: SIMULATED');
    await expectNoSeriousAxeViolations();
    expect(document.querySelectorAll('style')).toHaveLength(0);
  });

  it.each(['dialog', 'sheet', 'drawer', 'activity', 'wallets'])(
    'opens the %s overlay from the query string and passes axe',
    async (overlay) => {
      history.replaceState(null, '', `/__gallery?open=${overlay}&theme=light&palette=cvd`);
      render(<Gallery />);
      const open = [...document.querySelectorAll('dialog')].filter((d) => d.open);
      expect(open).toHaveLength(1);
      expect(document.documentElement.dataset.theme).toBe('light');
      expect(document.documentElement.dataset.palette).toBe('cvd');
      await expectNoSeriousAxeViolations();
      expect(document.querySelectorAll('style')).toHaveLength(0);
    },
  );

  it('holds a tooltip open inside the open dialog', async () => {
    history.replaceState(null, '', '/__gallery?open=dialog');
    render(<Gallery />);
    const dialog = screen.getByRole('dialog', { name: 'Cancel order' });
    const tooltip = await within(dialog).findByRole('tooltip');
    expect(tooltip.textContent).toBe('It takes effect when epoch #18422 clears.');
  });

  it('opens overlays from their buttons and closes them', () => {
    render(<Gallery />);
    fireEvent.click(screen.getByRole('button', { name: 'Open drawer' }));
    const drawer = screen.getByRole('dialog', { name: 'Order details' }) as HTMLDialogElement;
    expect(drawer.open).toBe(true);
    fireEvent.click(within(drawer).getByRole('button', { name: 'Close' }));
    expect(drawer.open).toBe(false);
  });

  it('opens the tooltip without injecting styles', async () => {
    render(<Gallery />);
    fireEvent.focus(screen.getByRole('button', { name: 'Why?' }));
    await screen.findByRole('tooltip');
    expect(document.querySelectorAll('style')).toHaveLength(0);
  });
});
