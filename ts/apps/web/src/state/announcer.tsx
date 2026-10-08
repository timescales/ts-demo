// The app's two live regions: one polite, one assertive for critical
// banners. By default the polite region speaks only about the user's own
// orders and stepper progress, plus the cutoff warning while a draft ticket
// is in use. Market phase changes are spoken only with the "Announce market
// phase changes" setting, and market-driven messages share a budget of six a
// minute, so a 10 s epoch can never flood a screen reader.
import { VisuallyHidden } from '../components/primitives';
import type { Settings } from './settings';
import type { Store } from './store';
import { createStore, useStore } from './store';

export type AnnouncementCategory = 'own_order' | 'stepper' | 'cutoff' | 'market_phase' | 'critical';

export interface Announcement {
  id: number;
  text: string;
}

export interface Announcer {
  readonly polite: Store<Announcement | null>;
  readonly assertive: Store<Announcement | null>;
  /** Speaks `text` if the category is allowed now. Returns whether it was. */
  announce(text: string, category: AnnouncementCategory): boolean;
}

/** Market-driven polite messages per sliding minute. */
export const MARKET_BUDGET_PER_MINUTE = 6;
const MINUTE_MS = 60_000;

export function createAnnouncer(d: { settings: Store<Settings>; now?: () => number }): Announcer {
  const now = d.now ?? (() => Date.now());
  const polite = createStore<Announcement | null>(null);
  const assertive = createStore<Announcement | null>(null);
  const recent: number[] = [];
  let id = 0;

  const marketBudgetLeft = (): boolean => {
    const t = now();
    while (recent.length > 0 && t - recent[0]! >= MINUTE_MS) recent.shift();
    return recent.length < MARKET_BUDGET_PER_MINUTE;
  };

  return {
    polite,
    assertive,
    announce(text, category) {
      if (category === 'critical') {
        assertive.set({ id: ++id, text });
        return true;
      }
      if (category === 'market_phase' && !d.settings.get().announcePhases) return false;
      if (category === 'market_phase' || category === 'cutoff') {
        if (!marketBudgetLeft()) return false;
        recent.push(now());
      }
      polite.set({ id: ++id, text });
      return true;
    },
  };
}

/** Renders the two regions once, near the root of the shell. */
export function LiveRegions({ announcer }: { announcer: Announcer }) {
  const polite = useStore(announcer.polite);
  const assertive = useStore(announcer.assertive);
  return (
    <VisuallyHidden>
      <span aria-live="polite" aria-atomic="true" data-testid="live-polite">
        {polite ? <span key={polite.id}>{polite.text}</span> : null}
      </span>
      <span aria-live="assertive" aria-atomic="true" data-testid="live-assertive">
        {assertive ? <span key={assertive.id}>{assertive.text}</span> : null}
      </span>
    </VisuallyHidden>
  );
}
