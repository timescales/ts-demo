// The first-run flag (`/`): the app opens on /welcome until the user has
// finished or left onboarding once. Welcome's step progress lives with it.
import { brand } from '../design/brand';
import type { Store } from './store';
import { createStore, readLocal, writeLocal } from './store';

const KEY = `${brand.wordmark}.welcome.v1`;

export interface WelcomeProgress {
  /** The user finished or skipped onboarding at least once. */
  done: boolean;
  understoodPublic: boolean;
  market: string | null;
}

function parse(raw: string | null): WelcomeProgress {
  const empty: WelcomeProgress = { done: false, understoodPublic: false, market: null };
  if (raw === null) return empty;
  try {
    const v = JSON.parse(raw) as Partial<WelcomeProgress>;
    return {
      done: v.done === true,
      understoodPublic: v.understoodPublic === true,
      market: typeof v.market === 'string' ? v.market : null,
    };
  } catch {
    return empty;
  }
}

export const welcomeStore: Store<WelcomeProgress> = createStore(parse(readLocal(KEY)));

export function updateWelcome(patch: Partial<WelcomeProgress>): void {
  welcomeStore.set((p) => ({ ...p, ...patch }));
  writeLocal(KEY, JSON.stringify(welcomeStore.get()));
}

export function resetWelcome(): void {
  writeLocal(KEY, null);
  welcomeStore.set(parse(null));
}
