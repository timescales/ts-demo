// Masking of private values on screen (Settings > Privacy). The
// privacy screen sets whether values start masked. "Auto-hide values" masks
// everything again after N idle minutes. Alt+H hides all at once. This is a
// screen mask, not a lock: the values stay in memory.
import { useEffect, useState } from 'react';

import type { Settings } from './settings';
import { settingsStore } from './settings';
import type { Store } from './store';
import { createStore, useStore } from './store';

/** Bumped whenever every value must be masked again. */
export const hideAll: Store<number> = createStore(0);

export function hideAllValues(): void {
  hideAll.set((n) => n + 1);
}

/**
 * The revealed state for one MaskedValue: starts masked when the privacy
 * screen is on, and masks again whenever values are hidden globally.
 */
export function useMasked(): [boolean, (revealed: boolean) => void] {
  const settings = useStore(settingsStore);
  const generation = useStore(hideAll);
  const [state, setState] = useState({ generation, revealed: !settings.privacyScreen });
  const revealed = state.generation === generation ? state.revealed : false;
  return [revealed, (next) => setState({ generation, revealed: next })];
}

function editable(target: EventTarget | null): boolean {
  if (!(target instanceof HTMLElement)) return false;
  return target.isContentEditable || ['INPUT', 'TEXTAREA', 'SELECT'].includes(target.tagName);
}

/** Alt+H hides all values (outside editable fields). Idle time hides them per the setting. */
export function usePrivacyControls(settings: Settings): void {
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.altKey && !e.ctrlKey && !e.metaKey && e.code === 'KeyH' && !editable(e.target)) {
        e.preventDefault();
        hideAllValues();
      }
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, []);

  const minutes = settings.autoHideMinutes;
  useEffect(() => {
    if (minutes === 0) return;
    const idleMs = minutes * 60_000;
    let timer = setTimeout(hideAllValues, idleMs);
    const activity = () => {
      clearTimeout(timer);
      timer = setTimeout(hideAllValues, idleMs);
    };
    const events = ['pointerdown', 'keydown', 'wheel', 'touchstart'] as const;
    for (const ev of events) window.addEventListener(ev, activity, { passive: true });
    return () => {
      clearTimeout(timer);
      for (const ev of events) window.removeEventListener(ev, activity);
    };
  }, [minutes]);
}
