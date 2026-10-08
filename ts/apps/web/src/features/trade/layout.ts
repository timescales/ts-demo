import { useSyncExternalStore } from 'react';

/**  breakpoints. */
export const NARROW = '(max-width: 599px)';
export const WIDE = '(min-width: 1280px)';

/** Whether a media query matches. Without matchMedia the desktop layout is assumed. */
export function useMediaQuery(query: string, fallback: boolean): boolean {
  return useSyncExternalStore(
    (onChange) => {
      const m = globalThis.matchMedia?.(query);
      if (!m) return () => undefined;
      m.addEventListener('change', onChange);
      return () => m.removeEventListener('change', onChange);
    },
    () => globalThis.matchMedia?.(query).matches ?? fallback,
    () => fallback,
  );
}
