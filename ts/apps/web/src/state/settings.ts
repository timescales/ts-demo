// Display, accessibility, privacy and network settings (Settings). Kept
// in localStorage: none of it is order data.
import { brand } from '../design/brand';
import type { Store } from './store';
import { createStore, readLocal, useStore, writeLocal } from './store';

export type Theme = 'system' | 'dark' | 'light';
export type Palette = 'standard' | 'cvd';
export type NumberFormat = 'dot' | 'comma' | 'space' | 'plain';

/** Minutes idle before values are masked. 0 turns it off. */
export const AUTO_HIDE_OPTIONS = [0, 1, 5, 15, 30] as const;
export type AutoHideMinutes = (typeof AUTO_HIDE_OPTIONS)[number];

export interface Settings {
  theme: Theme;
  palette: Palette;
  reduceMotion: boolean;
  numberFormat: NumberFormat;
  /** Off by default: market phase changes are not announced. */
  announcePhases: boolean;
  /** Mask private values by default (on by default on small screens). */
  privacyScreen: boolean;
  autoHideMinutes: AutoHideMinutes;
  /** Ids from the build's RPC allowlist. */
  rpcPrimary: string | null;
  rpcCrossCheck: string | null;
  /** Opt-in ticket shortcuts. */
  shortcuts: boolean;
  /** Off by default. Texts never contain amounts. */
  notifications: boolean;
}

/** The separators `parseDecimal` accepts for each declared format. */
export const NUMBER_LOCALES: Record<
  NumberFormat,
  { decimal: '.' | ','; group: ',' | '.' | ' ' | '' }
> = {
  dot: { decimal: '.', group: ',' },
  comma: { decimal: ',', group: '.' },
  space: { decimal: ',', group: ' ' },
  plain: { decimal: '.', group: '' },
};

const KEY = `${brand.wordmark}.settings.v1`;

function smallScreen(): boolean {
  try {
    return globalThis.matchMedia?.('(max-width: 599px)').matches ?? false;
  } catch {
    return false;
  }
}

export function defaultSettings(): Settings {
  return {
    theme: 'dark',
    palette: 'standard',
    reduceMotion: false,
    numberFormat: 'dot',
    announcePhases: false,
    privacyScreen: smallScreen(),
    autoHideMinutes: 0,
    rpcPrimary: null,
    rpcCrossCheck: null,
    shortcuts: false,
    notifications: false,
  };
}

function oneOf<T extends string | number>(v: unknown, options: readonly T[], fallback: T): T {
  return options.includes(v as T) ? (v as T) : fallback;
}

function bool(v: unknown, fallback: boolean): boolean {
  return typeof v === 'boolean' ? v : fallback;
}

function idOrNull(v: unknown): string | null {
  return typeof v === 'string' && v.length > 0 ? v : null;
}

/** Reads stored settings. Unknown or malformed fields fall back to the defaults. */
export function parseSettings(raw: string | null): Settings {
  const d = defaultSettings();
  if (raw === null) return d;
  let v: Record<string, unknown>;
  try {
    const parsed: unknown = JSON.parse(raw);
    if (parsed === null || typeof parsed !== 'object') return d;
    v = parsed as Record<string, unknown>;
  } catch {
    return d;
  }
  return {
    theme: oneOf(v.theme, ['system', 'dark', 'light'] as const, d.theme),
    palette: oneOf(v.palette, ['standard', 'cvd'] as const, d.palette),
    reduceMotion: bool(v.reduceMotion, d.reduceMotion),
    numberFormat: oneOf(
      v.numberFormat,
      ['dot', 'comma', 'space', 'plain'] as const,
      d.numberFormat,
    ),
    announcePhases: bool(v.announcePhases, d.announcePhases),
    privacyScreen: bool(v.privacyScreen, d.privacyScreen),
    autoHideMinutes: oneOf(v.autoHideMinutes, AUTO_HIDE_OPTIONS, d.autoHideMinutes),
    rpcPrimary: idOrNull(v.rpcPrimary),
    rpcCrossCheck: idOrNull(v.rpcCrossCheck),
    shortcuts: bool(v.shortcuts, d.shortcuts),
    notifications: bool(v.notifications, d.notifications),
  };
}

export const settingsStore: Store<Settings> = createStore(parseSettings(readLocal(KEY)));

export function updateSettings(patch: Partial<Settings>): void {
  settingsStore.set((prev) => ({ ...prev, ...patch }));
  writeLocal(KEY, JSON.stringify(settingsStore.get()));
}

/** Forgets stored settings (Settings > Local data > wipe). */
export function resetSettings(): void {
  writeLocal(KEY, null);
  settingsStore.set(defaultSettings());
}

export function useSettings(): Settings {
  return useStore(settingsStore);
}

/**
 * The attributes tokens.css reads on <html>: data-theme (absent = dark),
 * data-palette="cvd" and data-motion="reduce".
 */
export function applyDocumentSettings(s: Settings, root: HTMLElement = document.documentElement) {
  root.setAttribute('data-theme', s.theme);
  if (s.palette === 'cvd') root.setAttribute('data-palette', 'cvd');
  else root.removeAttribute('data-palette');
  if (s.reduceMotion) root.setAttribute('data-motion', 'reduce');
  else root.removeAttribute('data-motion');
}
