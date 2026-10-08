// Background jobs the ActivityDrawer lists: wallet prompts, sealing,
// submitting, transactions, settlement progress and failures that need the
// user. Entries survive a reload. They never hold amounts, prices, order ids
// or commitments, only what kind of job ran, its epoch and its outcome.
import { brand } from '../design/brand';
import type { Store } from './store';
import { createStore, readLocal, writeLocal } from './store';

export type ActivityStatus = 'pending' | 'done' | 'failed' | 'action';

export interface ActivityEntry {
  id: string;
  title: string;
  status: ActivityStatus;
  detail?: string | undefined;
  atMs: number;
}

export interface ActivityController {
  readonly entries: Store<readonly ActivityEntry[]>;
  readonly open: Store<boolean>;
  /** Adds an entry, or replaces the one with the same id. */
  put(entry: ActivityEntry): void;
  clear(): void;
  setOpen(open: boolean): void;
}

const KEY = `${brand.wordmark}.activity.v1`;
const LIMIT = 50;
const STATUSES: readonly ActivityStatus[] = ['pending', 'done', 'failed', 'action'];

export function parseActivity(raw: string | null): ActivityEntry[] {
  if (raw === null) return [];
  try {
    const v: unknown = JSON.parse(raw);
    if (!Array.isArray(v)) return [];
    return v
      .filter(
        (x): x is ActivityEntry =>
          typeof x === 'object' &&
          x !== null &&
          typeof (x as ActivityEntry).id === 'string' &&
          typeof (x as ActivityEntry).title === 'string' &&
          STATUSES.includes((x as ActivityEntry).status) &&
          typeof (x as ActivityEntry).atMs === 'number',
      )
      .map((x) => ({
        id: x.id,
        title: x.title,
        status: x.status,
        atMs: x.atMs,
        ...(typeof x.detail === 'string' ? { detail: x.detail } : {}),
      }))
      .slice(0, LIMIT);
  } catch {
    return [];
  }
}

export function createActivityController(): ActivityController {
  const entries = createStore<readonly ActivityEntry[]>(parseActivity(readLocal(KEY)));
  const open = createStore(false);
  const save = () => writeLocal(KEY, JSON.stringify(entries.get()));
  return {
    entries,
    open,
    put(entry) {
      entries.set((list) => [entry, ...list.filter((e) => e.id !== entry.id)].slice(0, LIMIT));
      save();
    },
    clear() {
      entries.set([]);
      save();
    },
    setOpen(next) {
      open.set(next);
    },
  };
}
