import type { Address } from '@solana/kit';

/** This tab's part in the per-wallet coordination. */
export interface Leadership {
  readonly role: 'leader' | 'follower';
  /** Resolves when this tab holds the lock: at once for a leader, when the leader goes away for a follower. */
  readonly promoted: Promise<void>;
  /** Gives the lock up (or stops waiting for it). */
  release(): void;
}

interface LockManagerLike {
  request(
    name: string,
    options: { ifAvailable?: boolean; signal?: AbortSignal },
    callback: (lock: unknown) => Promise<void>,
  ): Promise<unknown>;
}

export function lockName(wallet: Address): string {
  return `timescales-orders:${wallet}`;
}

function lockManager(): LockManagerLike | null {
  const locks = (globalThis as { navigator?: { locks?: LockManagerLike } }).navigator?.locks;
  return locks !== undefined && typeof locks.request === 'function' ? locks : null;
}

/**
 * Tab leadership per wallet over `navigator.locks` ('timescales-orders:<wallet>').
 * The first tab takes the lock and leads. The others follow and queue for
 * the lock, so one of them takes over when the leader's tab closes. Without
 * Web Locks every tab leads: double submissions are then avoided only by the
 * relay's deduplication of identical bytes.
 */
export async function electLeader(wallet: Address): Promise<Leadership> {
  const locks = lockManager();
  let releaseHeld!: () => void;
  const held = new Promise<void>((resolve) => {
    releaseHeld = resolve;
  });
  if (locks === null) {
    return { role: 'leader', promoted: Promise.resolve(), release: releaseHeld };
  }
  const name = lockName(wallet);
  const leading = await new Promise<boolean>((resolve) => {
    locks
      .request(name, { ifAvailable: true }, async (lock) => {
        resolve(lock !== null);
        if (lock !== null) await held;
      })
      .catch(() => resolve(false));
  });
  if (leading) return { role: 'leader', promoted: Promise.resolve(), release: releaseHeld };

  const waiting = new AbortController();
  const promoted = new Promise<void>((resolve) => {
    locks
      .request(name, { signal: waiting.signal }, async () => {
        resolve();
        await held;
      })
      .catch(() => undefined);
  });
  return {
    role: 'follower',
    promoted,
    release() {
      waiting.abort();
      releaseHeld();
    },
  };
}
