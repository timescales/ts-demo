import { WalletError, abandonable } from './port.js';

/**
 * Serialises wallet requests so a wallet never sees two prompts at once.
 * A caller that aborts while queued leaves the queue without prompting. One
 * that aborts while its prompt is open releases the queue at once, because
 * a wallet that never answers must not block every later request.
 */
export class WalletMutex {
  private tail: Promise<void> = Promise.resolve();

  run<T>(f: () => Promise<T>, signal?: AbortSignal): Promise<T> {
    const before = this.tail;
    let release!: () => void;
    const done = new Promise<void>((r) => {
      release = r;
    });
    this.tail = before.then(() => done);
    return (async () => {
      try {
        await abandonable(before, signal);
        if (signal?.aborted === true) throw new WalletError('abandoned');
        return await abandonable(f(), signal);
      } finally {
        release();
      }
    })();
  }
}
