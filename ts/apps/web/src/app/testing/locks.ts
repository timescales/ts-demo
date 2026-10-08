// Test-only: happy-dom exposes navigator.locks but never grants a lock, so
// tests that start the order service install this in-memory Web Locks
// manager (exclusive locks, `ifAvailable`, abortable waits, FIFO queue).
type Callback = (lock: { name: string } | null) => Promise<unknown>;

interface Waiter {
  run(): void;
  signal: AbortSignal | undefined;
}

export function installLocks(): () => void {
  const held = new Set<string>();
  const queues = new Map<string, Waiter[]>();

  const release = (name: string) => {
    held.delete(name);
    const q = queues.get(name) ?? [];
    while (q.length > 0) {
      const next = q.shift()!;
      if (next.signal?.aborted) continue;
      next.run();
      return;
    }
  };

  const manager = {
    request(
      name: string,
      options: { ifAvailable?: boolean; signal?: AbortSignal },
      callback: Callback,
    ): Promise<unknown> {
      return new Promise((resolve, reject) => {
        const grant = () => {
          held.add(name);
          void Promise.resolve()
            .then(() => callback({ name }))
            .then(resolve, reject)
            .finally(() => release(name));
        };
        if (!held.has(name)) {
          grant();
          return;
        }
        if (options.ifAvailable) {
          void Promise.resolve()
            .then(() => callback(null))
            .then(resolve, reject);
          return;
        }
        const waiter: Waiter = { run: grant, signal: options.signal };
        options.signal?.addEventListener('abort', () => {
          const q = queues.get(name) ?? [];
          const i = q.indexOf(waiter);
          if (i >= 0) q.splice(i, 1);
          reject(new DOMException('aborted', 'AbortError'));
        });
        queues.set(name, [...(queues.get(name) ?? []), waiter]);
      });
    },
  };
  const before = Object.getOwnPropertyDescriptor(navigator, 'locks');
  Object.defineProperty(navigator, 'locks', { value: manager, configurable: true });
  return () => {
    if (before) Object.defineProperty(navigator, 'locks', before);
    else delete (navigator as { locks?: unknown }).locks;
  };
}
