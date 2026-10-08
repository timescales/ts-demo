// One attempt to sign, seal and submit a prepared order. It is started from
// the Seal click, not from an effect, so a re-render or remount never sends
// a second wallet prompt. Closing the stepper aborts it (a signature
// that arrives later is dropped and nothing is sealed).
import type { OrderRecord, PreparedOrder, SubmitStep } from '@timescales/sdk/orders';

import type { OrdersPort } from './services';

export type SealOutcome =
  { kind: 'record'; record: OrderRecord } | { kind: 'error'; error: unknown };

export interface SealState {
  step: SubmitStep | null;
  outcome: SealOutcome | null;
  startedAt: number;
}

export interface SealRun {
  readonly prepared: PreparedOrder;
  subscribe(onChange: () => void): () => void;
  getState(): SealState;
  /** The user closed the stepper. The SDK records the order as abandoned. */
  abandon(): void;
}

export function startSeal(orders: OrdersPort, prepared: PreparedOrder, now: () => number): SealRun {
  const controller = new AbortController();
  const listeners = new Set<() => void>();
  let state: SealState = { step: null, outcome: null, startedAt: now() };
  const set = (next: Partial<SealState>) => {
    state = { ...state, ...next };
    for (const f of [...listeners]) f();
  };
  orders
    .submit(prepared, {
      signal: controller.signal,
      onStep: (step) => {
        if (state.outcome === null) set({ step });
      },
    })
    .then(
      (record) => set({ outcome: { kind: 'record', record } }),
      (error: unknown) => set({ outcome: { kind: 'error', error } }),
    );
  return {
    prepared,
    subscribe(onChange) {
      listeners.add(onChange);
      return () => listeners.delete(onChange);
    },
    getState: () => state,
    abandon() {
      if (state.outcome === null) controller.abort();
    },
  };
}
