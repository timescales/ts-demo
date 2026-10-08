// The trading session of the connected wallet: resume, start with one
// wallet prompt, expiry, eviction by a session started elsewhere, revoke.
import type { Info, ServerClock, TimescalesApi } from '@timescales/sdk/api';
import type { Journal } from '@timescales/sdk/journal';
import type { TraderWallet } from '@timescales/sdk/wallet';
import { TradingSession } from '@timescales/sdk/wallet';
import { TimescalesError } from '@timescales/sdk';

import type { Store } from './store';
import { createStore } from './store';
import type { Address } from './types';

export type SessionStatus = 'none' | 'resuming' | 'opening' | 'active' | 'expired' | 'revoked';

export interface SessionState {
  status: SessionStatus;
  session: TradingSession | null;
  /** The wallet the state belongs to. */
  wallet: Address | null;
  error: TimescalesError | null;
  /** A second wallet signature is needed. The dialog resolves it (never silent). */
  secondPrompt: { resolve: (ok: boolean) => void } | null;
}

export interface SessionController {
  readonly state: Store<SessionState>;
  /** Called when the wallet or its journal changes. Resumes a stored session. */
  attach(wallet: TraderWallet | null, journal: Journal | null): Promise<void>;
  open(a: { market: Address | null; minContextSlot?: bigint }): Promise<TradingSession | null>;
  /** Asks the node whether the session still stands (eviction, expiry). */
  check(): Promise<void>;
  revoke(): Promise<void>;
  answerSecondPrompt(ok: boolean): void;
  dispose(): void;
}

const CHECK_EVERY_MS = 60_000;

function ended(e: unknown): 'revoked' | 'expired' | null {
  if (!(e instanceof TimescalesError) || e.kind !== 'api') return null;
  if (e.code === 'SESSION_REVOKED') return 'revoked';
  if (e.code === 'SESSION_EXPIRED' || e.code === 'SESSION_UNKNOWN') return 'expired';
  return null;
}

export function createSessionController(d: {
  api: TimescalesApi;
  clock: ServerClock;
  info: () => Promise<Info>;
}): SessionController {
  const state = createStore<SessionState>({
    status: 'none',
    session: null,
    wallet: null,
    error: null,
    secondPrompt: null,
  });
  let wallet: TraderWallet | null = null;
  let generation = 0;
  let timer: ReturnType<typeof setInterval> | null = null;
  let expiry: ReturnType<typeof setTimeout> | null = null;

  const clearTimers = () => {
    if (timer !== null) clearInterval(timer);
    if (expiry !== null) clearTimeout(expiry);
    timer = null;
    expiry = null;
  };

  const activate = (session: TradingSession) => {
    clearTimers();
    state.set((s) => ({ ...s, status: 'active', session, error: null }));
    timer = setInterval(() => void controller.check(), CHECK_EVERY_MS);
    const left = session.expiresAtMs - d.clock.now();
    expiry = setTimeout(
      () => {
        if (state.get().session === session) {
          clearTimers();
          state.set((s) => ({ ...s, status: 'expired' }));
        }
      },
      Math.max(0, Math.min(left, 2 ** 31 - 1)),
    );
  };

  const controller: SessionController = {
    state,
    async attach(next, journal) {
      const gen = ++generation;
      clearTimers();
      wallet = next;
      const address = (next?.address as Address | undefined) ?? null;
      state.set({
        status: 'none',
        session: null,
        wallet: address,
        error: null,
        secondPrompt: null,
      });
      if (next === null || journal === null) return;
      state.set((s) => ({ ...s, status: 'resuming' }));
      let resumed: TradingSession | null;
      try {
        resumed = await TradingSession.resume({
          api: d.api,
          wallet: next.address,
          journal,
          clock: d.clock,
        });
      } catch {
        resumed = null;
      }
      if (gen !== generation) return;
      if (resumed === null) state.set((s) => ({ ...s, status: 'none' }));
      else activate(resumed);
    },
    async open({ market, minContextSlot }) {
      const w = wallet;
      if (w === null) return null;
      const gen = generation;
      const before = state.get().status;
      state.set((s) => ({ ...s, status: 'opening', error: null }));
      try {
        const info = await d.info();
        const session = await TradingSession.open({
          api: d.api,
          wallet: w,
          info,
          clock: d.clock,
          market,
          ...(minContextSlot !== undefined ? { minContextSlot } : {}),
          onSecondPrompt: () =>
            new Promise<boolean>((resolve) => {
              state.set((s) => ({ ...s, secondPrompt: { resolve } }));
            }),
        });
        if (gen !== generation || w !== wallet) {
          await session.revoke().catch(() => undefined);
          return null;
        }
        activate(session);
        return session;
      } catch (e) {
        if (gen !== generation) return null;
        const error =
          e instanceof TimescalesError
            ? e
            : new TimescalesError({ kind: 'network', code: 'unknown', cause: e });
        state.set((s) => ({
          ...s,
          status: before === 'opening' || before === 'resuming' ? 'none' : before,
          secondPrompt: null,
          error,
        }));
        return null;
      }
    },
    async check() {
      const session = state.get().session;
      if (session === null) return;
      try {
        await d.api.currentSession(session);
      } catch (e) {
        const why = ended(e);
        if (why !== null && state.get().session === session) {
          clearTimers();
          state.set((s) => ({ ...s, status: why }));
        }
      }
    },
    async revoke() {
      const session = state.get().session;
      clearTimers();
      state.set((s) => ({ ...s, status: 'none', session: null }));
      await session?.revoke().catch(() => undefined);
    },
    answerSecondPrompt(ok) {
      const prompt = state.get().secondPrompt;
      state.set((s) => ({ ...s, secondPrompt: null }));
      prompt?.resolve(ok);
    },
    dispose() {
      ++generation;
      clearTimers();
      state.get().secondPrompt?.resolve(false);
    },
  };
  return controller;
}
