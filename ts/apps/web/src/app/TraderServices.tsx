// Provides the Trade, Orders and Funds screens with their services
// (features/trade/services.tsx), built from the shell's runtime: the same
// API client, server clock, RPC, wallet and order service the shell uses.
// Nothing here constructs SDK services of its own. The order service is the
// runtime's (one leader per wallet).
import type { ReactNode } from 'react';
import { useMemo } from 'react';

import { createFundsPort } from '../features/funds/adapter';
import type { FundsPort } from '../features/funds/port';
import { traderPort } from '../features/trade/adapters';
import type { TraderPort, TraderServices } from '../features/trade/services';
import { TraderServicesProvider } from '../features/trade/services';
import { useOrders, useSession, useWallet } from '../state/hooks';
import { useRuntime } from '../state/runtime';
import { NUMBER_LOCALES, useSettings } from '../state/settings';
import { useStore } from '../state/store';

export function ShellTraderServices({
  connectWallet,
  startSession,
  children,
}: {
  /** Opens the shell's wallet picker. */
  connectWallet: () => void;
  /** Opens the shell's session dialog. */
  startSession: () => void;
  children: ReactNode;
}) {
  const runtime = useRuntime();
  const { api, clock } = runtime.services;
  const program = runtime.config.programId;
  const { rpc } = useStore(runtime.rpc);
  const settings = useSettings();
  const { wallet, address, status } = useWallet();
  const session = useSession();
  const orders = useOrders();

  const connected = status === 'connected' && wallet !== null && address !== null ? wallet : null;
  // The service and journal are the trader's once the session is open and the
  // service started for this wallet. Until then the screens offer to start one.
  const started =
    connected !== null &&
    session.status === 'active' &&
    session.wallet === address &&
    orders.wallet === address &&
    orders.role !== null &&
    orders.service !== null &&
    orders.journal !== null;
  const service = started ? orders.service : null;
  const journal = started ? orders.journal : null;

  const trader = useMemo<TraderPort | null>(
    () =>
      connected === null || program === null
        ? null
        : traderPort({ wallet: connected, rpc, program, orders: service, journal }),
    [connected, rpc, program, service, journal],
  );
  const funds = useMemo<FundsPort | null>(
    () =>
      connected === null || program === null
        ? null
        : createFundsPort({ api, rpc, wallet: connected, program }),
    [api, rpc, connected, program],
  );
  const { announcer } = runtime;
  const announce = useMemo(
    () => (message: string) => void announcer.announce(message, 'own_order'),
    [announcer],
  );
  const numberFormat = NUMBER_LOCALES[settings.numberFormat];
  const ticketShortcuts = settings.shortcuts;
  const maskByDefault = settings.privacyScreen;

  const value = useMemo<TraderServices>(
    () => ({
      api,
      clock,
      numberFormat,
      trader,
      funds,
      announce,
      connectWallet,
      startSession,
      ticketShortcuts,
      maskByDefault,
    }),
    [
      api,
      clock,
      numberFormat,
      trader,
      funds,
      announce,
      connectWallet,
      startSession,
      ticketShortcuts,
      maskByDefault,
    ],
  );
  return <TraderServicesProvider value={value}>{children}</TraderServicesProvider>;
}
