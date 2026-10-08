// The routes. Feature screens are lazy chunks at
// features/<name>/<Name>Page.tsx. The shell (chrome, banners, footer) wraps
// them all. No order id, commitment, price or size ever appears in a path.
import type { ComponentType } from 'react';
import type { RouteObject } from 'react-router';

import { NotFound } from '../app/NotFound';
import { RouteError } from '../app/RouteError';
import { Shell, ShellFallback } from '../app/Shell';
import { FundsRedirect, RootRedirect, TradeRedirect } from './redirects';

function page(
  load: () => Promise<{ default: ComponentType }>,
): () => Promise<{ Component: ComponentType }> {
  return async () => ({ Component: (await load()).default });
}

export const ROUTE_PATHS = [
  '/',
  '/welcome',
  '/trade/:market',
  '/orders',
  '/funds',
  '/funds/:market',
  '/epochs/:market',
  '/epochs/:market/:epoch',
  '/verify',
  '/status',
  '/privacy',
  '/settings',
  '*',
] as const;

/** Test-mode builds only. The constant lets production builds drop the gallery chunk. */
const GALLERY = import.meta.env.MODE === 'test';

export function appRoutes(): RouteObject[] {
  const children: RouteObject[] = [
    { index: true, Component: RootRedirect },
    { path: 'welcome', lazy: page(() => import('../features/welcome/WelcomePage')) },
    { path: 'trade', Component: TradeRedirect },
    { path: 'trade/:market', lazy: page(() => import('../features/trade/TradePage')) },
    { path: 'orders', lazy: page(() => import('../features/orders/OrdersPage')) },
    { path: 'funds', Component: FundsRedirect },
    { path: 'funds/:market', lazy: page(() => import('../features/funds/FundsPage')) },
    { path: 'epochs', Component: TradeRedirect },
    { path: 'epochs/:market', lazy: page(() => import('../features/epochs/EpochsPage')) },
    { path: 'epochs/:market/:epoch', lazy: page(() => import('../features/epochs/EpochsPage')) },
    { path: 'verify', lazy: page(() => import('../features/verify/VerifyPage')) },
    { path: 'status', lazy: page(() => import('../features/status/StatusPage')) },
    { path: 'privacy', lazy: page(() => import('../features/privacy/PrivacyPage')) },
    { path: 'settings', lazy: page(() => import('../features/settings/SettingsPage')) },
    { path: '*', Component: NotFound },
  ];
  const routes: RouteObject[] = [
    {
      path: '/',
      Component: Shell,
      HydrateFallback: ShellFallback,
      ErrorBoundary: RouteError,
      children,
    },
  ];
  if (GALLERY) {
    // The component gallery exists only in test-mode builds (browser axe runs).
    routes.unshift({
      path: '/__gallery',
      lazy: async () => ({ Component: await (await import('../app/gallery')).loadGallery() }),
    });
  }
  return routes;
}
