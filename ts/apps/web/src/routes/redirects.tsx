import { Navigate, useLocation } from 'react-router';

import { ShellFallback } from '../app/Shell';
import { welcomeStore } from '../state/firstRun';
import { useMarketList } from '../state/hooks';
import { useMarkets } from '../state/queries';
import { useStore } from '../state/store';

/** Waits for the market list, then names the default market (or none). */
function useDefaultMarket(): { loading: boolean; market: string | null } {
  const markets = useMarkets();
  const { defaultMarket } = useMarketList();
  return { loading: markets.isPending && defaultMarket === null, market: defaultMarket };
}

/** `/`: Welcome on first run, else Trade on the default market. */
export function RootRedirect() {
  const progress = useStore(welcomeStore);
  const { loading, market } = useDefaultMarket();
  if (!progress.done) return <Navigate to="/welcome" replace />;
  if (loading) return <ShellFallback />;
  return <Navigate to={market === null ? '/welcome' : `/trade/${market}`} replace />;
}

/** `/trade` and `/epochs` without a market: the default one. */
export function TradeRedirect() {
  const { pathname } = useLocation();
  const { loading, market } = useDefaultMarket();
  if (loading) return <ShellFallback />;
  const section = pathname.startsWith('/epochs') ? 'epochs' : 'trade';
  return <Navigate to={market === null ? '/welcome' : `/${section}/${market}`} replace />;
}

/** `/funds` redirects to the last market. */
export function FundsRedirect() {
  const { loading, market } = useDefaultMarket();
  if (loading) return <ShellFallback />;
  return <Navigate to={market === null ? '/welcome' : `/funds/${market}`} replace />;
}
