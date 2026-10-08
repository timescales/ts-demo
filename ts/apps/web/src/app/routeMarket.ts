import { useParams } from 'react-router';

import { useMarketList } from '../state/hooks';
import type { Address } from '../state/types';
import { parseAddress } from '../state/types';

/** The market a route names, or the default one for routes without a market. */
export function useRouteMarket(): Address | null {
  const params = useParams();
  const { defaultMarket } = useMarketList();
  return parseAddress(params.market) ?? defaultMarket;
}
