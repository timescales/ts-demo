// The live status bar, first item pinned: the enclave label from the
// verified trust labels (V-14), never more than the operator-reported value.
import type { Info, Status } from '@timescales/sdk/api';
import type { StreamState } from '@timescales/sdk/api';

import type { EnclaveTrust, Health, StatusFooterProps } from '../components/chrome';
import { StatusFooter } from '../components/chrome';
import { useChain, useLive, useMarketCheck } from '../state/hooks';
import { useInfo, useStatus } from '../state/queries';
import { useRuntime } from '../state/runtime';
import type { Address } from '../state/types';
import type { MarketCheck } from '../state/verification';
import { routerLink } from './links';

/**
 * TDX is shown as required by the key committee only after V-14 passed. An
 * operator claim of TDX stays "operator-reported", and anything not known
 * yet is shown as simulated, which never overstates privacy.
 */
export function enclaveTrust(check: MarketCheck | undefined, info: Info | undefined): EnclaveTrust {
  if (check?.status === 'ok') {
    if (check.ctx.enclaveLabel === 'intel_tdx_vouched') return 'tdx_vouched';
    if (check.ctx.enclaveLabel === 'simulated') return 'simulated';
  }
  return info?.trust.enclave === 'intel_tdx' ? 'tdx_reported' : 'simulated';
}

export function streamHealth(s: StreamState): StatusFooterProps['stream'] {
  if (s === 'live') return 'live';
  if (s === 'polling') return 'polling';
  return 'reconnecting';
}

/**
 * A failed request counts at once, while the query still retries: the SDK
 * has already retried it ("fetch fails x3").
 */
export function apiHealth(
  info: { failureReason: unknown },
  status: { data?: Status | undefined; failureReason: unknown },
): Health {
  if (info.failureReason !== null || status.failureReason !== null) return 'down';
  if (status.data?.status === 'degraded' || status.data?.status === 'recovering') return 'degraded';
  if (status.data?.status === 'down') return 'down';
  return 'ok';
}

export function Footer({ market }: { market: Address | null }) {
  const { config } = useRuntime();
  const info = useInfo();
  const status = useStatus();
  const check = useMarketCheck(market);
  const chain = useChain();
  const live = useLive();
  return (
    <StatusFooter
      enclave={enclaveTrust(check, info.data)}
      cluster={config.cluster}
      slot={chain.slot}
      rpc={chain.health}
      apiVersion={info.data?.apiVersion ?? '1'}
      api={apiHealth(info, status)}
      stream={streamHealth(live.stream)}
      reference={info.data?.trust.referencePrice === 'modelled_tlsnotary' ? 'modelled' : 'operator'}
      links={{
        status: '/status',
        privacy: '/privacy',
        verify: '/verify',
        settings: '/settings',
        help: '/welcome',
      }}
      renderLink={routerLink}
    />
  );
}
