// The global BannerStack's content, in the rows order. The
// stack itself moves critical banners to the top.
import type { PauseReason } from '@timescales/sdk/api';
import { failureRow } from '@timescales/sdk/api';
import type { PendingChange as ChainPendingChange } from '@timescales/sdk/solana';
import { TimescalesError } from '@timescales/sdk';
import { useEffect, useState } from 'react';
import { useNavigate } from 'react-router';

import type { PendingChange, StackBanner } from '../components/chrome';
import {
  GovernanceWatch,
  PersistenceWarning,
  SimulatedBanner,
  VerificationBanner,
  shortAddress,
} from '../components/chrome';
import { componentsCopy } from '../components/copy';
import { Button } from '../components/primitives';
import { formatDuration, formatSlots, SLOT_MS } from '../state/format';
import {
  useChain,
  useKeyCheck,
  useLive,
  useMarketCheck,
  useOrders,
  useWallClock,
  useWallet,
} from '../state/hooks';
import { useCurrent, useInfo, useMarkets, useStatus } from '../state/queries';
import { useRuntime } from '../state/runtime';
import type { Address } from '../state/types';
import type { MarketCheck } from '../state/verification';
import { CROSS_CHECK } from '../state/verification';
import { appCopy } from './copy';
import { downloadJson } from './download';
import { routerLink } from './links';

const copy = appCopy.banners;

/** Below this timelock a non-localnet market has "no effective timelock" (V-13). */
const EFFECTIVE_TIMELOCK_SLOTS = 216_000n;
const STREAM_BANNER_AFTER_MS = 10_000;
const INCONCLUSIVE_BANNER_AFTER_MS = 60_000;
const SKEW_BANNER_MS = 1_000;

const GOVERNANCE_KINDS: Record<ChainPendingChange['kind'], PendingChange['kind']> = {
  set_relay: 'relay',
  set_executors: 'executors',
  set_committee_digest: 'committee',
  set_admin: 'admin',
  set_timings: 'timings',
  set_timelock: 'timelock',
};

function thingOf(check: string): string {
  const key = check.split(' ')[0] ?? check;
  return copy.verificationThing[key] ?? copy.verificationThing.fallback!;
}

/**
 * The global API rows only: network failures, timeouts and server errors
 * (api_unreachable), and responses the SDK could not read. Other API errors
 * (rate limits, pruned data,...) belong to the screen that made the request.
 */
function apiProblem(e: unknown): 'api_unreachable' | 'response_invalid' | null {
  if (e === null || e === undefined) return null;
  const row = e instanceof TimescalesError ? failureRow(e) : 'api_unreachable';
  return row === 'api_unreachable' || row === 'response_invalid' ? row : null;
}

function pauseCopy(reason: PauseReason | undefined): string {
  return copy.pauseReasons[reason ?? 'unknown'] ?? copy.pauseReasons.unknown;
}

export interface ShellBannerOptions {
  market: Address | null;
  /** The Trade screen shows the collapsible simulated-enclave banner. */
  onTrade: boolean;
}

/** The epochs voided in this tab's lifetime, shown once each ("Epoch voided"). */
function useVoidedEpochs(market: Address | null): [string | null, () => void] {
  const runtime = useRuntime();
  const [voided, setVoided] = useState<{ market: Address; epoch: string } | null>(null);
  useEffect(
    () =>
      runtime.live.onEvent((e) => {
        if (e.kind === 'epoch.aborted')
          setVoided({ market: e.market as Address, epoch: String(e.epoch) });
      }),
    [runtime],
  );
  const shown = voided !== null && voided.market === market ? voided.epoch : null;
  return [shown, () => setVoided(null)];
}

export interface ShellBanners {
  banners: StackBanner[];
  onDismiss: (id: string) => void;
}

export function useShellBanners({ market, onTrade }: ShellBannerOptions): ShellBanners {
  const runtime = useRuntime();
  const navigate = useNavigate();
  const check = useMarketCheck(market);
  const key = useKeyCheck(market);
  const current = useCurrent(market);
  const info = useInfo();
  const status = useStatus();
  const live = useLive();
  const chain = useChain();
  const wallet = useWallet();
  const orders = useOrders();
  // Re-evaluates the time-based rows (stream, inconclusive, skew) every second.
  const wallNow = useWallClock();
  const summary = useMarkets().data?.find((m) => m.market === market);
  const [voided, clearVoided] = useVoidedEpochs(market);
  const [simCollapsed, setSimCollapsed] = useState(false);

  const banners: StackBanner[] = [];
  const marketStatus = status.data?.markets.find((m) => m.market === market);

  // Verification failed (any) and the checks with their own rows.
  if (market !== null && check?.status === 'fail') {
    banners.push(...failureBanners(market, check, () => void runtime.verification.recheck(market)));
  }
  if (check?.status === 'inconclusive' && wallNow - check.since > INCONCLUSIVE_BANNER_AFTER_MS) {
    banners.push({
      id: 'verification-inconclusive',
      severity: 'info',
      title: copy.inconclusive(copy.verificationThing.fallback!),
    });
  }
  if (key?.status === 'refused' && check?.status === 'ok') {
    banners.push({
      id: 'key-not-vouched',
      severity: 'warning',
      title: copy.keyNotVouched(String(key.epoch)),
      body: copy.retryLater,
    });
  }

  // The user's own orders: exclusion evidence and failed checks.
  for (const r of orders.records) {
    for (const p of r.epochs.values()) {
      if (p.state.kind === 'excluded') {
        banners.push({
          id: `excluded-${r.id}-${p.epoch}`,
          severity: 'critical',
          title: copy.excluded(String(p.epoch)),
          actions: routerLink({ href: '/orders?tab=evidence', children: copy.exportEvidence }),
        });
      }
    }
    if (r.state.kind === 'verification_failed' && r.state.check.startsWith('V-4')) {
      const epoch = [...r.epochs.keys()].pop();
      banners.push({
        id: `terms-${r.id}`,
        severity: 'critical',
        title: copy.termsMismatch(String(epoch ?? '')),
        actions: routerLink({ href: '/orders?tab=evidence', children: copy.exportEvidence }),
      });
    }
  }

  // Governance (V-13) and the program (V-16).
  if (check?.status === 'ok') {
    const g = governanceOf(check, chain.slot, runtime.config.cluster);
    if (g.changes.length > 0 || g.noEffectiveTimelock || g.recentUpgradeAgo !== null) {
      banners.push({
        id: 'governance',
        severity: 'warning',
        element: (
          <GovernanceWatch
            {...g}
            reviewHref="/privacy"
            fundsHref={`/funds/${market}`}
            renderLink={routerLink}
          />
        ),
      });
    }
  }

  // The simulated enclave: footer label everywhere, collapsible banner on Trade.
  const simulated =
    check?.status === 'ok'
      ? check.ctx.enclaveLabel === 'simulated'
      : info.data?.trust.enclave === 'simulated';
  if (onTrade && simulated) {
    banners.push({
      id: 'simulated',
      severity: 'simulated',
      element: (
        <SimulatedBanner
          privacyHref="/privacy"
          collapsed={simCollapsed}
          onToggle={() => setSimCollapsed((c) => !c)}
          renderLink={routerLink}
        />
      ),
    });
  }

  // The node and the API.
  const i = info.data;
  // The SDK refuses another major version itself (VERSION_UNSUPPORTED).
  const refused =
    info.failureReason instanceof TimescalesError &&
    info.failureReason.code === 'VERSION_UNSUPPORTED';
  if (
    refused ||
    (i !== undefined &&
      (!i.apiVersion.startsWith('1.') || i.protocolVersion !== 1 || i.headerVersion !== 2))
  ) {
    banners.push({
      id: 'version',
      severity: 'critical',
      title: copy.versionMismatch,
      actions: (
        <Button size="sm" variant="secondary" onClick={() => window.location.reload()}>
          {appCopy.reload}
        </Button>
      ),
    });
  }
  // `failureReason` is set while the query still retries: the SDK has
  // already retried the request itself ("fetch fails x3").
  const problem = apiProblem(info.failureReason) ?? apiProblem(status.failureReason);
  if (problem !== null) {
    banners.push({
      id: problem,
      severity: 'warning',
      title: problem === 'api_unreachable' ? copy.apiUnreachable : copy.responseInvalid,
      actions: routerLink({ href: '/status', children: copy.statusPage }),
    });
  }

  // Live updates.
  if (live.stream === 'polling') {
    banners.push({ id: 'stream', severity: 'info', title: copy.streamPolling });
  } else if (live.nonLiveSince !== null && wallNow - live.nonLiveSince > STREAM_BANNER_AFTER_MS) {
    banners.push({
      id: 'stream',
      severity: 'warning',
      title: copy.streamPaused(Math.max(1, live.reconnects)),
    });
  }

  // The user's RPC and clock.
  if (chain.stale) {
    banners.push({
      id: 'rpc',
      severity: 'warning',
      title: copy.rpcStale,
      actions: routerLink({ href: '/settings#network', children: copy.changeRpc }),
    });
  }
  const skew = runtime.services.clock.skewMs();
  if (Math.abs(skew) > SKEW_BANNER_MS) {
    banners.push({
      id: 'skew',
      severity: 'info',
      title: copy.clockSkew((Math.abs(skew) / 1000).toFixed(1)),
    });
  }

  // The market's state.
  const halted = (check?.status === 'ok' && check.ctx.market.halted) || summary?.halted === true;
  const c = current.data;
  if (c?.intake === 'paused' && !halted) {
    banners.push({
      id: 'intake',
      severity: 'warning',
      title: copy.intakePaused(pauseCopy(c.pauseReason)),
    });
  }
  if (halted) {
    banners.push({
      id: 'halted',
      severity: 'critical',
      title: copy.halted,
      actions: routerLink({ href: `/funds/${market}`, children: copy.funds }),
    });
  }
  if (marketStatus?.state === 'fenced' || marketStatus?.state === 'recovering') {
    banners.push({ id: 'recovering', severity: 'critical', title: copy.recovering });
  }
  if (marketStatus !== undefined && marketStatus.settlementLag >= 2) {
    banners.push({ id: 'lag', severity: 'info', title: copy.settlementLag });
  }
  if (voided !== null) {
    banners.push({
      id: `voided-${voided}`,
      severity: 'warning',
      title: copy.voided(voided),
      dismissible: true,
    });
  }

  // The wallet and this device.
  const notice = wallet.notice;
  if (notice !== null) {
    banners.push({
      id: 'wallet',
      severity: 'warning',
      title:
        notice.kind === 'switched'
          ? copy.walletSwitched(shortAddress(notice.address))
          : notice.kind === 'locked'
            ? copy.walletLocked
            : copy.walletDisconnected,
      dismissible: true,
    });
  }
  if (orders.persistence !== null) {
    banners.push({
      id: 'persistence',
      severity: 'warning',
      element: (
        <PersistenceWarning
          problem={orders.persistence}
          onExport={() => void navigate('/settings#local-data')}
          onImport={() => void navigate('/settings#local-data')}
        />
      ),
    });
  }
  if (check?.status === 'unpinned') {
    banners.push({ id: 'unpinned', severity: 'info', title: copy.unpinned });
  }
  return {
    banners,
    onDismiss(id) {
      if (id === 'wallet') runtime.wallets.dismissNotice();
      else if (id.startsWith('voided-')) clearVoided();
    },
  };
}

/**
 * Each critical banner is spoken once by the assertive region when it
 * appears. A banner that goes away and comes back is spoken again.
 */
export function useCriticalAnnouncements(banners: readonly StackBanner[]): void {
  const runtime = useRuntime();
  const [spoken] = useState(() => new Set<string>());
  const critical = banners
    .filter((b) => b.severity === 'critical')
    .map((b) => [b.id, b.spoken ?? ('title' in b && typeof b.title === 'string' ? b.title : '')]);
  const key = JSON.stringify(critical);
  useEffect(() => {
    const now = JSON.parse(key) as [string, string][];
    const ids = new Set(now.map(([id]) => id));
    for (const id of spoken) if (!ids.has(id)) spoken.delete(id);
    for (const [id, text] of now) {
      if (spoken.has(id) || text === '') continue;
      spoken.add(id);
      runtime.announcer.announce(text, 'critical');
    }
  }, [runtime, spoken, key]);
}

function failureBanners(
  market: Address,
  check: Extract<MarketCheck, { status: 'fail' }>,
  recheck: () => void,
): StackBanner[] {
  const exportDetails = () =>
    downloadJson(`verification-${check.check.split(' ')[0]}.json`, {
      market,
      check: check.check,
      reason: check.reason,
      at: new Date(check.atMs).toISOString(),
    });
  if (check.check.startsWith('V-16')) {
    return [
      {
        id: 'program-authority',
        severity: 'critical',
        spoken: componentsCopy.governance.unexpectedAuthority,
        element: (
          <GovernanceWatch
            changes={[]}
            unexpectedAuthority
            reviewHref="/privacy"
            fundsHref={`/funds/${market}`}
            renderLink={routerLink}
          />
        ),
      },
    ];
  }
  if (check.check === CROSS_CHECK) {
    return [
      {
        id: 'cross-check',
        severity: 'critical',
        title: copy.rpcsDisagree,
        body: check.reason,
        actions: (
          <>
            {routerLink({ href: '/settings#network', children: copy.changeRpc })}
            {routerLink({ href: '/status', children: copy.statusPage })}
          </>
        ),
      },
    ];
  }
  if (check.check === 'pins') {
    return [{ id: 'pins', severity: 'critical', title: copy.noGenesis }];
  }
  const thing = check.check.startsWith('V-1')
    ? copy.verificationThing['V-1']!
    : thingOf(check.check);
  return [
    {
      id: 'verification',
      severity: 'critical',
      spoken: componentsCopy.verification.title(thing),
      element: <VerificationBanner thing={thing} onRecheck={recheck} onExport={exportDetails} />,
    },
  ];
}

function governanceOf(
  check: Extract<MarketCheck, { status: 'ok' }>,
  slot: bigint | null,
  cluster: string,
): {
  changes: PendingChange[];
  noEffectiveTimelock: boolean;
  recentUpgradeAgo: string | null;
} {
  const nowSlot = slot ?? check.checkedAtSlot;
  const p = check.pending;
  const changes: PendingChange[] =
    p === null
      ? []
      : [
          {
            kind: GOVERNANCE_KINDS[p.kind],
            eta: formatSlots(p.etaSlot - nowSlot),
            decrease:
              (p.kind === 'set_timelock' && p.decrease) ||
              (p.kind === 'set_executors' && p.quorumDecrease),
          },
        ];
  const upgradedSlots = nowSlot - check.ctx.program.lastDeploySlot;
  return {
    changes,
    noEffectiveTimelock:
      cluster !== 'localnet' && check.ctx.market.timelockSlots < EFFECTIVE_TIMELOCK_SLOTS,
    recentUpgradeAgo: check.recentUpgrade
      ? formatDuration(Number(upgradedSlots > 0n ? upgradedSlots : 0n) * SLOT_MS)
      : null,
  };
}
