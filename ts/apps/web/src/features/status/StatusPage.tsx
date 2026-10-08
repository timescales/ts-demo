import type { Status } from '@timescales/sdk/api';
import { useQueries } from '@tanstack/react-query';
import { Info as InfoIcon, OctagonAlert, TriangleAlert } from 'lucide-react';

import { shortAddress } from '../../components/chrome';
import { Badge, Banner, Skeleton, Table } from '../../components/primitives';
import type { Column } from '../../components/primitives';
import type { Tone } from '../../components/types';
import pageStyles from '../../app/Page.module.css';
import { routerLink, usePageTitle } from '../../app/links';
import { formatDateTime, formatSlots } from '../../state/format';
import { useChain, useLive, useOrders, useVerification } from '../../state/hooks';
import { marketQuery, useStatus } from '../../state/queries';
import { useRuntime } from '../../state/runtime';
import type { Address } from '../../state/types';
import { appCopy } from '../../app/copy';
import { statusCopy } from './copy';

type Component = Status['components'][number];
type MarketRow = Status['markets'][number];

const TONE: Record<Component['status'], Tone> = {
  ok: 'buy',
  degraded: 'warning',
  down: 'danger',
  unknown: 'neutral',
};

export function componentName(raw: string): string {
  const c = statusCopy.components;
  const [kind, arg] = raw.split(/:(.*)/s, 2) as [string, string | undefined];
  if (arg !== undefined) {
    if (kind === 'enclave') return c.enclave(arg);
    if (kind === 'pipeline') return c.pipeline(shortAddress(arg));
    if (kind === 'epoch_keys') return c.keys(shortAddress(arg));
  }
  return c.names[raw] ?? raw;
}

export function ComponentHealthList({ components }: { components: readonly Component[] }) {
  const c = statusCopy.components;
  const columns: Column<Component>[] = [
    { key: 'name', header: c.name, cell: (r) => componentName(r.name) },
    {
      key: 'state',
      header: c.state,
      cell: (r) => <Badge tone={TONE[r.status]}>{c.health[r.status]}</Badge>,
    },
    { key: 'since', header: c.since, cell: (r) => formatDateTime(r.sinceMs) },
    { key: 'detail', header: c.detail, cell: (r) => r.detail ?? '' },
  ];
  return (
    <Table
      caption={c.caption}
      captionHidden
      columns={columns}
      rows={components}
      rowKey={(r) => r.name}
    />
  );
}

export function IntakeStateTable({ markets }: { markets: readonly MarketRow[] }) {
  const t = statusCopy.intake;
  const reasons = appCopy.banners.pauseReasons;
  const columns: Column<MarketRow>[] = [
    { key: 'market', header: t.market, cell: (r) => shortAddress(r.market) },
    { key: 'state', header: t.state, cell: (r) => t.states[r.state] },
    {
      key: 'intake',
      header: t.intake,
      cell: (r) => (r.intake === 'paused' ? t.paused(reasons[r.pauseReason ?? 'unknown']) : t.open),
    },
    {
      key: 'epoch',
      header: t.epoch,
      numeric: true,
      cell: (r) => (r.currentEpoch === null ? t.none : `#${r.currentEpoch}`),
    },
    { key: 'committed', header: t.committed, numeric: true, cell: (r) => `#${r.lastCommitted}` },
    { key: 'settled', header: t.settled, numeric: true, cell: (r) => `#${r.lastSettled}` },
    { key: 'lag', header: t.lag, numeric: true, cell: (r) => String(r.settlementLag) },
    { key: 'keys', header: t.keys, numeric: true, cell: (r) => String(r.keysReadyAhead) },
  ];
  return (
    <Table
      caption={t.caption}
      captionHidden
      columns={columns}
      rows={markets}
      rowKey={(r) => r.market}
    />
  );
}

interface ClientCheck {
  id: string;
  label: string;
  result: string;
  tone: Tone;
}

export function ClientChecks({ checks }: { checks: readonly ClientCheck[] }) {
  const c = statusCopy.client;
  return (
    <Table
      caption={c.caption}
      captionHidden
      columns={[
        { key: 'check', header: c.check, cell: (r: ClientCheck) => r.label },
        {
          key: 'result',
          header: c.result,
          cell: (r: ClientCheck) => <Badge tone={r.tone}>{r.result}</Badge>,
        },
      ]}
      rows={checks}
      rowKey={(r) => r.id}
    />
  );
}

function useClientChecks(): ClientCheck[] {
  const runtime = useRuntime();
  const chain = useChain();
  const live = useLive();
  const orders = useOrders();
  const c = statusCopy.client;
  const skew = runtime.services.clock.skewMs() / 1000;
  const journal =
    orders.wallet === null
      ? { text: c.journalStates.none, tone: 'neutral' as Tone }
      : orders.persistence === 'full'
        ? { text: c.journalStates.full, tone: 'danger' as Tone }
        : orders.persistence === 'unreadable'
          ? { text: c.journalStates.unreadable, tone: 'warning' as Tone }
          : orders.persistence === 'private_window'
            ? { text: c.journalStates.memory, tone: 'warning' as Tone }
            : orders.persistence === 'not_persistent'
              ? { text: c.journalStates.notPersistent, tone: 'warning' as Tone }
              : { text: c.journalStates.indexeddb, tone: 'buy' as Tone };
  return [
    {
      id: 'rpc',
      label: c.rpc,
      result:
        chain.slot === null ? c.rpcWaiting : chain.stale ? c.rpcStale : c.rpcOk(String(chain.slot)),
      tone: chain.stale ? 'danger' : chain.slot === null ? 'neutral' : 'buy',
    },
    {
      id: 'stream',
      label: c.stream,
      result: c.streamStates[live.stream],
      tone: live.stream === 'live' ? 'buy' : live.stream === 'polling' ? 'warning' : 'danger',
    },
    {
      id: 'clock',
      label: c.clock,
      result: c.clockValue(skew.toFixed(1)),
      tone: Math.abs(skew) > 1 ? 'warning' : 'buy',
    },
    { id: 'journal', label: c.journal, result: journal.text, tone: journal.tone },
  ];
}

function GovernancePanel({ markets }: { markets: readonly Address[] }) {
  const { services } = useRuntime();
  const verification = useVerification();
  const chain = useChain();
  const details = useQueries({ queries: markets.map((m) => marketQuery(services.api, m)) });
  const g = statusCopy.governance;
  const items = markets.flatMap((m, i) => {
    const check = verification.markets.get(m);
    if (check?.status === 'ok') {
      const p = check.pending;
      if (p === null) return [];
      const now = chain.slot ?? check.checkedAtSlot;
      return [
        { market: m, kind: p.kind, eta: formatSlots(p.etaSlot - now), due: p.due, verified: true },
      ];
    }
    const p = details[i]?.data?.pendingChange;
    if (p === null || p === undefined) return [];
    const now = chain.slot ?? details[i]!.data!.chain.contextSlot;
    return [
      { market: m, kind: p.kind, eta: formatSlots(p.etaSlot - now), due: p.due, verified: false },
    ];
  });
  if (items.length === 0) return <p className={pageStyles.muted}>{g.empty}</p>;
  return (
    <ul className={pageStyles.list}>
      {items.map((item) => (
        <li key={item.market} className={pageStyles.card}>
          <p>
            <strong>{shortAddress(item.market)}</strong> - {g.change(g.kinds[item.kind], item.eta)}
          </p>
          {item.due ? <p>{g.due}</p> : null}
          {item.verified ? null : <p className={pageStyles.muted}>{g.unverified}</p>}
        </li>
      ))}
    </ul>
  );
}

const NOTICE_SEVERITY = {
  info: 'info',
  warning: 'warning',
  critical: 'critical',
  unknown: 'info',
} as const;

export default function StatusPage() {
  usePageTitle(statusCopy.title);
  const status = useStatus();
  const checks = useClientChecks();
  const s = status.data;
  const Icon = s?.status === 'ok' ? InfoIcon : s?.status === 'down' ? OctagonAlert : TriangleAlert;
  return (
    <div className={pageStyles.page}>
      <header className={pageStyles.header}>
        <h1>{statusCopy.title}</h1>
        <p className={pageStyles.lede}>{statusCopy.lede}</p>
        {s ? (
          <p className={pageStyles.row}>
            <Icon size={20} aria-hidden="true" />
            {statusCopy.overall[s.status]}
          </p>
        ) : null}
      </header>
      {s?.notice ? (
        <Banner severity={NOTICE_SEVERITY[s.notice.level]} title={statusCopy.notice.title}>
          <p>{s.notice.message}</p>
          <p>{statusCopy.notice.since(formatDateTime(s.notice.sinceMs))}</p>
        </Banner>
      ) : null}
      <section className={pageStyles.section} aria-labelledby="status-client">
        <h2 id="status-client">{statusCopy.client.title}</h2>
        <ClientChecks checks={checks} />
      </section>
      <section className={pageStyles.section} aria-labelledby="status-components">
        <h2 id="status-components">{statusCopy.components.title}</h2>
        {s ? (
          <ComponentHealthList components={s.components} />
        ) : status.failureReason !== null ? (
          <p>{statusCopy.unreachable}</p>
        ) : (
          <Skeleton lines={4} />
        )}
      </section>
      <section className={pageStyles.section} aria-labelledby="status-markets">
        <h2 id="status-markets">{statusCopy.intake.title}</h2>
        {s ? <IntakeStateTable markets={s.markets} /> : <Skeleton lines={2} />}
      </section>
      <section className={pageStyles.section} aria-labelledby="status-governance">
        <h2 id="status-governance">{statusCopy.governance.title}</h2>
        <GovernancePanel markets={(s?.markets ?? []).map((m) => m.market as Address)} />
        <p>{routerLink({ href: '/privacy', children: appCopy.banners.privacy })}</p>
      </section>
    </div>
  );
}
