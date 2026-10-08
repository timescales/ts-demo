import { useQueries, useQuery, useQueryClient } from '@tanstack/react-query';
import { withdrawStatus } from '@timescales/sdk/solana';
import { useEffect, useState } from 'react';
import { Navigate, useNavigate, useParams } from 'react-router';

import type { MarketOption } from '../../components/chrome';
import { MarketSelector } from '../../components/chrome';
import { Banner, Button, CopyHash, EmptyState, Skeleton } from '../../components/primitives';
import { queryKeys, useCurrentEpoch, useMarkets, useOrderRecords } from '../trade/data';
import { errorInfo } from '../trade/errors';
import { readPref, writePref } from '../trade/prefs';
import type { Address } from '../trade/services';
import { useOptionalServices, useServices, WithQueryClient } from '../trade/services';
import { buckets as bucketsOf } from './balances';
import { BalanceBuckets } from './BalanceBuckets';
import { fundsCopy } from './copy';
import styles from './funds.module.css';
import {
  CancelRequestSheet,
  CloseAccountCard,
  DepositSheet,
  FreezeAuthorityNotice,
  HaltedNotice,
  OpenAccountCard,
  UnlockExplainer,
  WithdrawRequestSheet,
  WithdrawSheet,
} from './FundsSheets';
import type { FundsAction } from './port';
import { NODE_RPC_MISMATCH } from './port';
import type { TxOutcome } from './txRun';

const LAST_MARKET = 'ts.funds.lastMarket';

type SheetKind = FundsAction['kind'];

export default function FundsPage() {
  const services = useOptionalServices();
  useEffect(() => {
    document.title = fundsCopy.title;
  }, []);
  if (services === null) {
    return (
      <div className={styles.page}>
        <h1>{fundsCopy.title}</h1>
        <p>{fundsCopy.noServices}</p>
      </div>
    );
  }
  return (
    <WithQueryClient>
      <FundsRoute />
    </WithQueryClient>
  );
}

function FundsRoute() {
  const { market } = useParams();
  if (market === undefined) return <FundsRedirect />;
  return <FundsScreen market={market as Address} />;
}

/** `/funds` opens the last market used here, else the first one. */
function FundsRedirect() {
  const markets = useMarkets();
  const last = readPref(LAST_MARKET);
  if (last !== null) return <Navigate to={`/funds/${last}`} replace />;
  if (markets.isPending) {
    return (
      <div className={styles.page}>
        <h1>{fundsCopy.title}</h1>
        <Skeleton lines={4} label={fundsCopy.loading} />
      </div>
    );
  }
  const first = markets.data?.[0]?.market;
  if (first === undefined) {
    return (
      <div className={styles.page}>
        <h1>{fundsCopy.title}</h1>
        <p>{fundsCopy.noMarkets}</p>
      </div>
    );
  }
  return <Navigate to={`/funds/${first}`} replace />;
}

interface ActivityItem {
  id: number;
  what: string;
  outcome: TxOutcome;
}

function FundsScreen({ market }: { market: Address }) {
  const services = useServices();
  const { api, funds, trader, numberFormat } = services;
  const navigate = useNavigate();
  const client = useQueryClient();
  const markets = useMarkets();
  const marketList = markets.data ?? [];
  const details = useQueries({
    queries: marketList.map((m) => ({
      queryKey: queryKeys.market(m.market),
      queryFn: () => api.market(m.market),
      staleTime: 30_000,
    })),
  });
  const wallet = trader?.wallet.address ?? ('' as Address);
  const snapshot = useQuery({
    queryKey: queryKeys.funds(market, wallet),
    queryFn: () => funds!.snapshot(market),
    enabled: funds !== null,
  });
  const interval = snapshot.data?.detail.timing.epochIntervalMs;
  const current = useCurrentEpoch(market, interval);
  const records = useOrderRecords();
  const [sheet, setSheet] = useState<SheetKind | null>(null);
  const [activity, setActivity] = useState<ActivityItem[]>([]);

  useEffect(() => {
    writePref(LAST_MARKET, market);
  }, [market]);
  useEffect(() => {
    if (snapshot.data) document.title = fundsCopy.pageTitle(snapshot.data.detail.name);
  }, [snapshot.data]);

  const options: MarketOption[] = marketList.map((m, i) => ({
    address: m.market,
    label: m.name,
    flow: details[i]?.data?.params.flow === 1 ? 'dual_flow' : 'single_book',
  }));
  const selector =
    options.length > 0 ? (
      <MarketSelector
        markets={options}
        value={market}
        onChange={(address) => void navigate(`/funds/${address}`)}
      />
    ) : null;

  const header = (
    <>
      <h1>{fundsCopy.title}</h1>
      {selector}
    </>
  );

  if (trader === null || funds === null) {
    return (
      <div className={styles.page}>
        {header}
        <EmptyState
          title={fundsCopy.noWallet}
          action={
            services.connectWallet ? (
              <Button variant="primary" onClick={services.connectWallet}>
                {fundsCopy.connect}
              </Button>
            ) : null
          }
        />
      </div>
    );
  }

  if (snapshot.isPending) {
    return (
      <div className={styles.page}>
        {header}
        <Skeleton lines={6} label={fundsCopy.loading} />
      </div>
    );
  }
  if (snapshot.data === undefined) {
    const mismatch = errorInfo(snapshot.error).code === NODE_RPC_MISMATCH;
    return (
      <div className={styles.page}>
        {header}
        <Banner
          severity={mismatch ? 'critical' : 'warning'}
          title={mismatch ? fundsCopy.mismatch : fundsCopy.loadFailed}
          actions={<Button onClick={() => void snapshot.refetch()}>{fundsCopy.retry}</Button>}
        />
      </div>
    );
  }

  const s = snapshot.data;
  const b = bucketsOf({
    wallet: s.wallet,
    market: s.market,
    trader: s.trader,
    records,
    band: current.data?.open?.band ?? null,
  });
  const t = s.trader;
  const pendingRequest = t !== null && (t.requestedBase !== 0n || t.requestedQuote !== 0n);
  const status = t ? withdrawStatus(s.market, t) : null;

  const finished = (what: string) => (outcome: TxOutcome) => {
    setActivity((items) => [{ id: Date.now(), what, outcome }, ...items]);
    if (outcome.kind === 'confirmed') {
      void client.invalidateQueries({ queryKey: queryKeys.funds(market, wallet) });
      void client.invalidateQueries({ queryKey: queryKeys.trader(market, wallet) });
    }
  };
  const sheetProps = (kind: SheetKind, what: string) => ({
    open: sheet === kind,
    port: funds,
    market,
    snapshot: s,
    numberFormat,
    onClose: () => setSheet(null),
    onFinished: finished(what),
  });
  const a = fundsCopy.actions;

  return (
    <div className={styles.page}>
      {header}
      <HaltedNotice snapshot={s} />
      <FreezeAuthorityNotice snapshot={s} />
      {t === null ? (
        <OpenAccountCard
          {...sheetProps('open', fundsCopy.open.action)}
          sheetOpen={sheet === 'open'}
          onOpenSheet={() => setSheet('open')}
        />
      ) : null}
      <BalanceBuckets detail={s.detail} buckets={b} numberFormat={numberFormat} />
      {t !== null ? (
        <section className={styles.actionsBar} aria-label={fundsCopy.buckets.title}>
          <Button variant="primary" disabled={s.market.halted} onClick={() => setSheet('deposit')}>
            {a.deposit}
          </Button>
          <Button disabled={pendingRequest} onClick={() => setSheet('request_withdraw')}>
            {a.requestWithdraw}
          </Button>
          {pendingRequest ? (
            <>
              <Button onClick={() => setSheet('cancel_request')}>{a.cancelRequest}</Button>
              <Button
                variant="primary"
                disabled={status?.withdrawable !== true}
                onClick={() => setSheet('withdraw')}
              >
                {a.withdraw}
              </Button>
            </>
          ) : null}
        </section>
      ) : null}
      {pendingRequest && status ? (
        <UnlockExplainer
          snapshot={s}
          base={status.payoutUpTo.base}
          quote={status.payoutUpTo.quote}
          numberFormat={numberFormat}
          unlock={status}
        />
      ) : null}
      {t !== null ? (
        <>
          <DepositSheet {...sheetProps('deposit', a.deposit)} />
          <WithdrawRequestSheet {...sheetProps('request_withdraw', a.requestWithdraw)} />
          <CancelRequestSheet {...sheetProps('cancel_request', a.cancelRequest)} />
          <WithdrawSheet {...sheetProps('withdraw', a.withdraw)} unlockEpoch={b.unlockEpoch} />
          <CloseAccountCard
            {...sheetProps('close', fundsCopy.close.action)}
            sheetOpen={sheet === 'close'}
            onOpenSheet={() => setSheet('close')}
          />
        </>
      ) : null}
      <FundsActivity items={activity} />
    </div>
  );
}

/** This session's transactions. History beyond the session is on chain. */
function FundsActivity({ items }: { items: readonly ActivityItem[] }) {
  const c = fundsCopy.activity;
  return (
    <section aria-labelledby="funds-activity-title" className={styles.section}>
      <h2 id="funds-activity-title">{c.title}</h2>
      {items.length === 0 ? (
        <p className={styles.muted}>{c.empty}</p>
      ) : (
        <ul className={styles.activity}>
          {items.map((item) => (
            <li key={item.id}>
              {c.item(
                item.what,
                item.outcome.kind === 'confirmed' ? fundsCopy.tx.confirmed : item.outcome.message,
              )}
              {item.outcome.kind === 'confirmed' || item.outcome.signature ? (
                <CopyHash
                  value={
                    item.outcome.kind === 'confirmed'
                      ? item.outcome.signature
                      : (item.outcome.signature ?? '')
                  }
                  label={fundsCopy.tx.signature}
                />
              ) : null}
            </li>
          ))}
        </ul>
      )}
    </section>
  );
}
