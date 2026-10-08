import { useQuery } from '@tanstack/react-query';
import type { BookId } from '@timescales/sdk/core';
import type { OrderRecord, PreparedOrder } from '@timescales/sdk/orders';
import { Plus } from 'lucide-react';
import type { ReactNode } from 'react';
import { useEffect, useId, useState } from 'react';
import { Link, useNavigate, useParams } from 'react-router';

import {
  Banner,
  Button,
  Drawer,
  EmptyState,
  Sheet,
  Skeleton,
  ToggleGroup,
} from '../../components/primitives';
import { cancelEpochFor, replacementDraft } from '../orders/actions';
import { fillsByEpoch } from '../orders/fills';
import { OrderDrawer } from '../orders/OrderDrawer';
import { ResealConsentDialog } from '../orders/ResealConsentDialog';
import { ClearingChart } from './ClearingChart';
import { ClearingTape, TAPE_PAGE } from './ClearingTape';
import { tradeCopy } from './copy';
import {
  queryKeys,
  unitsOf,
  useCurrentEpoch,
  useInfo,
  useMarketDetail,
  useNow,
  useOrderRecords,
  useTraderAccount,
  useVerifiedContext,
} from './data';
import { enclaveLabel } from './DisclosureChips';
import { errorInfo } from './errors';
import { EpochClock } from './EpochClock';
import { NARROW, WIDE, useMediaQuery } from './layout';
import { MarketHeader } from './MarketHeader';
import { MyMarketOrders } from './MyMarketOrders';
import { OrderTicket } from './OrderTicket';
import { SealStepper } from './SealStepper';
import type { SealRun } from './sealRun';
import { startSeal } from './sealRun';
import type { Address } from './services';
import { useOptionalServices, useServices, WithQueryClient } from './services';
import styles from './trade.module.css';

export default function TradePage() {
  const services = useOptionalServices();
  const { market } = useParams();
  useEffect(() => {
    document.title = tradeCopy.title;
  }, []);
  if (services === null || market === undefined) {
    return (
      <div className={styles.page}>
        <h1>{tradeCopy.title}</h1>
        <p>{tradeCopy.noServices}</p>
      </div>
    );
  }
  return (
    <WithQueryClient>
      <TradeScreen market={market as Address} />
    </WithQueryClient>
  );
}

function TradeScreen({ market }: { market: Address }) {
  const services = useServices();
  const { api, clock, numberFormat, trader } = services;
  const navigate = useNavigate();
  const tableId = useId();
  const detailQuery = useMarketDetail(market);
  const detail = detailQuery.data;
  const intervalMs = detail?.timing.epochIntervalMs;
  const info = useInfo();
  const current = useCurrentEpoch(market, intervalMs);
  const account = useTraderAccount(market, intervalMs);
  const context = useVerifiedContext(market);
  const records = useOrderRecords();
  const now = useNow(clock);
  const narrow = useMediaQuery(NARROW, false);
  const wide = useMediaQuery(WIDE, true);

  const [cursors, setCursors] = useState<bigint[]>([]);
  const before = cursors[cursors.length - 1] ?? null;
  const tape = useQuery({
    queryKey: queryKeys.clearing(market, before),
    queryFn: () =>
      api.clearing(market, { ...(before !== null ? { before } : {}), limit: TAPE_PAGE }),
    refetchInterval: before === null && intervalMs ? Math.max(intervalMs, 1000) : false,
  });
  const latest = useQuery({
    queryKey: queryKeys.clearing(market, null),
    queryFn: () => api.clearing(market, { limit: TAPE_PAGE }),
    enabled: before !== null,
  });
  const chartRows = (before === null ? tape.data : latest.data)?.items ?? [];

  const [chartBook, setChartBook] = useState<BookId | null>(null);
  const [draftActive, setDraftActive] = useState(false);
  const [run, setRun] = useState<SealRun | null>(null);
  const [opened, setOpened] = useState<string | null>(null);
  const [ticketOpen, setTicketOpen] = useState(false);
  const [railOpen, setRailOpen] = useState(false);
  const [resealDismissed, setResealDismissed] = useState<ReadonlySet<string>>(() => new Set());
  const [sealProblem, setSealProblem] = useState<string | null>(null);

  useEffect(() => {
    if (detail) document.title = tradeCopy.pageTitle(detail.name);
  }, [detail]);

  if (detailQuery.isPending) {
    return (
      <div className={styles.page}>
        <h1>{tradeCopy.title}</h1>
        <Skeleton lines={6} label={tradeCopy.loading} />
      </div>
    );
  }
  if (detail === undefined) {
    return (
      <div className={styles.page}>
        <h1>{tradeCopy.title}</h1>
        <Banner
          severity="warning"
          title={tradeCopy.marketUnavailable}
          actions={<Button onClick={() => void detailQuery.refetch()}>{tradeCopy.retry}</Button>}
        />
      </div>
    );
  }

  const units = unitsOf(detail);
  const orders = trader?.orders ?? null;
  const open = current.data?.open ?? null;
  const book: BookId = chartBook ?? (detail.params.flow === 1 ? 1 : 0);
  const bookName =
    detail.params.flow === 1
      ? (detail.books.find((b) => b.book === book)?.label ?? '')
      : tradeCopy.header.flow.single;
  const enclave = enclaveLabel(context.data?.enclaveLabel, info.data?.trust.enclave);
  const referenceSource =
    open?.priceCommitment.source ?? info.data?.trust.referencePrice ?? 'unknown';
  const marketRecords = records.filter((r) => r.market === market);
  const ownFillEpochs = new Set(
    marketRecords.flatMap((r) => fillsByEpoch(r).map((f) => f.epoch.toString())),
  );
  const openedRecord = opened ? (records.find((r) => r.id === opened) ?? null) : null;
  const resealing =
    marketRecords.find(
      (r) => r.state.kind === 'reseal_needs_consent' && !resealDismissed.has(r.id),
    ) ?? null;

  const blocked = ((): ReactNode | null => {
    const s = tradeCopy.states;
    if (trader === null) {
      return (
        <EmptyState
          as="p"
          title={s.noWallet}
          action={
            services.connectWallet ? (
              <Button variant="primary" onClick={services.connectWallet}>
                {s.connect}
              </Button>
            ) : null
          }
        />
      );
    }
    if (orders === null) {
      return (
        <EmptyState
          as="p"
          title={s.noSession}
          action={
            services.startSession ? (
              <Button variant="primary" onClick={services.startSession}>
                {s.startSession}
              </Button>
            ) : null
          }
        />
      );
    }
    if (account.isSuccess && account.data === null) {
      return (
        <p>
          {s.noAccount} <Link to={`/funds/${market}`}>{s.openAccount}</Link>
        </p>
      );
    }
    if (detail.halted) return <p>{s.halted}</p>;
    const c = current.data;
    if (c && (c.intake !== 'open' || c.open === null)) {
      const reason = tradeCopy.pauseReasons[c.pauseReason ?? 'unknown'];
      const resume =
        c.pauseReason === 'pipeline_backlog' || c.pauseReason === 'epoch_key_unavailable'
          ? s.resumeNextEpoch
          : s.resumeUnknown;
      return <p>{s.paused(reason, resume)}</p>;
    }
    if (context.isError) {
      return (
        <Banner
          severity="critical"
          title={s.unverified(errorInfo(context.error).code)}
          actions={<Button onClick={() => void context.refetch()}>{s.recheck}</Button>}
        />
      );
    }
    if (context.isPending) return <p>{s.checking}</p>;
    return null;
  })();

  const onSeal = (prepared: PreparedOrder) => {
    if (orders === null) return;
    setTicketOpen(false);
    setRun(startSeal(orders, prepared, () => clock.now()));
  };

  const retry = () => {
    if (orders === null || run === null) return;
    try {
      setRun(startSeal(orders, orders.prepare(run.prepared.draft), () => clock.now()));
    } catch (e) {
      setRun(null);
      setSealProblem(e instanceof Error ? e.message : String(e));
    }
  };

  const retrySubmit = async (record: OrderRecord) => {
    if (orders === null || record.body.kind !== 'place') return;
    await orders.reconcile(record.body.order.validFrom);
  };

  const replace = (record: OrderRecord) => {
    setResealDismissed((prev) => new Set(prev).add(record.id));
    if (orders === null || open === null) return;
    const draft = replacementDraft(record, open.epoch, detail.params);
    if (draft === null) return;
    try {
      setRun(startSeal(orders, orders.prepare(draft), () => clock.now()));
    } catch (e) {
      setSealProblem(e instanceof Error ? e.message : String(e));
    }
  };

  const ticket = (
    <OrderTicket
      market={market}
      detail={detail}
      current={current.data}
      now={now}
      account={account.data?.value ?? null}
      orders={context.isSuccess ? orders : null}
      records={records}
      numberFormat={numberFormat}
      lastClearing={chartRows[0]?.clearing ?? detail.lastClearing}
      enclave={enclave}
      blocked={blocked}
      onSeal={onSeal}
      onDraftActiveChange={setDraftActive}
      shortcuts={services.ticketShortcuts}
    />
  );

  const myOrders = (
    <MyMarketOrders
      detail={detail}
      records={records}
      numberFormat={numberFormat}
      maskByDefault={services.maskByDefault ?? true}
      onOpen={(r) => setOpened(r.id)}
      allOrdersHref="/orders"
    />
  );

  const items = tape.data?.items ?? [];
  return (
    <div className={styles.page}>
      <MarketHeader
        detail={detail}
        band={open?.band ?? null}
        referenceSource={referenceSource}
        numberFormat={numberFormat}
      />
      <EpochClock
        current={current.data}
        intervalMs={detail.timing.epochIntervalMs}
        now={now}
        draftActive={draftActive}
        announce={services.announce}
      />
      {sealProblem ? (
        <Banner severity="warning" title={sealProblem} onDismiss={() => setSealProblem(null)} />
      ) : null}
      <div className={styles.columns}>
        {narrow ? null : <div className={styles.ticketColumn}>{ticket}</div>}
        <div className={styles.mainColumn}>
          {detail.params.flow === 1 ? (
            <ToggleGroup<string>
              label={tradeCopy.chart.book}
              value={String(book)}
              onValueChange={(v) => setChartBook(Number(v) as BookId)}
              options={detail.books.map((b) => ({ value: String(b.book), label: b.label }))}
            />
          ) : null}
          {tape.isPending ? (
            <Skeleton lines={5} label={tradeCopy.loading} />
          ) : (
            <ClearingChart
              pair={detail.name}
              bookLabel={bookName}
              book={book}
              rows={chartRows}
              units={units}
              numberFormat={numberFormat}
              ownFillEpochs={ownFillEpochs}
              onOpenEpoch={(epoch) => void navigate(`/epochs/${market}/${epoch}`)}
              tableId={tableId}
            />
          )}
          {tape.isError ? (
            <Banner
              severity="warning"
              title={tradeCopy.tape.loadFailed}
              actions={<Button onClick={() => void tape.refetch()}>{tradeCopy.retry}</Button>}
            />
          ) : (
            <ClearingTape
              id={tableId}
              detail={detail}
              rows={items}
              numberFormat={numberFormat}
              hasOlder={tape.data?.nextBefore != null}
              hasNewer={cursors.length > 0}
              onOlder={() => {
                const next = tape.data?.nextBefore;
                if (next != null) setCursors((c) => [...c, next]);
              }}
              onNewest={() => setCursors([])}
            />
          )}
        </div>
        {wide ? <aside className={styles.rail}>{myOrders}</aside> : null}
      </div>
      {wide ? null : (
        <Button className={styles.railButton} onClick={() => setRailOpen(true)}>
          {tradeCopy.myOrders.openRail}
        </Button>
      )}
      {narrow ? (
        <Button
          variant="primary"
          className={styles.fab}
          icon={<Plus size={20} aria-hidden="true" />}
          onClick={() => setTicketOpen(true)}
        >
          {tradeCopy.ticket.title}
        </Button>
      ) : null}
      {narrow ? (
        <Sheet
          open={ticketOpen}
          onClose={() => setTicketOpen(false)}
          title={tradeCopy.ticket.title}
        >
          {ticket}
        </Sheet>
      ) : null}
      {wide ? null : (
        <Drawer open={railOpen} onClose={() => setRailOpen(false)} title={tradeCopy.myOrders.title}>
          {myOrders}
        </Drawer>
      )}
      {run && orders ? (
        <SealStepper
          run={run}
          records={records}
          now={() => clock.now()}
          announce={services.announce}
          onClose={() => setRun(null)}
          onRetry={retry}
          onRetrySubmit={retrySubmit}
        />
      ) : null}
      {openedRecord ? (
        <OrderDrawer
          record={openedRecord}
          detail={detail}
          numberFormat={numberFormat}
          orders={orders}
          journal={trader?.journal ?? null}
          cancelEpoch={cancelEpochFor(openedRecord, current.data, now)}
          maskByDefault={services.maskByDefault ?? true}
          onClose={() => setOpened(null)}
          onReseal={replace}
        />
      ) : null}
      {resealing && resealing.state.kind === 'reseal_needs_consent' && run === null ? (
        <ResealConsentDialog
          open
          epoch={resealing.state.epoch}
          onReplace={() => replace(resealing)}
          onClose={() => setResealDismissed((prev) => new Set(prev).add(resealing.id))}
        />
      ) : null}
    </div>
  );
}
