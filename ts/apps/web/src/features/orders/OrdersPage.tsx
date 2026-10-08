import { useQueries, useQuery } from '@tanstack/react-query';
import type { MarketDetail } from '@timescales/sdk/api';
import type { OrderRecord } from '@timescales/sdk/orders';
import { useEffect, useMemo, useState } from 'react';

import { Button, EmptyState, Tabs } from '../../components/primitives';
import { tradeCopy } from '../trade/copy';
import { queryKeys, useCurrentEpoch, useNow, useOrderRecords } from '../trade/data';
import { NARROW, useMediaQuery } from '../trade/layout';
import { SealStepper } from '../trade/SealStepper';
import type { SealRun } from '../trade/sealRun';
import { startSeal } from '../trade/sealRun';
import type { Address, TraderServices } from '../trade/services';
import { useOptionalServices, useServices, WithQueryClient } from '../trade/services';
import { cancelEpochFor, replacementDraft } from './actions';
import { ordersCopy } from './copy';
import { EvidencePanel } from './EvidencePanel';
import { FillsTable } from './FillsTable';
import { JournalBanner } from './JournalBanner';
import { ExportDialog, ImportDialog, lastExportAt, ReconcileDialog } from './JournalDialogs';
import { isHistoryRecord, isOpenRecord, newestFirst } from './lists';
import { OrderDrawer } from './OrderDrawer';
import { OrderCards, OrdersTable } from './OrdersTable';
import styles from './orders.module.css';
import { ResealConsentDialog } from './ResealConsentDialog';

/** Batches older than this may be reclaimed on chain (BATCH_RETENTION). */
const RECONCILE_WINDOW = 1024n;

export default function OrdersPage() {
  const services = useOptionalServices();
  useEffect(() => {
    document.title = ordersCopy.title;
  }, []);
  return (
    <div className={styles.page}>
      <h1>{ordersCopy.title}</h1>
      {services === null ? null : (
        <WithQueryClient>
          <OrdersScreen services={services} />
        </WithQueryClient>
      )}
    </div>
  );
}

function OrdersScreen({ services }: { services: TraderServices }) {
  const { trader } = services;
  if (trader === null) {
    return (
      <EmptyState
        title={ordersCopy.noWallet}
        action={
          services.connectWallet ? (
            <Button variant="primary" onClick={services.connectWallet}>
              {ordersCopy.connect}
            </Button>
          ) : null
        }
      />
    );
  }
  if (trader.orders === null || trader.journal === null) {
    return (
      <EmptyState
        title={ordersCopy.noSession}
        action={
          services.startSession ? (
            <Button variant="primary" onClick={services.startSession}>
              {ordersCopy.startSession}
            </Button>
          ) : null
        }
      />
    );
  }
  return <OrdersLists />;
}

function useDetails(markets: readonly Address[]): ReadonlyMap<string, MarketDetail> {
  const { api } = useServices();
  const results = useQueries({
    queries: markets.map((m) => ({
      queryKey: queryKeys.market(m),
      queryFn: () => api.market(m),
      staleTime: 30_000,
    })),
  });
  const map = new Map<string, MarketDetail>();
  results.forEach((r, i) => {
    if (r.data) map.set(markets[i]!, r.data);
  });
  return map;
}

function OrdersLists() {
  const services = useServices();
  const trader = services.trader!;
  const orders = trader.orders!;
  const journal = trader.journal!;
  const { numberFormat, clock } = services;
  const maskByDefault = services.maskByDefault ?? true;
  const records = useOrderRecords();
  const narrow = useMediaQuery(NARROW, false);
  const now = useNow(clock);
  const [tab, setTab] = useState('working');
  const [opened, setOpened] = useState<string | null>(null);
  const [dialog, setDialog] = useState<'export' | 'import' | 'reconcile' | null>(null);
  const [lastExport, setLastExport] = useState(() => lastExportAt(trader.wallet.address));
  const [run, setRun] = useState<SealRun | null>(null);
  const [resealDismissed, setResealDismissed] = useState<ReadonlySet<string>>(() => new Set());
  const [problem, setProblem] = useState<string | null>(null);

  const markets = useMemo(
    () => [...new Set(records.map((r) => r.market))].sort() as Address[],
    [records],
  );
  const details = useDetails(markets);
  const working = records.filter(isOpenRecord).sort(newestFirst);
  const history = records.filter(isHistoryRecord).sort(newestFirst);
  const openedRecord = opened ? (records.find((r) => r.id === opened) ?? null) : null;
  const openedMarket = (openedRecord?.market ?? markets[0] ?? '') as Address;
  const current = useCurrentEpoch(openedMarket, details.get(openedMarket)?.timing.epochIntervalMs);
  const evidence = useQuery({
    queryKey: queryKeys.evidence(trader.wallet.address),
    queryFn: () => journal.listEvidence(),
    enabled: tab === 'evidence',
  });
  const resealing =
    records.find((r) => r.state.kind === 'reseal_needs_consent' && !resealDismissed.has(r.id)) ??
    null;

  const replace = async (record: OrderRecord) => {
    setResealDismissed((prev) => new Set(prev).add(record.id));
    try {
      const ctx = await orders.context(record.market);
      const latest = await services.api.current(record.market);
      if (latest.open === null) throw new Error(tradeCopy.clock.noOpen);
      const draft = replacementDraft(record, latest.open.epoch, ctx.market.params);
      if (draft === null) return;
      setRun(startSeal(orders, orders.prepare(draft), () => clock.now()));
    } catch (e) {
      setProblem(e instanceof Error ? e.message : String(e));
    }
  };

  const listProps = {
    details,
    numberFormat,
    maskByDefault,
    onOpen: (r: OrderRecord) => setOpened(r.id),
  };
  const List = narrow ? OrderCards : OrdersTable;
  const highestEpoch = records.reduce(
    (m, r) => [...r.epochs.keys()].reduce((x, e) => (e > x ? e : x), m),
    0n,
  );

  return (
    <>
      <JournalBanner
        journal={journal}
        lastExportAtMs={lastExport}
        onExport={() => setDialog('export')}
        onImport={() => setDialog('import')}
        onReconcile={() => setDialog('reconcile')}
      />
      {problem ? <p role="alert">{problem}</p> : null}
      <Tabs
        label={ordersCopy.tabs.label}
        value={tab}
        onValueChange={setTab}
        items={[
          {
            value: 'working',
            label: ordersCopy.tabs.working,
            content: (
              <List
                {...listProps}
                caption={ordersCopy.table.working}
                records={working}
                empty={ordersCopy.empty.working}
              />
            ),
          },
          {
            value: 'history',
            label: ordersCopy.tabs.history,
            content: (
              <List
                {...listProps}
                caption={ordersCopy.table.history}
                records={history}
                empty={ordersCopy.empty.history}
              />
            ),
          },
          {
            value: 'fills',
            label: ordersCopy.tabs.fills,
            content: <FillsTable records={records} details={details} numberFormat={numberFormat} />,
          },
          {
            value: 'evidence',
            label: ordersCopy.tabs.evidence,
            content: (
              <EvidencePanel evidence={evidence.data} failed={evidence.isError} details={details} />
            ),
          },
        ]}
      />
      {openedRecord ? (
        <OrderDrawer
          record={openedRecord}
          detail={details.get(openedRecord.market)}
          numberFormat={numberFormat}
          orders={orders}
          journal={journal}
          cancelEpoch={cancelEpochFor(openedRecord, current.data, now)}
          maskByDefault={maskByDefault}
          onClose={() => setOpened(null)}
          onReseal={(r) => void replace(r)}
        />
      ) : null}
      <ExportDialog
        open={dialog === 'export'}
        journal={journal}
        wallet={trader.wallet.address}
        onClose={() => setDialog(null)}
        onExported={setLastExport}
      />
      <ImportDialog open={dialog === 'import'} journal={journal} onClose={() => setDialog(null)} />
      {dialog === 'reconcile' ? (
        <ReconcileDialog
          open
          orders={orders}
          defaultFrom={highestEpoch > RECONCILE_WINDOW ? highestEpoch - RECONCILE_WINDOW : 0n}
          onClose={() => setDialog(null)}
        />
      ) : null}
      {resealing && resealing.state.kind === 'reseal_needs_consent' && run === null ? (
        <ResealConsentDialog
          open
          epoch={resealing.state.epoch}
          onReplace={() => void replace(resealing)}
          onClose={() => setResealDismissed((prev) => new Set(prev).add(resealing.id))}
        />
      ) : null}
      {run ? (
        <SealStepper
          run={run}
          records={records}
          now={() => clock.now()}
          announce={services.announce}
          onClose={() => setRun(null)}
          onRetry={() => {
            try {
              setRun(startSeal(orders, orders.prepare(run.prepared.draft), () => clock.now()));
            } catch (e) {
              setRun(null);
              setProblem(e instanceof Error ? e.message : String(e));
            }
          }}
          onRetrySubmit={async (r) => {
            if (r.body.kind === 'place') await orders.reconcile(r.body.order.validFrom);
          }}
        />
      ) : null}
    </>
  );
}
