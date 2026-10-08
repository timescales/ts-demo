// Epoch detail: timeline, root, terms, receipt, public fills,
// settlement, abort notice, the user's own orders and the manual Reveal.
import type { EpochDetail, MarketDetail } from '@timescales/sdk/api';
import {
  b58,
  decodeArtifacts,
  decodeReceipt,
  hex,
  lotsToBase,
  receiptDigest,
} from '@timescales/sdk/core';
import type { Fill } from '@timescales/sdk/core';
import { revealBeaconIx } from '@timescales/sdk/solana';
import { useQuery } from '@tanstack/react-query';
import { useState } from 'react';

import { shortAddress } from '../../components/chrome';
import type { Column, Step } from '../../components/primitives';
import {
  Banner,
  Button,
  CopyHash,
  InlineError,
  PhaseBadge,
  Skeleton,
  Stepper,
  Table,
} from '../../components/primitives';
import { DirectionGlyph } from '../../components/motif';
import { routerLink } from '../../app/links';
import { formatTick, unitsOf } from '../../state/format';
import { useChain, useMarketCheck, useOrders, useWallet } from '../../state/hooks';
import { useRuntime } from '../../state/runtime';
import type { TxStep } from '../../state/tx';
import { failureText, runTraderTx } from '../../state/tx';
import type { Address } from '../../state/types';
import { describeFailure } from '../../state/failures';
import { CheckList } from './CheckList';
import type { ReceiptChecks } from './checks';
import { checkReceipt, checkRoot, checkTerms, readBatch, revealDue } from './checks';
import { epochsCopy } from './copy';
import styles from './Epochs.module.css';

const ORDER = ['open', 'closed', 'committed', 'revealed', 'executing', 'posted', 'settled'];

/** The  timeline as stepper steps. */
export function timelineSteps(d: EpochDetail): Step[] {
  const t = epochsCopy.timeline;
  const b = d.batch;
  const s = d.settlement;
  const reached = Math.max(0, ORDER.indexOf(d.phase));
  const done = [
    true,
    reached >= 1 || b !== null,
    b !== null,
    b?.beacon != null,
    reached >= 4 || d.receiptBytes !== null,
    d.receiptBytes !== null,
    s !== null && s.total > 0 && s.verified >= s.total,
    s !== null && s.total > 0 && s.applied >= s.total,
    d.phase === 'settled',
  ];
  const labels = [
    t.opened,
    t.closed,
    t.committed,
    b?.beaconSlots
      ? `${t.revealed} (${t.revealedSlots(String(b.beaconSlots[0]), String(b.beaconSlots[1]))})`
      : t.revealed,
    t.executing,
    b !== null && d.receiptBytes !== null
      ? `${t.posted} (${t.cosigned(b.quorum.have, b.quorum.need)})`
      : t.posted,
    t.verified(s?.verified ?? 0, s?.total ?? 0),
    t.applied(s?.applied ?? 0, s?.total ?? 0),
    t.settled,
  ];
  const aborted = d.phase === 'aborted' || d.phase === 'aborting';
  const firstOpen = done.findIndex((x) => !x);
  const steps: Step[] = labels.map((label, i) => ({
    id: String(i),
    label,
    status: done[i] ? 'done' : i === firstOpen ? (aborted ? 'error' : 'current') : 'upcoming',
  }));
  if (aborted) {
    const reason = d.abortReason ?? d.abort?.reason ?? 'unknown';
    const stop = firstOpen < 0 ? steps.length - 1 : firstOpen;
    steps[stop] = {
      id: 'aborted',
      label: t.aborted(epochsCopy.abortReasons[reason]),
      status: 'error',
      ...(d.abort?.detail ? { detail: d.abort.detail } : {}),
    };
    return steps.slice(0, stop + 1);
  }
  return steps;
}

/** The receipt as the node describes it, else decoded from its canonical bytes. */
export function receiptSummary(
  d: EpochDetail,
): { executor: string; backend: string; digest: Uint8Array; attestation: Uint8Array } | null {
  if (d.receipt !== null) {
    return {
      executor: d.receipt.executor,
      backend: d.receipt.backend,
      digest: d.receipt.digest,
      attestation: d.receipt.attestation,
    };
  }
  if (d.receiptBytes === null) return null;
  try {
    const r = decodeReceipt(d.receiptBytes);
    return {
      executor: b58.encode(r.executor),
      backend: r.backend,
      digest: receiptDigest(d.receiptBytes),
      attestation: r.attestation,
    };
  } catch {
    return null;
  }
}

function TxList({ detail }: { detail: EpochDetail }) {
  if (detail.txs.length === 0) return null;
  return (
    <ul className={styles.checks}>
      {detail.txs.map((tx) => (
        <li key={`${tx.op}-${tx.signature}`} className={styles.check}>
          <span className={styles.mono}>{tx.op}</span>
          <CopyHash value={tx.signature} label={`${tx.op} ${epochsCopy.timeline.tx}`} />
        </li>
      ))}
    </ul>
  );
}

function FillsTable({
  fills,
  detail,
}: {
  fills: readonly Fill[];
  detail: MarketDetail | undefined;
}) {
  const f = epochsCopy.fills;
  const columns: Column<Fill & { i: number }>[] = [
    {
      key: 'book',
      header: f.book,
      cell: (x) => detail?.books.find((b) => b.book === x.book)?.label ?? String(x.book),
    },
    {
      key: 'side',
      header: f.side,
      cell: (x) => <DirectionGlyph side={x.side === 0 ? 'buy' : 'sell'} />,
    },
    { key: 'role', header: f.role, cell: (x) => (x.role === 0 ? f.maker : f.taker) },
    {
      key: 'quantity',
      header: f.quantity,
      numeric: true,
      cell: (x) => (detail ? lotsToBase(unitsOf(detail), x.quantity) : String(x.quantity)),
    },
    { key: 'price', header: f.price, numeric: true, cell: (x) => formatTick(detail, x.tick) },
    { key: 'trader', header: f.trader, cell: (x) => shortAddress(b58.encode(x.trader)) },
  ];
  return (
    <Table
      caption={f.caption}
      columns={columns}
      rows={fills.map((x, i) => ({ ...x, i }))}
      rowKey={(x) => String(x.i)}
      empty={f.empty}
    />
  );
}

function RevealAction({ market, detail }: { market: Address; detail: EpochDetail }) {
  const runtime = useRuntime();
  const chain = useChain();
  const wallet = useWallet();
  const check = useMarketCheck(market);
  const [step, setStep] = useState<TxStep | null>(null);
  const [result, setResult] = useState<{ ok: boolean; text: string } | null>(null);
  const r = epochsCopy.reveal;
  const b = detail.batch;
  const program = runtime.config.programId;
  if (b === null || b.beacon !== null || chain.slot === null || program === null) return null;
  const d = check?.status === 'ok' ? BigInt(check.ctx.market.beaconDelaySlots) : null;
  if (!revealDue(chain.slot, b.commitSlot, d)) return null;
  const reveal = async () => {
    const w = wallet.wallet;
    if (w === null) return;
    setResult(null);
    const id = `reveal-${market}-${detail.epoch}`;
    const log = (status: 'pending' | 'done' | 'failed') =>
      runtime.activity.put({
        id,
        title: r.activity(String(detail.epoch)),
        status,
        atMs: Date.now(),
      });
    log('pending');
    try {
      const ix = await revealBeaconIx({
        program,
        cranker: w.address,
        market,
        epoch: detail.epoch,
      });
      const out = await runTraderTx({
        rpc: runtime.rpc.get().rpc,
        wallet: w,
        instructions: [ix],
        onStep: setStep,
      });
      if (out.status === 'confirmed') setResult({ ok: true, text: r.done });
      else if (out.status === 'failed')
        setResult({ ok: false, text: r.failed(failureText(out.failure)) });
      else if (out.status === 'expired') setResult({ ok: false, text: r.expired });
      else setResult({ ok: false, text: r.rewritten });
      log(out.status === 'confirmed' ? 'done' : 'failed');
      if (out.status === 'confirmed') await runtime.live.refresh(market);
    } catch (e) {
      log('failed');
      setResult({ ok: false, text: r.failed(describeFailure(e).text) });
    } finally {
      setStep(null);
    }
  };
  return (
    <Banner
      severity="warning"
      title={r.title}
      actions={
        wallet.wallet === null ? (
          <span>{r.connect}</span>
        ) : (
          <Button variant="secondary" size="sm" busy={step !== null} onClick={() => void reveal()}>
            {step === null ? r.action : r.steps[step]}
          </Button>
        )
      }
    >
      <p>{r.body}</p>
      <p>{r.public}</p>
      {result ? result.ok ? <p>{result.text}</p> : <InlineError>{result.text}</InlineError> : null}
    </Banner>
  );
}

function MyOrdersOverlay({ epoch }: { epoch: bigint }) {
  const orders = useOrders();
  const m = epochsCopy.mine;
  if (orders.wallet === null) return <p>{m.noWallet}</p>;
  const mine = orders.records.filter((r) => r.epochs.has(epoch));
  return (
    <>
      <p>{mine.length === 0 ? m.none : m.count(mine.length)}</p>
      {mine.length > 0 ? <p>{routerLink({ href: '/orders', children: m.open })}</p> : null}
    </>
  );
}

export function EpochDetailView({
  market,
  detail,
  marketDetail,
}: {
  market: Address;
  detail: EpochDetail;
  marketDetail: MarketDetail | undefined;
}) {
  const runtime = useRuntime();
  const check = useMarketCheck(market);
  const program = runtime.config.programId;
  const verifiedMarket = check?.status === 'ok' ? check.ctx.market : null;
  const e = epochsCopy;
  const key = [
    detail.market,
    String(detail.epoch),
    detail.phase,
    String(detail.batch?.count ?? -1),
  ];
  const batch = useQuery({
    queryKey: ['batchAccount', ...key],
    queryFn: () =>
      verifiedMarket === null || program === null
        ? Promise.resolve(undefined)
        : readBatch(runtime.rpc.get().rpc, program, market, detail.epoch),
  });
  const root = useQuery({
    queryKey: ['rootCheck', ...key, batch.data === undefined ? 'nochain' : 'chain'],
    queryFn: () => checkRoot({ api: runtime.services.api, detail, batch: batch.data }),
    enabled: !batch.isPending,
  });
  const terms = checkTerms({ detail, market: verifiedMarket, batch: batch.data });
  const [receipt, setReceipt] = useState<ReceiptChecks | 'running' | null>(null);
  const fills = useQuery({
    queryKey: ['publicFills', detail.market, String(detail.epoch)],
    queryFn: async () => {
      const a = await runtime.services.api.artifacts(detail.market, detail.epoch);
      return decodeArtifacts(a.artifactsBytes).fills;
    },
    enabled: detail.artifactsPublic,
  });
  const band = detail.band;
  const summary = receiptSummary(detail);
  return (
    <>
      {detail.phase === 'aborted' || detail.phase === 'aborting' ? (
        <Banner severity="warning" title={e.abort.title}>
          <p>{e.abort.body}</p>
        </Banner>
      ) : null}
      <RevealAction market={market} detail={detail} />
      <div className={styles.panels}>
        <section className={styles.panel} aria-labelledby="epoch-timeline">
          <h2 id="epoch-timeline">{e.timeline.title}</h2>
          <PhaseBadge phase={detail.phase} />
          <Stepper label={e.timeline.label(String(detail.epoch))} steps={timelineSteps(detail)} />
          <TxList detail={detail} />
        </section>
        <section className={styles.panel} aria-labelledby="epoch-root">
          <h2 id="epoch-root">{e.root.title}</h2>
          {detail.batch === null ? (
            <p>{e.root.pending}</p>
          ) : (
            <>
              <CopyHash value={hex.encode(detail.batch.root)} label={e.root.title} />
              <p>{e.root.count(detail.batch.count)}</p>
              {root.data ? (
                <CheckList
                  label={e.root.title}
                  rows={[
                    { id: 'leaves', label: e.root.leaves, result: root.data.leaves },
                    { id: 'chain', label: e.root.chain, result: root.data.chain },
                  ]}
                />
              ) : (
                <Skeleton lines={2} />
              )}
            </>
          )}
        </section>
        <section className={styles.panel} aria-labelledby="epoch-terms">
          <h2 id="epoch-terms">{e.terms.title}</h2>
          <dl className={styles.checks}>
            <div className={styles.check}>
              <dt>{e.terms.band}</dt>
              <dd className={styles.mono}>
                {e.terms.bandValue(
                  formatTick(marketDetail, band.lo),
                  formatTick(marketDetail, band.hi),
                )}
              </dd>
            </div>
          </dl>
          <CopyHash value={hex.encode(detail.termsDigest)} label={e.terms.title} />
          <CheckList
            label={e.terms.title}
            rows={[
              { id: 'announcement', label: e.terms.announcement, result: terms.announcement },
              { id: 'chain', label: e.terms.chain, result: terms.chain },
            ]}
          />
          {verifiedMarket === null ? <p>{e.terms.needsMarket}</p> : null}
        </section>
        <section className={styles.panel} aria-labelledby="epoch-receipt">
          <h2 id="epoch-receipt">{e.receipt.title}</h2>
          {summary === null ? (
            <p>{e.receipt.none}</p>
          ) : (
            <>
              <dl className={styles.checks}>
                <div className={styles.check}>
                  <dt>{e.receipt.executor}</dt>
                  <dd>{shortAddress(summary.executor)}</dd>
                </div>
                <div className={styles.check}>
                  <dt>{e.receipt.backend}</dt>
                  <dd>{summary.backend}</dd>
                </div>
                <div className={styles.check}>
                  <dt>{e.receipt.quorum}</dt>
                  <dd>
                    {detail.batch
                      ? e.receipt.quorumValue(detail.batch.quorum.have, detail.batch.quorum.need)
                      : '-'}
                  </dd>
                </div>
                <div className={styles.check}>
                  <dt>{e.receipt.platform}</dt>
                  <dd>{detail.teePlatform ?? '-'}</dd>
                </div>
              </dl>
              <CopyHash value={hex.encode(summary.digest)} label={e.receipt.digest} />
              <CopyHash value={hex.encode(summary.attestation)} label={e.receipt.attestation} />
              {!detail.artifactsPublic ? <p>{e.receipt.provisional}</p> : null}
              <div>
                <Button
                  variant="secondary"
                  disabled={verifiedMarket === null}
                  busy={receipt === 'running'}
                  onClick={() => {
                    if (verifiedMarket === null || program === null) return;
                    setReceipt('running');
                    void readBatch(runtime.rpc.get().rpc, program, market, detail.epoch)
                      .then((b) =>
                        checkReceipt({
                          api: runtime.services.api,
                          detail,
                          market: verifiedMarket,
                          batch: b,
                        }),
                      )
                      .catch((err: unknown) => ({
                        receipt: {
                          status: 'pending' as const,
                          reason: err instanceof Error ? err.message : 'the check could not run',
                        },
                        quorum: null,
                        artifacts: { status: 'skipped' as const, reason: 'no receipt check' },
                        verified: null,
                      }))
                      .then(setReceipt);
                  }}
                >
                  {receipt === 'running' ? e.receipt.verifying : e.receipt.verify}
                </Button>
              </div>
              {verifiedMarket === null ? <p>{e.terms.needsMarket}</p> : null}
              {receipt !== null && receipt !== 'running' ? (
                <CheckList
                  label={e.receipt.title}
                  rows={[
                    { id: 'v7', label: e.receipt.v7, result: receipt.receipt },
                    {
                      id: 'quorum',
                      label: e.receipt.quorumMet,
                      result:
                        receipt.quorum === null
                          ? { status: 'skipped', reason: 'no receipt check' }
                          : receipt.quorum.met
                            ? { status: 'ok' }
                            : {
                                status: 'pending',
                                reason: e.receipt.quorumValue(
                                  receipt.quorum.have,
                                  receipt.quorum.need,
                                ),
                              },
                    },
                    { id: 'v8', label: e.receipt.v8, result: receipt.artifacts },
                  ]}
                />
              ) : null}
            </>
          )}
        </section>
        <section className={styles.panel} aria-labelledby="epoch-settlement">
          <h2 id="epoch-settlement">{e.settlement.title}</h2>
          {detail.settlement === null ? (
            <p>{e.settlement.none}</p>
          ) : (
            <>
              <p>{e.settlement.status[detail.settlement.status]}</p>
              <p>
                {e.settlement.progress(
                  detail.settlement.verified,
                  detail.settlement.applied,
                  detail.settlement.total,
                )}
              </p>
            </>
          )}
        </section>
        <section className={styles.panel} aria-labelledby="epoch-mine">
          <h2 id="epoch-mine">{e.mine.title}</h2>
          <MyOrdersOverlay epoch={detail.epoch} />
        </section>
      </div>
      <section className={styles.panel} aria-labelledby="epoch-fills">
        <h2 id="epoch-fills">{e.fills.title}</h2>
        {!detail.artifactsPublic ? (
          <p>{e.fills.notPublic}</p>
        ) : fills.data ? (
          <FillsTable fills={fills.data} detail={marketDetail} />
        ) : fills.isError ? (
          <p>{e.loadFailed}</p>
        ) : (
          <Skeleton lines={3} />
        )}
      </section>
    </>
  );
}
