import type { CurrentEpoch, MarketDetail } from '@timescales/sdk/api';
import type { OrderRecord, PreparedOrder } from '@timescales/sdk/orders';
import type { TraderAccount } from '@timescales/sdk/solana';
import { availableFor } from '@timescales/sdk/solana';
import { TriangleAlert } from 'lucide-react';

import { formatCountdown } from '../../components/chrome';
import { tradeCopy } from './copy';
import { unitsOf } from './data';
import { coverableLots, formatAmounts, reservationOf, reservedByOrders } from './reservation';
import type { NumberFormat } from './services';
import styles from './trade.module.css';
import { atomsToDecimal, localize, lotsToBaseText } from './units';

export interface TicketSummaryProps {
  prepared: PreparedOrder;
  detail: MarketDetail;
  current: CurrentEpoch | undefined;
  now: number;
  account: TraderAccount | null;
  records: readonly OrderRecord[];
  numberFormat: NumberFormat;
}

/** Collateral, fees, worst case and which epochs the order joins (TicketSummary). */
export function TicketSummary({
  prepared,
  detail,
  current,
  now,
  account,
  records,
  numberFormat,
}: TicketSummaryProps) {
  const copy = tradeCopy.summary;
  const u = unitsOf(detail);
  const symbols = { base: detail.baseSymbol, quote: detail.quoteSymbol };
  const quote = (atoms: bigint) =>
    `${localize(atomsToDecimal(atoms, u.quoteDecimals), numberFormat)} ${detail.quoteSymbol}`;
  const open = current?.open ?? null;
  const { from, to, parkedTo } = prepared.epochs;
  const joinsOpen = open !== null && from === open.epoch;
  const roleWord = prepared.draft.role === 0 ? tradeCopy.ticket.maker : tradeCopy.ticket.taker;

  let undercapitalized: string | null = null;
  if (prepared.warnings.includes('undercapitalized') && open !== null) {
    const perLot = reservationOf({ ...prepared.order, quantity: 1n }, detail.params, open.band);
    const others = reservedByOrders(records, prepared.draft.market, detail.params, open.band);
    const available = account ? availableFor(account, from) : { base: 0n, quote: 0n };
    const lots = coverableLots(perLot, available, others, prepared.order.quantity);
    undercapitalized = copy.undercapitalized(
      `${localize(lotsToBaseText(u, lots), numberFormat)} ${detail.baseSymbol}`,
    );
  }

  return (
    <section className={styles.summary} aria-label={copy.title}>
      <dl className={styles.summaryList}>
        <div>
          <dt>{copy.reserved}</dt>
          <dd className={styles.mono}>{formatAmounts(prepared.collateral, u, symbols)}</dd>
        </div>
        <div>
          <dt>{copy.fee(roleWord)}</dt>
          <dd className={styles.mono}>{quote(prepared.feeEstimate)}</dd>
        </div>
        <div>
          <dt>{copy.worst}</dt>
          <dd className={styles.mono}>{quote(prepared.worstNotional)}</dd>
        </div>
      </dl>
      <ul className={styles.summaryNotes}>
        <li>
          {joinsOpen
            ? copy.joins(from.toString(), formatCountdown((open.cutoffMs - now) / 1000))
            : copy.willJoinNext(from.toString())}
        </li>
        {to > from ? (
          <li>
            {copy.restsUntil(to.toString())}
            {parkedTo > from
              ? ` (${copy.queued((from + 1n).toString(), parkedTo.toString())})`
              : ''}
          </li>
        ) : null}
        {to > parkedTo ? <li>{copy.needsApp(parkedTo.toString())}</li> : null}
      </ul>
      {undercapitalized ? (
        <p className={styles.warningText}>
          <TriangleAlert size={16} aria-hidden="true" />
          {undercapitalized}
        </p>
      ) : null}
      {prepared.warnings.includes('second_prompt_needed') ? (
        <p className={styles.warningText}>
          <TriangleAlert size={16} aria-hidden="true" />
          {copy.secondPrompt}
        </p>
      ) : null}
    </section>
  );
}
