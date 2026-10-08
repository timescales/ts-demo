import type { Clearing, CurrentEpoch, MarketDetail } from '@timescales/sdk/api';
import type { BookId, Role, Side } from '@timescales/sdk/core';
import { bookFor } from '@timescales/sdk/core';
import type { OrderDraft, OrderRecord, PreparedOrder } from '@timescales/sdk/orders';
import type { TraderAccount } from '@timescales/sdk/solana';
import { availableFor } from '@timescales/sdk/solana';
import { OctagonAlert, TriangleAlert } from 'lucide-react';
import type { FormEvent, KeyboardEvent as ReactKeyboardEvent, ReactNode } from 'react';
import { useEffect, useId, useMemo, useRef, useState } from 'react';

import { DirectionGlyph } from '../../components/motif';
import { Button, NumberField, ToggleGroup } from '../../components/primitives';
import { tradeCopy } from './copy';
import { unitsOf } from './data';
import { DisclosureChips, type EnclaveLabel } from './DisclosureChips';
import { DEFAULT_SIGN_BUDGET_MS, durationPresets } from './presets';
import { lastLifetime, lastRole, rememberLifetime, rememberRole } from './prefs';
import { selfTradeConflicts } from './selfTrade';
import type { Address, NumberFormat, OrdersPort } from './services';
import { TicketSummary } from './TicketSummary';
import styles from './trade.module.css';
import {
  atomsToDecimal,
  clearingTick,
  deviationPercent,
  localize,
  lotsForShare,
  lotsToBaseText,
  maxLots,
  parseLimit,
  parseQuantity,
  priceOf,
  reserveTick,
} from './units';

export interface OrderTicketProps {
  market: Address;
  detail: MarketDetail;
  current: CurrentEpoch | undefined;
  now: number;
  account: TraderAccount | null;
  orders: OrdersPort | null;
  records: readonly OrderRecord[];
  numberFormat: NumberFormat;
  lastClearing: readonly Clearing[] | null;
  enclave: EnclaveLabel;
  /** Why the ticket cannot seal right now (no wallet, paused, unverified...). Fields stay usable. */
  blocked: ReactNode | null;
  onSeal: (prepared: PreparedOrder) => void;
  onDraftActiveChange?: ((active: boolean) => void) | undefined;
  /** Opt-in ticket shortcuts (B/S side, M/T role, Enter review, Ctrl/⌘+Enter seal). */
  shortcuts?: boolean | undefined;
}

const SHARES = [25, 50, 100] as const;

function bookLabel(detail: MarketDetail, book: BookId): string {
  return detail.books.find((b) => b.book === book)?.label ?? tradeCopy.header.flow.single;
}

function isEditable(target: EventTarget | null): boolean {
  if (!(target instanceof HTMLElement)) return false;
  return (
    target.isContentEditable ||
    target instanceof HTMLInputElement ||
    target instanceof HTMLTextAreaElement ||
    target instanceof HTMLSelectElement
  );
}

export function OrderTicket({
  market,
  detail,
  current,
  now,
  account,
  orders,
  records,
  numberFormat,
  lastClearing,
  enclave,
  blocked,
  onSeal,
  onDraftActiveChange,
  shortcuts = false,
}: OrderTicketProps) {
  const copy = tradeCopy.ticket;
  const u = unitsOf(detail);
  const params = detail.params;
  const intervalMs = detail.timing.epochIntervalMs;
  const band = current?.open?.band ?? null;

  const [side, setSide] = useState<Side>(0);
  const [role, setRole] = useState<Role>(() => lastRole());
  const [kind, setKind] = useState<0 | 1>(0);
  const [quantityText, setQuantityText] = useState('');
  const [limitText, setLimitText] = useState('');
  const [lifetime, setLifetime] = useState<number | null>(() => lastLifetime());
  const [dirty, setDirty] = useState(false);
  const [focused, setFocused] = useState(false);
  const [reviewed, setReviewed] = useState(false);
  const [signBudgetMs, setSignBudgetMs] = useState(DEFAULT_SIGN_BUDGET_MS);
  const errorSummaryRef = useRef<HTMLDivElement>(null);
  const sealRef = useRef<HTMLButtonElement>(null);
  const ids = { quantity: useId(), limit: useId(), summary: useId() };

  const active = dirty || focused;
  useEffect(() => {
    onDraftActiveChange?.(active);
  }, [active, onDraftActiveChange]);

  const presets = useMemo(
    () => durationPresets(params, intervalMs, signBudgetMs),
    [params, intervalMs, signBudgetMs],
  );
  const chosenLifetime =
    presets.find((p) => p.epochs === lifetime)?.epochs ??
    presets.find((p) => p.epochs === 2)?.epochs ??
    presets[0]?.epochs ??
    1;

  const book = bookFor(params.flow, side, role);
  const quantity = parseQuantity(quantityText, numberFormat, u);
  const limit = kind === 0 ? parseLimit(limitText, numberFormat, u, side) : null;
  const price = (tick: bigint) => localize(priceOf(u, tick), numberFormat);
  const baseSymbol = detail.baseSymbol;
  const quoteSymbol = detail.quoteSymbol;

  const conflicts = selfTradeConflicts(records, { market, flow: params.flow, book, side });
  const fromEpoch = current?.open?.epoch ?? null;
  const available = account && fromEpoch !== null ? availableFor(account, fromEpoch) : null;
  const lastTick = clearingTick(lastClearing, book);
  const outsideBand =
    limit?.ok === true && band !== null
      ? side === 0
        ? limit.tick < band.lo
        : limit.tick > band.hi
      : false;

  const quantityError = quantity.ok
    ? null
    : quantity.error === 'too_large'
      ? copy.errors.quantity.too_large(`${lotsToBaseText(u, maxLots(params))} ${baseSymbol}`)
      : copy.errors.quantity[quantity.error];
  const limitError = limit === null || limit.ok ? null : copy.errors.price[limit.error];
  const showQuantityError = (reviewed || quantityText !== '') && quantityError !== null;
  const showLimitError = (reviewed || limitText !== '') && limitError !== null;

  const draft: OrderDraft | null =
    quantity.ok && (limit === null || limit.ok)
      ? {
          market,
          side,
          role,
          kind,
          ...(limit?.ok ? { limitTick: limit.tick } : {}),
          quantityLots: quantity.lots,
          lifetimeEpochs: chosenLifetime,
        }
      : null;

  let prepared: PreparedOrder | null = null;
  let prepareError: string | null = null;
  if (draft !== null && orders !== null) {
    try {
      prepared = orders.prepare(draft);
    } catch (e) {
      prepareError = e instanceof Error ? e.message : String(e);
    }
  }
  // The presets follow the signing budget the service measured. Adjusting
  // state during render settles in one extra pass without an effect.
  const budgetSeen = prepared?.signBudgetMs;
  if (budgetSeen !== undefined && budgetSeen !== signBudgetMs) setSignBudgetMs(budgetSeen);

  const selfTrade = conflicts.length > 0 || prepared?.blockers.includes('self_trade') === true;
  const canSeal =
    prepared !== null && blocked === null && !selfTrade && prepared.blockers.length === 0;

  const edit = (f: () => void) => {
    f();
    setDirty(true);
  };

  const fillShare = (percent: 25 | 50 | 100) => {
    if (available === null || band === null) return;
    const tick = reserveTick(band, side, kind, limit?.ok ? limit.tick : band.hi);
    const lots = lotsForShare({
      params,
      side,
      feeBps: role === 0 ? params.makerFeeBps : params.takerFeeBps,
      available,
      tick,
      percent,
    });
    edit(() => setQuantityText(localize(lotsToBaseText(u, lots), { ...numberFormat, group: '' })));
  };

  const errorCount = (quantityError ? 1 : 0) + (limitError ? 1 : 0);

  const review = (event?: FormEvent) => {
    event?.preventDefault();
    setReviewed(true);
    if (errorCount > 0) {
      errorSummaryRef.current?.focus();
      return;
    }
    sealRef.current?.focus();
  };

  const seal = () => {
    setReviewed(true);
    if (!canSeal || draft === null || orders === null) return;
    // Prepare again at the click: the signing budget and the open epoch move with time.
    try {
      onSeal(orders.prepare(draft));
    } catch {
      // The ticket already shows why the draft cannot be prepared.
    }
  };

  const onKeyDown = (event: ReactKeyboardEvent<HTMLFormElement>) => {
    if (!shortcuts || event.altKey) return;
    const mod = event.ctrlKey || event.metaKey;
    if (event.key === 'Enter' && mod) {
      event.preventDefault();
      seal();
      return;
    }
    if (mod || isEditable(event.target)) return;
    const key = event.key.toLowerCase();
    if (key === 'b') edit(() => setSide(0));
    else if (key === 's') edit(() => setSide(1));
    else if (key === 'm') edit(() => setRole(0));
    else if (key === 't') edit(() => setRole(1));
    else return;
    event.preventDefault();
  };

  const roleExplainer =
    params.flow === 1
      ? copy.roleDual(bookLabel(detail, book))
      : copy.roleSingle(params.makerFeeBps, params.takerFeeBps);

  return (
    <form
      className={styles.ticket}
      aria-labelledby={`${ids.summary}-title`}
      noValidate
      onSubmit={review}
      onKeyDown={onKeyDown}
      onFocus={() => setFocused(true)}
      onBlur={(event) => {
        if (!event.currentTarget.contains(event.relatedTarget as Node | null)) setFocused(false);
      }}
    >
      <h2 id={`${ids.summary}-title`}>{copy.title}</h2>

      {reviewed && errorCount > 0 ? (
        <div ref={errorSummaryRef} tabIndex={-1} role="alert" className={styles.errorSummary}>
          <p>{copy.errors.summary(errorCount)}</p>
          <ul>
            {quantityError ? (
              <li>
                <a href={`#${ids.quantity}`}>
                  {copy.quantity}: {quantityError}
                </a>
              </li>
            ) : null}
            {limitError ? (
              <li>
                <a href={`#${ids.limit}`}>
                  {copy.limitPrice}: {limitError}
                </a>
              </li>
            ) : null}
          </ul>
        </div>
      ) : null}

      <div className={styles.field}>
        <p className={styles.fieldLabel} aria-hidden="true">
          {copy.side}
        </p>
        <ToggleGroup<'0' | '1'>
          label={copy.side}
          value={side === 0 ? '0' : '1'}
          onValueChange={(v) => edit(() => setSide(v === '0' ? 0 : 1))}
          options={[
            { value: '0', label: <DirectionGlyph side="buy" />, tone: 'buy' },
            { value: '1', label: <DirectionGlyph side="sell" />, tone: 'sell' },
          ]}
        />
      </div>

      <div className={styles.field}>
        <p className={styles.fieldLabel} aria-hidden="true">
          {copy.role}
        </p>
        <ToggleGroup<'0' | '1'>
          label={copy.role}
          value={role === 0 ? '0' : '1'}
          onValueChange={(v) =>
            edit(() => {
              const next: Role = v === '0' ? 0 : 1;
              setRole(next);
              rememberRole(next);
            })
          }
          options={[
            { value: '0', label: copy.maker },
            { value: '1', label: copy.taker },
          ]}
        />
        <p className={styles.hint}>{roleExplainer}</p>
      </div>

      {params.flow === 1 ? (
        <div className={styles.field}>
          <p className={styles.fieldLabel}>{copy.book}</p>
          <p className={styles.derived}>{bookLabel(detail, book)}</p>
          <p className={styles.hint}>{copy.bookHint}</p>
        </div>
      ) : null}

      <div className={styles.field}>
        <p className={styles.fieldLabel} aria-hidden="true">
          {copy.type}
        </p>
        <ToggleGroup<'limit' | 'market'>
          label={copy.type}
          value={kind === 0 ? 'limit' : 'market'}
          onValueChange={(v) => edit(() => setKind(v === 'limit' ? 0 : 1))}
          options={[
            { value: 'limit', label: copy.limit },
            { value: 'market', label: copy.market },
          ]}
        />
        {kind === 1 && band !== null ? (
          <p className={styles.hint}>{copy.worstPrice(price(band.hi), price(band.lo))}</p>
        ) : null}
      </div>

      <NumberField
        id={ids.quantity}
        label={copy.quantity}
        unit={baseSymbol}
        value={quantityText}
        onValueChange={(text) => edit(() => setQuantityText(text))}
        hint={
          <>
            {copy.quantityHint(lotsToBaseText(u, 1n), baseSymbol)}
            {available ? (
              <>
                {' '}
                {side === 1
                  ? copy.available(atomsToDecimal(available.base, u.baseDecimals), baseSymbol)
                  : copy.available(atomsToDecimal(available.quote, u.quoteDecimals), quoteSymbol)}
              </>
            ) : null}
          </>
        }
        exact={
          quantity.ok ? copy.quantityExact(localize(quantity.base, numberFormat), baseSymbol) : null
        }
        error={showQuantityError ? quantityError : null}
      />
      {available && band ? (
        <div className={styles.shares} role="group" aria-label={copy.shareGroup}>
          {SHARES.map((percent) => (
            <Button
              key={percent}
              size="sm"
              variant="ghost"
              aria-label={copy.shareLabel(percent)}
              onClick={() => fillShare(percent)}
            >
              {copy.share(percent)}
            </Button>
          ))}
        </div>
      ) : null}

      {kind === 0 ? (
        <NumberField
          id={ids.limit}
          label={copy.limitPrice}
          unit={quoteSymbol}
          value={limitText}
          onValueChange={(text) => edit(() => setLimitText(text))}
          exact={
            limit?.ok && limit.price !== limit.typed
              ? copy.limitExact(localize(limit.price, numberFormat))
              : null
          }
          hint={
            <>
              {lastTick !== null ? copy.lastClearing(price(lastTick)) : copy.noLastClearing}
              {band ? <> - {copy.bandHint(price(band.lo), price(band.hi))}</> : null}
              {limit?.ok && lastTick !== null ? (
                <> - {copy.deviation(deviationPercent(limit.tick, lastTick))}</>
              ) : null}
            </>
          }
          error={showLimitError ? limitError : null}
        />
      ) : null}
      {outsideBand ? (
        <p className={styles.warningText}>
          <TriangleAlert size={16} aria-hidden="true" />
          {copy.outsideBand}
        </p>
      ) : null}

      <div className={styles.field}>
        <p className={styles.fieldLabel} aria-hidden="true">
          {copy.duration}
        </p>
        <ToggleGroup<string>
          label={copy.duration}
          value={String(chosenLifetime)}
          onValueChange={(v) =>
            edit(() => {
              setLifetime(Number(v));
              rememberLifetime(Number(v));
            })
          }
          className={styles.presets}
          options={presets.map((p) => ({ value: String(p.epochs), label: p.label }))}
        />
        <p className={styles.hint}>{copy.durationHint}</p>
      </div>

      {selfTrade ? (
        <p className={styles.blocker} role="alert">
          <OctagonAlert size={16} aria-hidden="true" />
          {tradeCopy.selfTrade}
        </p>
      ) : null}

      {prepared ? (
        <TicketSummary
          prepared={prepared}
          detail={detail}
          current={current}
          now={now}
          account={account}
          records={records}
          numberFormat={numberFormat}
        />
      ) : null}
      {prepareError && draft !== null ? <p className={styles.muted}>{prepareError}</p> : null}

      <DisclosureChips enclave={enclave} />

      {blocked ? <div className={styles.blockedReason}>{blocked}</div> : null}

      <div className={styles.ticketActions}>
        <Button type="submit" variant="secondary">
          {copy.review}
        </Button>
        <Button
          ref={sealRef}
          variant="primary"
          disabled={!canSeal}
          onClick={seal}
          aria-describedby={`${ids.summary}-sig`}
        >
          {tradeCopy.seal.button}
        </Button>
      </div>
      <p className={styles.hint} id={`${ids.summary}-sig`}>
        {tradeCopy.summary.signature}
      </p>
    </form>
  );
}
