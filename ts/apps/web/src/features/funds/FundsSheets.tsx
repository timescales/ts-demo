import { closeStatus } from '@timescales/sdk/solana';
import { Snowflake } from 'lucide-react';
import { useState } from 'react';

import { Banner, Button, NumberField, Select } from '../../components/primitives';
import type { NumberFormat } from '../trade/services';
import { atomsToDecimal, localize } from '../trade/units';
import type { AmountError } from './amounts';
import { MAX_BALANCE, parseAmount } from './amounts';
import { fundsCopy } from './copy';
import styles from './funds.module.css';
import type { FundsSnapshot, TokenSide } from './port';
import type { TxSheetProps } from './TxSheet';
import { TxSheet } from './TxSheet';

const SOL_DECIMALS = 9;

type SheetBase = Pick<TxSheetProps, 'open' | 'port' | 'market' | 'onClose' | 'onFinished'> & {
  snapshot: FundsSnapshot;
  numberFormat: NumberFormat;
};

function amountError(e: AmountError, decimals: number): string {
  return e === 'precision' ? fundsCopy.amountErrors.precision(decimals) : fundsCopy.amountErrors[e];
}

function fmt(atoms: bigint, decimals: number, f: NumberFormat): string {
  return localize(atomsToDecimal(atoms, decimals), f);
}

export function rentText(s: FundsSnapshot, f: NumberFormat): string | null {
  return s.traderRentLamports === null ? null : fmt(s.traderRentLamports, SOL_DECIMALS, f);
}

function upTo(s: FundsSnapshot, base: bigint, quote: bigint, f: NumberFormat): string {
  const d = s.detail;
  return `${fmt(base, d.baseDecimals, f)} ${d.baseSymbol} + ${fmt(quote, d.quoteDecimals, f)} ${d.quoteSymbol}`;
}

/**
 * "Withdrawable after epoch #U is settled or voided...". U is the
 * epoch the request waits for: the batch in flight when it was made.
 */
export function UnlockExplainer({
  snapshot,
  base,
  quote,
  numberFormat,
  unlock,
}: {
  snapshot: FundsSnapshot;
  base: bigint;
  quote: bigint;
  numberFormat: NumberFormat;
  /** A pending request's status. Omitted for a request not yet made. */
  unlock?: { withdrawable: boolean; unlocksAfterEpoch: bigint };
}) {
  const m = snapshot.market;
  const amount = upTo(snapshot, base, quote, numberFormat);
  let text: string;
  if (unlock !== undefined) {
    text = unlock.withdrawable
      ? fundsCopy.unlock.ready(amount)
      : fundsCopy.unlock.later(unlock.unlocksAfterEpoch.toString(), amount);
  } else {
    text =
      m.lastSettled >= m.lastCommitted
        ? fundsCopy.unlock.now(amount)
        : fundsCopy.unlock.later(m.lastCommitted.toString(), amount);
  }
  return <p className={styles.explainer}>{text}</p>;
}

/** V-1: a mint with a freeze authority can freeze this market's vault. */
export function FreezeAuthorityNotice({ snapshot }: { snapshot: FundsSnapshot }) {
  const d = snapshot.detail;
  const symbols = [
    ...(d.mintAuthorities.base.freeze !== null ? [d.baseSymbol] : []),
    ...(d.mintAuthorities.quote.freeze !== null ? [d.quoteSymbol] : []),
  ];
  if (symbols.length === 0) return null;
  return (
    <ul className={styles.notices}>
      {symbols.map((symbol) => (
        <li key={symbol} className={styles.notice}>
          <Snowflake size={16} aria-hidden="true" />
          {fundsCopy.freeze(symbol)}
        </li>
      ))}
    </ul>
  );
}

export function DepositSheet(props: SheetBase) {
  const { snapshot: s, numberFormat } = props;
  const c = fundsCopy.deposit;
  const [side, setSide] = useState<TokenSide>('quote');
  const [text, setText] = useState('');
  const [tried, setTried] = useState(false);
  const decimals = side === 'base' ? s.detail.baseDecimals : s.detail.quoteDecimals;
  const symbol = side === 'base' ? s.detail.baseSymbol : s.detail.quoteSymbol;
  const inWallet = side === 'base' ? s.wallet.base : s.wallet.quote;
  const parsed = parseAmount(text, numberFormat, decimals, { max: inWallet ?? 0n });
  const inAccount = (side === 'base' ? s.trader?.base : s.trader?.quote) ?? 0n;
  const overCap = parsed.ok && inAccount + parsed.atoms > MAX_BALANCE;
  return (
    <TxSheet
      {...props}
      title={c.title}
      description={s.market.halted ? c.halted : undefined}
      estimate={<p>{fundsCopy.estimate.fee}</p>}
      action={() => {
        setTried(true);
        if (s.market.halted || !parsed.ok || overCap) return null;
        return { kind: 'deposit', side, amount: parsed.atoms };
      }}
    >
      <Select
        label={c.side}
        value={side}
        onValueChange={(v) => setSide(v === 'base' ? 'base' : 'quote')}
        options={[
          { value: 'base', label: s.detail.baseSymbol },
          { value: 'quote', label: s.detail.quoteSymbol },
        ]}
      />
      <NumberField
        label={c.amount}
        unit={symbol}
        value={text}
        onValueChange={setText}
        hint={c.max(inWallet === null ? '0' : fmt(inWallet, decimals, numberFormat), symbol)}
        error={
          !tried
            ? null
            : !parsed.ok
              ? amountError(parsed.error, decimals)
              : overCap
                ? c.overCap
                : null
        }
      />
    </TxSheet>
  );
}

export function WithdrawRequestSheet(props: SheetBase) {
  const { snapshot: s, numberFormat } = props;
  const c = fundsCopy.request;
  const t = s.trader;
  const [baseText, setBaseText] = useState('');
  const [quoteText, setQuoteText] = useState('');
  const [tried, setTried] = useState(false);
  const d = s.detail;
  const base = parseAmount(baseText, numberFormat, d.baseDecimals, {
    max: t?.base ?? 0n,
    optional: true,
  });
  const quote = parseAmount(quoteText, numberFormat, d.quoteDecimals, {
    max: t?.quote ?? 0n,
    optional: true,
  });
  const pending = t !== null && (t.requestedBase !== 0n || t.requestedQuote !== 0n);
  const nothing = base.ok && quote.ok && base.atoms === 0n && quote.atoms === 0n;
  return (
    <TxSheet
      {...props}
      title={c.title}
      description={pending ? c.pending : undefined}
      estimate={<p>{fundsCopy.estimate.fee}</p>}
      action={() => {
        setTried(true);
        if (pending || !base.ok || !quote.ok || nothing) return null;
        return { kind: 'request_withdraw', base: base.atoms, quote: quote.atoms };
      }}
    >
      <NumberField
        label={c.base(d.baseSymbol)}
        unit={d.baseSymbol}
        value={baseText}
        onValueChange={setBaseText}
        hint={c.balance(fmt(t?.base ?? 0n, d.baseDecimals, numberFormat), d.baseSymbol)}
        error={tried && !base.ok ? amountError(base.error, d.baseDecimals) : null}
      />
      <NumberField
        label={c.quote(d.quoteSymbol)}
        unit={d.quoteSymbol}
        value={quoteText}
        onValueChange={setQuoteText}
        hint={c.balance(fmt(t?.quote ?? 0n, d.quoteDecimals, numberFormat), d.quoteSymbol)}
        error={tried && !quote.ok ? amountError(quote.error, d.quoteDecimals) : null}
      />
      {tried && nothing ? <p role="alert">{c.nothing}</p> : null}
      <UnlockExplainer
        snapshot={s}
        base={base.ok ? base.atoms : 0n}
        quote={quote.ok ? quote.atoms : 0n}
        numberFormat={numberFormat}
      />
    </TxSheet>
  );
}

export function CancelRequestSheet(props: SheetBase) {
  const c = fundsCopy.cancelRequest;
  return (
    <TxSheet
      {...props}
      title={c.title}
      description={c.body}
      estimate={<p>{fundsCopy.estimate.fee}</p>}
      action={() => ({ kind: 'cancel_request' })}
    />
  );
}

export function WithdrawSheet(props: SheetBase & { unlockEpoch: bigint | null }) {
  const { snapshot: s, numberFormat, unlockEpoch } = props;
  const c = fundsCopy.withdraw;
  const t = s.trader;
  const payoutBase = t ? (t.requestedBase < t.base ? t.requestedBase : t.base) : 0n;
  const payoutQuote = t ? (t.requestedQuote < t.quote ? t.requestedQuote : t.quote) : 0n;
  return (
    <TxSheet
      {...props}
      title={c.title}
      description={c.body(upTo(s, payoutBase, payoutQuote, numberFormat))}
      unlockEpoch={unlockEpoch}
      estimate={
        <>
          <p>{fundsCopy.estimate.fee}</p>
          <p>{c.createsAta}</p>
        </>
      }
      action={() => ({ kind: 'withdraw' })}
    >
      {unlockEpoch !== null ? <p>{c.locked(unlockEpoch.toString())}</p> : null}
    </TxSheet>
  );
}

export interface AccountCardProps extends SheetBase {
  onOpenSheet: () => void;
  sheetOpen: boolean;
}

/** Empty state of the screen: the wallet has no trader account in this market. */
export function OpenAccountCard(props: AccountCardProps) {
  const { snapshot: s, numberFormat } = props;
  const c = fundsCopy.open;
  const rent = rentText(s, numberFormat);
  return (
    <section className={styles.card} aria-labelledby="open-account-title">
      <h2 id="open-account-title">{c.title}</h2>
      <p>{rent === null ? c.bodyNoRent : c.empty(rent)}</p>
      <Button variant="primary" onClick={props.onOpenSheet}>
        {c.action}
      </Button>
      <TxSheet
        {...props}
        open={props.sheetOpen}
        title={c.title}
        description={rent === null ? c.bodyNoRent : c.body(rent)}
        estimate={
          <>
            <p>{fundsCopy.estimate.fee}</p>
            {rent !== null ? <p>{fundsCopy.estimate.rent(rent)}</p> : null}
          </>
        }
        action={() => ({ kind: 'open' })}
      />
    </section>
  );
}

export function CloseAccountCard(props: AccountCardProps) {
  const { snapshot: s } = props;
  const c = fundsCopy.close;
  if (s.trader === null) return null;
  const status = closeStatus(s.market, s.trader);
  return (
    <section className={styles.card} aria-labelledby="close-account-title">
      <h2 id="close-account-title">{c.title}</h2>
      <p>
        {status.reason === 'ok'
          ? c.body
          : status.reason === 'not_empty'
            ? c.notEmpty
            : c.leafInFlight((status.availableAfterEpoch ?? s.market.lastCommitted).toString())}
      </p>
      <Button disabled={!status.closable} onClick={props.onOpenSheet}>
        {c.action}
      </Button>
      <TxSheet
        {...props}
        open={props.sheetOpen}
        title={c.title}
        description={c.body}
        estimate={<p>{fundsCopy.estimate.fee}</p>}
        action={() => ({ kind: 'close' })}
      />
    </section>
  );
}

export function HaltedNotice({ snapshot }: { snapshot: FundsSnapshot }) {
  if (!snapshot.market.halted && !snapshot.detail.halted) return null;
  return <Banner severity="critical" title={fundsCopy.halted} />;
}
