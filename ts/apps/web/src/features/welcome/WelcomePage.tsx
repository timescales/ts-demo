// Onboarding (Welcome): six steps, each skippable once done. Progress is
// kept on this device.
import { requestPersistence } from '@timescales/sdk/journal';
import type { MarketDetail } from '@timescales/sdk/api';
import type { TraderAccount } from '@timescales/sdk/solana';
import type { VerifiedMarketContext } from '@timescales/sdk/verify';
import { associatedTokenAddress, depositIx, openTraderIx, traderPda } from '@timescales/sdk/solana';
import { useQuery } from '@tanstack/react-query';
import type { ReactNode } from 'react';
import { useState } from 'react';
import { useNavigate } from 'react-router';

import { MarketSelector, WalletPicker, shortAddress } from '../../components/chrome';
import type { Step } from '../../components/primitives';
import {
  Banner,
  Button,
  Checkbox,
  InlineError,
  Stepper,
  TextField,
  ToggleGroup,
} from '../../components/primitives';
import { routerLink, usePageTitle } from '../../app/links';
import pageStyles from '../../app/Page.module.css';
import { isIOS, walletHandoffLinks } from '../../app/platform';
import { enclaveTrust } from '../../app/Footer';
import { formatSol, rentExemption } from '../../state/chain';
import { describeFailure } from '../../state/failures';
import { updateWelcome, welcomeStore } from '../../state/firstRun';
import {
  rememberMarket,
  useMarketCheck,
  useMarketList,
  useSession,
  useWallet,
} from '../../state/hooks';
import { useInfo, useMarketDetail } from '../../state/queries';
import { useRuntime } from '../../state/runtime';
import { useSettings } from '../../state/settings';
import { useStore } from '../../state/store';
import type { Instruction, TxStep } from '../../state/tx';
import { failureText, runTraderTx } from '../../state/tx';
import type { Address } from '../../state/types';
import { parseAddress } from '../../state/types';
import { amountToAtoms, atomsToAmount } from '../../state/units';
import type { MarketCheck } from '../../state/verification';
import { privacyCopy } from '../privacy/copy';
import { settingsCopy } from '../settings/copy';
import { TrustMatrix } from '../privacy/TrustMatrix';
import { WhoSeesWhatMatrix } from '../privacy/WhoSeesWhatMatrix';
import { welcomeCopy } from './copy';
import styles from './Welcome.module.css';

/** Rent-exempt size of a Trader account. */
const TRADER_ACCOUNT_LEN = 148;

/**
 * Money moves only on a market this app verified (V-1): the decimals that
 * scale a typed amount, the mint and the vault come from the verified
 * accounts, never from the node's report alone.
 */
export function fundsGate(
  check: MarketCheck | undefined,
): { ctx: VerifiedMarketContext; reason: null } | { ctx: null; reason: string } {
  const g = welcomeCopy.gate;
  if (check === undefined || check.status === 'checking' || check.status === 'inconclusive')
    return { ctx: null, reason: g.checking };
  if (check.status === 'ok') return { ctx: check.ctx, reason: null };
  if (check.status === 'fail') return { ctx: null, reason: g.failed(check.reason) };
  return { ctx: null, reason: g.unpinned };
}

export function WalletHandoffLinks({ pageUrl }: { pageUrl: string }) {
  const c = welcomeCopy.connect;
  return (
    <div className={styles.handoff}>
      <p>{c.ios}</p>
      <ul className={pageStyles.list}>
        {walletHandoffLinks(pageUrl).map((l) => (
          <li key={l.wallet}>
            <a href={l.href} rel="noopener noreferrer">
              {c.handoff(l.wallet)}
            </a>
          </li>
        ))}
      </ul>
    </div>
  );
}

function useTx() {
  const runtime = useRuntime();
  const wallet = useWallet();
  const [step, setStep] = useState<TxStep | null>(null);
  const [result, setResult] = useState<{ ok: boolean; text: string } | null>(null);
  const t = welcomeCopy.tx;
  const run = async (instructions: Instruction[], title: string): Promise<bigint | null> => {
    if (wallet.wallet === null) return null;
    setResult(null);
    // Activity entries name the job, never an amount.
    const id = `tx-${Date.now()}`;
    const log = (status: 'pending' | 'done' | 'failed', detail?: string) =>
      runtime.activity.put({ id, title, status, atMs: Date.now(), ...(detail ? { detail } : {}) });
    log('pending');
    try {
      const out = await runTraderTx({
        rpc: runtime.rpc.get().rpc,
        wallet: wallet.wallet,
        instructions,
        onStep: setStep,
      });
      if (out.status === 'confirmed') {
        setResult({ ok: true, text: t.confirmed });
        log('done');
        return out.slot;
      }
      const text =
        out.status === 'failed'
          ? t.failed(failureText(out.failure))
          : out.status === 'expired'
            ? t.expired
            : t.rewritten;
      setResult({ ok: false, text });
      log('failed', text);
    } catch (e) {
      runtime.wallets.report(e);
      const text = t.failed(describeFailure(e).text);
      setResult({ ok: false, text });
      log('failed', text);
    } finally {
      setStep(null);
    }
    return null;
  };
  const view: ReactNode = (
    <>
      <p className={pageStyles.muted}>{t.public}</p>
      {step !== null ? <p>{t[step]}</p> : null}
      {result ? result.ok ? <p>{result.text}</p> : <InlineError>{result.text}</InlineError> : null}
    </>
  );
  return { busy: step !== null, run, view };
}

function useTrader(market: Address | null) {
  const runtime = useRuntime();
  const wallet = useWallet();
  const program = runtime.config.programId;
  return useQuery({
    queryKey: ['trader', market, wallet.address],
    enabled: market !== null && wallet.address !== null && program !== null,
    queryFn: async (): Promise<TraderAccount | null> => {
      const [address] = await traderPda(program!, market!, wallet.address!);
      const t = await runtime.rpc.get().rpc.trader(address);
      return t?.value ?? null;
    },
  });
}

function AccountStep({ market, check }: { market: Address; check: MarketCheck | undefined }) {
  const runtime = useRuntime();
  const gate = fundsGate(check);
  const wallet = useWallet();
  const tx = useTx();
  const trader = useTrader(market);
  const url = runtime.rpc.get().option?.url ?? null;
  const rent = useQuery({
    queryKey: ['rent', url],
    enabled: url !== null,
    queryFn: () => rentExemption(url!, TRADER_ACCOUNT_LEN),
    staleTime: 600_000,
  });
  const c = welcomeCopy.account;
  const program = runtime.config.programId;
  return (
    <div className={styles.panel}>
      <p>
        {c.explain} {rent.data === undefined ? c.rentUnknown : c.rent(formatSol(rent.data))}
      </p>
      {gate.reason !== null ? <p className={pageStyles.muted}>{gate.reason}</p> : null}
      <div>
        <Button
          variant="primary"
          busy={tx.busy}
          disabled={wallet.wallet === null || program === null || gate.ctx === null}
          onClick={() => {
            if (wallet.address === null || program === null || gate.ctx === null) return;
            void openTraderIx({ program, owner: wallet.address, market })
              .then((ix) => tx.run([ix], welcomeCopy.steps.account))
              .then(() => trader.refetch());
          }}
        >
          {c.open}
        </Button>
      </div>
      {tx.view}
    </div>
  );
}

function DepositStep({
  market,
  detail,
  check,
  onDeposited,
}: {
  market: Address;
  detail: MarketDetail;
  check: MarketCheck | undefined;
  onDeposited: (slot: bigint) => void;
}) {
  const gate = fundsGate(check);
  const runtime = useRuntime();
  const wallet = useWallet();
  const settings = useSettings();
  const trader = useTrader(market);
  const tx = useTx();
  const [side, setSide] = useState<'base' | 'quote'>('quote');
  const [amount, setAmount] = useState('');
  const [error, setError] = useState<string | null>(null);
  const c = welcomeCopy.deposit;
  const program = runtime.config.programId;
  const submit = async () => {
    const ctx = gate.ctx;
    if (wallet.address === null || program === null || ctx === null) return;
    const decimals = side === 'base' ? ctx.units.baseDecimals : ctx.units.quoteDecimals;
    let atoms: bigint;
    try {
      atoms = amountToAtoms(amount, decimals, settings.numberFormat);
    } catch {
      setError(c.invalid);
      return;
    }
    setError(null);
    const mint = side === 'base' ? ctx.market.baseMint : ctx.market.quoteMint;
    const source = await associatedTokenAddress(wallet.address, mint);
    const ix = await depositIx({
      program,
      owner: wallet.address,
      market,
      source,
      vault: side === 'base' ? ctx.market.baseVault : ctx.market.quoteVault,
      side,
      amount: atoms,
    });
    const slot = await tx.run([ix], welcomeCopy.steps.deposit);
    if (slot !== null) {
      // Ask the browser to keep the journal once money is in.
      void requestPersistence();
      onDeposited(slot);
      void trader.refetch();
    }
  };
  return (
    <div className={styles.panel}>
      <p>{c.explain}</p>
      <ToggleGroup<'base' | 'quote'>
        label={c.side}
        value={side}
        onValueChange={setSide}
        options={[
          { value: 'base', label: detail.baseSymbol },
          { value: 'quote', label: detail.quoteSymbol },
        ]}
      />
      <TextField
        label={c.amount}
        hint={c.amountHint(settingsCopy.display.formats[settings.numberFormat])}
        error={error}
        inputMode="decimal"
        value={amount}
        onChange={(e) => setAmount(e.target.value)}
      />
      {gate.reason !== null ? <p className={pageStyles.muted}>{gate.reason}</p> : null}
      <div>
        <Button
          variant="primary"
          busy={tx.busy}
          disabled={wallet.wallet === null || program === null || gate.ctx === null}
          onClick={() => void submit()}
        >
          {c.deposit}
        </Button>
      </div>
      {tx.view}
    </div>
  );
}

export default function WelcomePage() {
  usePageTitle(welcomeCopy.title);
  const runtime = useRuntime();
  const navigate = useNavigate();
  const wallet = useWallet();
  const session = useSession();
  const progress = useStore(welcomeStore);
  const info = useInfo();
  const { markets, defaultMarket } = useMarketList();
  // A remembered choice counts only while the node still lists that market.
  // After a redeploy the stored address is gone and this build does not pin it.
  const stored = parseAddress(progress.market);
  const chosen = stored !== null && markets.some((m) => m.address === stored);
  const market = chosen ? stored : defaultMarket;
  const detail = useMarketDetail(market).data;
  const check = useMarketCheck(market);
  const trader = useTrader(chosen ? market : null);
  const [pickerOpen, setPickerOpen] = useState(false);
  const [depositSlot, setDepositSlot] = useState<bigint | null>(null);
  const s = welcomeCopy.steps;

  const connected = wallet.status === 'connected' && wallet.address !== null;
  const t = trader.data ?? null;
  const done = [
    connected,
    progress.understoodPublic,
    chosen,
    t !== null,
    t !== null && (t.base > 0n || t.quote > 0n),
    session.status === 'active',
  ];
  const current = done.findIndex((d) => !d);
  const finish = () => {
    updateWelcome({ done: true });
    if (market !== null) {
      rememberMarket(market);
      void navigate(`/trade/${market}`);
    } else void navigate('/');
  };
  const ios =
    typeof navigator !== 'undefined' &&
    isIOS(navigator.userAgent, navigator.maxTouchPoints) &&
    wallet.available.length === 0;

  const panels: ReactNode[] = [
    <div key="connect" className={styles.panel}>
      <p>{welcomeCopy.noWallet}</p>
      <p className={pageStyles.muted}>{welcomeCopy.connect.untested}</p>
      {ios ? <WalletHandoffLinks pageUrl={window.location.href} /> : null}
      <div className={pageStyles.row}>
        <Button variant="primary" onClick={() => setPickerOpen(true)}>
          {welcomeCopy.connect.choose}
        </Button>
        {market !== null
          ? routerLink({ href: `/epochs/${market}`, children: welcomeCopy.browse })
          : null}
      </div>
      {wallet.error ? <InlineError>{welcomeCopy.connect.error}</InlineError> : null}
    </div>,
    <div key="learn" className={styles.panel}>
      <WhoSeesWhatMatrix enclave={enclaveTrust(check, info.data)} summary />
      {info.data ? (
        <TrustMatrix
          compact
          trust={info.data.trust}
          label={check?.status === 'ok' ? check.ctx.enclaveLabel : null}
        />
      ) : null}
      <p>
        <strong>{welcomeCopy.learn.signCode}</strong>
      </p>
      <Checkbox
        label={welcomeCopy.learn.understood}
        checked={progress.understoodPublic}
        onCheckedChange={(understoodPublic) => updateWelcome({ understoodPublic })}
      />
      <p>{routerLink({ href: '/privacy', children: welcomeCopy.learn.more })}</p>
    </div>,
    <div key="market" className={styles.panel}>
      {markets.length === 0 || market === null ? (
        <p>{welcomeCopy.market.none}</p>
      ) : (
        <>
          <MarketSelector
            markets={markets}
            value={market}
            onChange={(next) => updateWelcome({ market: next })}
          />
          <div>
            <Button variant="primary" onClick={() => updateWelcome({ market })}>
              {welcomeCopy.market.choose}
            </Button>
          </div>
        </>
      )}
    </div>,
    market !== null ? <AccountStep key="account" market={market} check={check} /> : null,
    market !== null && detail !== undefined ? (
      <DepositStep
        key="deposit"
        market={market}
        detail={detail}
        check={check}
        onDeposited={setDepositSlot}
      />
    ) : null,
    <div key="session" className={styles.panel}>
      <p>{welcomeCopy.session.explain}</p>
      <div>
        <Button
          variant="primary"
          busy={session.status === 'opening'}
          disabled={!connected}
          onClick={() =>
            void runtime.session.open({
              market,
              ...(depositSlot !== null ? { minContextSlot: depositSlot } : {}),
            })
          }
        >
          {welcomeCopy.session.start}
        </Button>
      </div>
      {session.error ? <InlineError>{describeFailure(session.error).text}</InlineError> : null}
    </div>,
  ];

  const summaries: ReactNode[] = [
    connected
      ? welcomeCopy.connect.connected(wallet.wallet?.name ?? '', shortAddress(wallet.address!))
      : null,
    null,
    detail ? welcomeCopy.market.chosen(detail.name) : null,
    welcomeCopy.account.exists,
    t !== null && detail !== undefined && check?.status === 'ok'
      ? welcomeCopy.deposit.done(
          `${atomsToAmount(t.base, check.ctx.units.baseDecimals)} ${detail.baseSymbol}`,
          `${atomsToAmount(t.quote, check.ctx.units.quoteDecimals)} ${detail.quoteSymbol}`,
        )
      : null,
    welcomeCopy.session.active,
  ];

  const labels = [s.connect, s.learn, s.market, s.account, s.deposit, s.session];
  const steps: Step[] = labels.map((label, i) => ({
    id: String(i),
    label,
    status: done[i] ? 'done' : i === current ? 'current' : 'upcoming',
    detail: i === current ? panels[i] : done[i] ? summaries[i] : undefined,
  }));
  const freeze =
    check?.status === 'ok' && detail !== undefined
      ? check.freezeWarnings.map((w) => (w === 'base' ? detail.baseSymbol : detail.quoteSymbol))
      : [];

  return (
    <div className={pageStyles.page}>
      <header className={pageStyles.header}>
        <h1>{welcomeCopy.title}</h1>
        <p className={pageStyles.lede}>{welcomeCopy.lede}</p>
      </header>
      {freeze.map((symbol) => (
        <Banner key={symbol} severity="info" title={welcomeCopy.market.freeze(symbol)} />
      ))}
      <Stepper label={welcomeCopy.stepperLabel} steps={steps} />
      <div>
        <Button variant={current === -1 ? 'primary' : 'secondary'} onClick={finish}>
          {welcomeCopy.continue}
        </Button>
      </div>
      <p className={pageStyles.muted}>{privacyCopy.device.text[2]}</p>
      <WalletPicker
        open={pickerOpen}
        onClose={() => setPickerOpen(false)}
        wallets={wallet.available}
        onSelect={(id) => {
          setPickerOpen(false);
          void runtime.wallets.connect(id);
        }}
      />
    </div>
  );
}
