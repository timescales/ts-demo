import { brand } from '../../design/brand';

const name = brand.name;

export const welcomeCopy = {
  title: 'Welcome',
  lede: `${name} clears sealed orders in short batches. These six steps get you ready. Each one can be skipped once it is done, and your progress stays on this device.`,
  stepperLabel: 'Getting started',
  noWallet:
    'Connect a wallet to seal orders. You can browse epochs and clearing prices without one.',
  continue: 'Continue to trading',
  browse: 'Browse epochs without a wallet',
  steps: {
    connect: 'Connect a wallet',
    learn: `What ${name} hides and what it doesn't`,
    market: 'Choose a market',
    account: 'Open a trader account',
    deposit: 'Deposit',
    session: 'Start a trading session',
  },
  connect: {
    choose: 'Choose wallet',
    connected: (wallet: string, address: string) => `Connected: ${wallet} ${address}`,
    untested: `Every wallet is untested with ${name} until the wallet matrix is signed off.`,
    ios: 'Safari on iPhone and iPad cannot connect a wallet. Open this page in a wallet app instead:',
    handoff: (wallet: string) => `Open in ${wallet}`,
    error: 'The wallet did not connect. Nothing was shared.',
  },
  learn: {
    understood: 'I understand deposits, withdrawals and fills are public',
    signCode: `${name} will ask your wallet to sign a short code for each order. Never sign such a code for any other site.`,
    more: 'Read the full privacy page',
  },
  market: {
    chosen: (label: string) => `Market: ${label}`,
    choose: 'Use this market',
    freeze: (symbol: string) => `The issuer of ${symbol} can freeze this market's vault.`,
    none: 'No market is available yet.',
  },
  account: {
    explain: `This wallet has no ${name} account in this market yet.`,
    rent: (rent: string) =>
      `Opening one is a public transaction and costs ~ ${rent} SOL rent, refunded when you close it.`,
    rentUnknown:
      'Opening one is a public transaction. Your RPC did not report the rent, which is refunded when you close the account.',
    open: 'Open account',
    exists: 'Trader account open.',
    needsWallet: 'Connect a wallet first.',
  },
  deposit: {
    explain: 'Deposits are public on Solana. Deposit at least what you plan to trade.',
    side: 'Token',
    amount: 'Amount',
    amountHint: (format: string) => `Typed as ${format}.`,
    deposit: 'Deposit',
    done: (base: string, quote: string) => `In ${name}: ${base} and ${quote}.`,
    invalid: 'Enter a positive amount in the number format from Settings.',
    persistence: 'This browser may delete your order details. Export a backup from Settings.',
  },
  gate: {
    checking:
      'This app is still verifying this market. Accounts and deposits wait until it passes.',
    failed: (reason: string) =>
      `This market failed verification in this app (${reason}). Accounts and deposits are off.`,
    unpinned:
      'This build does not pin this market, so it cannot verify it. Accounts and deposits are off.',
  },
  session: {
    explain:
      'Start a trading session to submit orders. Your wallet signs once. Each order still needs its own signature.',
    start: 'Start session (1 wallet signature)',
    active: 'Session active.',
  },
  tx: {
    building: 'Preparing the transaction...',
    signing: 'Confirm in your wallet...',
    sending: 'Sending...',
    confirming: 'Confirming...',
    confirmed: 'Confirmed.',
    failed: (why: string) => `Failed: ${why}`,
    expired: 'Expired before it landed. Nothing changed.',
    rewritten: 'Your wallet changed this transaction in an unexpected way. It was not sent.',
    public: 'This transaction is public on Solana.',
  },
} as const;
