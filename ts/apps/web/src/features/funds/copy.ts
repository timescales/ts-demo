// Funds screen copy (normative). Product-name strings
// interpolate brand.name so a rename stays a one-file change.
import { brand } from '../../design/brand';

const name = brand.name;

export const fundsCopy = {
  title: 'Funds',
  pageTitle: (pair: string) => `Funds ${pair}`,
  loading: 'Loading balances',
  noServices: `This screen is waiting for the connection to the ${name} service.`,
  noMarkets: 'No markets are available.',
  noWallet: 'Connect a wallet to see your balances and move funds.',
  connect: 'Connect wallet',
  loadFailed: "Balances can't be read from Solana right now. They may be stale.",
  mismatch: 'The service and your Solana RPC disagree about this market.',
  retry: 'Retry',
  halted: 'Market halted by its administrator. Withdrawals remain available.',
  publicTx: 'This transaction is public on Solana.',

  buckets: {
    title: 'Balances',
    caption: 'Balances in this market',
    bucket: 'Bucket',
    visibility: 'Who can see it',
    info: (bucket: string) => `About ${bucket}`,
    public: 'Public',
    private: 'Private (this device only)',
    publicOncePosted: 'Public once posted',
    unknown: '-',
    wallet: 'In wallet',
    walletInfo: 'Token balances of your wallet. Public on Solana.',
    timescales: `In ${name}`,
    timescalesInfo: `Your trader account in this market. Public on Solana.`,
    reserved: 'Reserved by working orders',
    reservedInfo:
      'An estimate made on this device from your working orders at this epoch’s band. Private.',
    pending: 'Pending settlement',
    pendingInfo: `Your verified fills of epochs not yet settled. "In ${name}" changes when they apply. Public once posted.`,
    requested: 'Requested for withdrawal',
    requestedInfo: 'Your pending withdrawal request. Public on Solana.',
    withdrawable: 'Withdrawable now',
    withdrawableInfo:
      'The requested amount once the batch in flight at request time has settled or been voided. Public on Solana.',
    noAccount: 'No account',
    noAta: 'No token account',
  },

  open: {
    title: `Open a ${name} trader account`,
    body: (rent: string) =>
      `Open a ${name} trader account (one-time rent ~ ${rent} SOL, refundable when you close it).`,
    bodyNoRent: `Open a ${name} trader account (one-time rent, refundable when you close it).`,
    empty: (rent: string) =>
      `This wallet has no ${name} account in this market yet. Opening one is a public transaction and costs ~ ${rent} SOL rent, refunded when you close it.`,
    action: 'Open account',
  },

  close: {
    title: 'Close account',
    body: 'Closing returns the account’s rent to your wallet.',
    notEmpty: 'Withdraw everything and cancel any request before closing.',
    leafInFlight: (epoch: string) => `Closing is available after epoch #${epoch} settles.`,
    action: 'Close account',
  },

  actions: {
    deposit: 'Deposit',
    requestWithdraw: 'Request withdrawal',
    cancelRequest: 'Cancel request',
    withdraw: 'Withdraw',
  },

  deposit: {
    title: 'Deposit',
    side: 'Token',
    amount: 'Amount',
    max: (amount: string, symbol: string) => `In wallet: ${amount} ${symbol}`,
    halted: 'Deposits are paused while the market is halted.',
    overCap: 'The deposit would exceed the balance this market allows.',
  },

  request: {
    title: 'Request withdrawal',
    base: (symbol: string) => `${symbol} amount`,
    quote: (symbol: string) => `${symbol} amount`,
    balance: (amount: string, symbol: string) => `In ${name}: ${amount} ${symbol}`,
    pending: 'A withdrawal request is already pending. Cancel it first to change it.',
    nothing: 'Enter an amount for at least one token.',
  },

  unlock: {
    later: (epoch: string, upTo: string) =>
      `Withdrawable after epoch #${epoch} is settled or voided (usually within one cycle). Up to ${upTo}; less if orders sealed before your request fill.`,
    now: (upTo: string) =>
      `Withdrawable right after the request: no batch is in flight. Up to ${upTo}.`,
    ready: (upTo: string) => `Withdrawable now, up to ${upTo}.`,
  },

  withdraw: {
    title: 'Withdraw',
    body: (amount: string) => `Withdraw ${amount} to your wallet.`,
    locked: (epoch: string) => `Locked until epoch #${epoch} is settled or voided.`,
    createsAta: 'A token account is created in your wallet if it has none.',
  },

  cancelRequest: {
    title: 'Cancel withdrawal request',
    body: 'Your requested amount becomes available for trading again.',
  },

  amountErrors: {
    empty: 'Enter an amount.',
    syntax: 'Enter a number such as 25.5.',
    ambiguous: 'This number mixes separators. Use the number format chosen in Settings.',
    zero: 'Enter more than zero.',
    too_large: 'More than you have.',
    precision: (decimals: number) => `At most ${decimals} decimals.`,
  },

  estimate: {
    fee: 'Network fee: about 0.000005 SOL per signature, plus any priority fee.',
    rent: (rent: string) => `Rent: ~ ${rent} SOL, refunded when you close the account.`,
  },

  tx: {
    label: 'Transaction progress',
    sign: 'Sign in wallet',
    send: 'Send to Solana',
    confirm: 'Confirmed',
    confirmed: 'Confirmed on Solana.',
    submit: 'Sign and send',
    retry: 'Retry',
    close: 'Close',
    expired: 'Expired before it landed. Nothing changed.',
    rewritten: 'Your wallet changed this transaction in an unexpected way. It was not sent.',
    rejected: 'Declined in wallet. Nothing was sent.',
    noSigner: "This wallet can't sign Solana transactions here.",
    failed: (reason: string) => `Failed: ${reason}`,
    signature: 'Transaction signature',
    insufficientSol: 'You need more SOL for fees and rent.',
    generic: 'The transaction could not be sent.',
  },

  programErrors: {
    WithdrawLocked: (epoch: string) => `Withdrawal locked until epoch #${epoch} is settled.`,
    WithdrawPending: 'A withdrawal request is already pending.',
    NothingToWithdraw: 'There is nothing to withdraw.',
    Insolvent: 'The amount is more than the account holds.',
    Halted: 'The market is halted. Deposits are paused.',
    InFlight: 'The account holds a result of the batch in flight. Try after it settles.',
    AccountNotEmpty: 'The account still holds funds or a request.',
    DuplicateTrader: 'This wallet already has an account in this market.',
    BalanceCap: 'The deposit would exceed the balance this market allows.',
    InvalidTokenAccount: 'The token account does not belong to this market’s mint.',
    InsufficientFunds: 'Not enough tokens in the wallet.',
    other: (program: string, code: number, name: string | null) =>
      `${name ?? 'Error'} (${program} program, code ${code}).`,
  },

  activity: {
    title: 'This session',
    empty: 'No transactions in this session.',
    item: (what: string, status: string) => `${what}: ${status}`,
  },

  freeze: (symbol: string) => `The issuer of ${symbol} can freeze this market's vault.`,
} as const;
