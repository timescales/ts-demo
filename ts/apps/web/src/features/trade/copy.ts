// Trade screen copy (normative). Product-name strings
// interpolate brand.name so a rename stays a one-file change.
import { brand } from '../../design/brand';

const name = brand.name;

export const tradeCopy = {
  title: 'Trade',
  pageTitle: (pair: string) => `Trade ${pair}`,
  loading: 'Loading market',
  marketUnavailable: "This market can't be loaded right now.",
  retry: 'Retry',
  noServices: `This screen is waiting for the connection to the ${name} service.`,

  header: {
    label: 'Market',
    flowLabel: 'Flow',
    flow: { single: 'Single book', dual: 'Dual flow' },
    band: 'Band',
    bandValue: (lo: string, hi: string) => `${lo} - ${hi}`,
    noBand: 'No open epoch',
    reference: 'Reference',
    referenceSource: {
      fixed: 'fixed by the operator',
      last_clearing: 'last clearing price',
      operator: 'operator-reported',
      modelled_tlsnotary: 'modelled TLSNotary',
      unknown: 'unknown source',
    },
    halted: 'Halted',
  },

  clock: {
    label: 'Epoch clock',
    epoch: (epoch: string) => `Epoch #${epoch}`,
    toCutoff: 'to cutoff',
    timerLabel: (epoch: string) => `Time to cutoff of epoch ${epoch}`,
    noOpen: 'No epoch is open for orders',
    nearCutoff: 'Cutoff is close',
    announceCutoff: (epoch: string, seconds: number) =>
      `Epoch ${epoch} closes in ${seconds} seconds.`,
    inFlight: (epoch: string) => `In flight: #${epoch}`,
    legend: 'Phases',
    legendItems: {
      open: 'Open: orders seal into this epoch',
      closed: 'Closed: the batch is fixed',
      clearing: 'Clearing: the enclave executes it',
      settled: 'Settled on Solana',
    },
  },

  ticket: {
    title: 'New order',
    side: 'Side',
    buy: 'Buy',
    sell: 'Sell',
    role: 'Role',
    maker: 'Maker',
    taker: 'Taker',
    roleSingle: (maker: number, taker: number) =>
      `In this market your role only sets your fee (maker ${maker} bps, taker ${taker} bps). Matching treats both the same.`,
    roleDual: (book: string) =>
      `Maker orders trade against taker flow in the ${book}; your book follows from side and role.`,
    book: 'Book',
    bookHint: 'Set by side and role.',
    type: 'Type',
    limit: 'Limit',
    market: 'Market',
    worstPrice: (hi: string, lo: string) => `Worst price: band edge ${hi} (buy) / ${lo} (sell)`,
    quantity: 'Quantity',
    quantityHint: (lot: string, symbol: string) => `In ${symbol}; one lot is ${lot} ${symbol}.`,
    quantityExact: (base: string, symbol: string) => `Signed as ${base} ${symbol}`,
    share: (percent: number) => `${percent}%`,
    shareLabel: (percent: number) => `${percent}% of available`,
    shareGroup: 'Fill from the available balance',
    available: (amount: string, symbol: string) => `Available: ${amount} ${symbol}`,
    limitPrice: 'Limit price',
    limitExact: (price: string) => `Signed as ${price} (the nearest tick in your favour)`,
    lastClearing: (price: string) => `Last clearing ${price}`,
    noLastClearing: 'No clearing yet',
    bandHint: (lo: string, hi: string) => `Band ${lo} - ${hi}`,
    deviation: (percent: string) => `${percent}% from last clearing`,
    outsideBand:
      "Won't trade at this epoch's band. It stays working for later epochs while its lifetime lasts.",
    duration: 'Duration',
    durationHint: 'How many epochs the order may rest.',
    presetThisEpoch: 'This epoch',
    presetNext: (epochs: number) => `Next clearing (${epochs} epochs)`,
    presetEpochs: (epochs: number) => `${epochs} epochs`,
    presetMax: (epochs: number) => `Max: ${epochs} ${epochs === 1 ? 'epoch' : 'epochs'}`,
    presetAbout: (label: string, duration: string) => `${label} ~ ${duration}`,
    review: 'Review',
    errors: {
      quantity: {
        empty: 'Enter a quantity.',
        syntax: 'Enter a number such as 1.5.',
        ambiguous: 'This number mixes separators. Use the number format chosen in Settings.',
        zero: 'Less than one lot. Enter at least one lot.',
        too_large: (max: string) => `At most ${max} per order.`,
      },
      price: {
        empty: 'Enter a limit price.',
        syntax: 'Enter a price such as 182.37.',
        ambiguous: 'This number mixes separators. Use the number format chosen in Settings.',
        zero: 'The limit price is below one tick.',
        too_large: 'This price is too large for this market.',
      },
      summary: (n: number) =>
        n === 1 ? 'Fix 1 field to continue.' : `Fix ${n} fields to continue.`,
    },
    shortcutsIgnored: 'Shortcuts are ignored while you type in a field.',
  },

  summary: {
    title: 'Summary',
    reserved: 'Reserved collateral',
    fee: (role: string) => `Fee estimate (${role})`,
    worst: 'Worst-case notional',
    joins: (epoch: string, cutoff: string) => `Joins epoch #${epoch} (cutoff in ${cutoff})`,
    willJoinNext: (epoch: string) =>
      `Will join #${epoch}: not enough time is left to sign before this cutoff.`,
    restsUntil: (last: string) => `Rests until #${last}`,
    queued: (from: string, to: string) => `queued with the operator for #${from}...#${to}`,
    needsApp: (after: string) => `Epochs after #${after} need ${name} open`,
    undercapitalized: (amount: string) => `Undercapitalized: only ${amount} can fill`,
    secondPrompt:
      'This needs another wallet signature: your session ends before this order does. Renew the session to keep it resting.',
    linkable:
      'Resting across epochs is linkable: the same sealed commitment appears each epoch (partly masked by cover).',
    signature: `Your wallet will show a short code. It authorizes this one order on ${name}. Never sign such a code for any other site.`,
  },

  disclosure: {
    label: 'Who can see this order',
    simulated:
      "Readable by this deployment's operator (simulated enclave). Hidden from other traders until clearing.",
    tdx: 'Hidden from other traders and the operator until clearing, unless the key dealer or at least t key-committee members collude.',
    operatorReported: '(operator-reported)',
    publicIfFilled: 'Public if filled: your wallet, side, role, size, price',
    alwaysPublic: `Always public: this wallet holds a ${name} account, your deposits and withdrawals`,
    linkable:
      'Resting across epochs is linkable: the same sealed commitment appears each epoch (partly masked by cover)',
  },

  seal: {
    button: 'Seal order',
    title: 'Seal order',
    stepsLabel: 'Sealing progress',
    confirm: 'Confirm in wallet',
    fingerprint: (code: string) =>
      `Order code ${code}: check that the code your wallet shows starts with it.`,
    fingerprintWeak:
      'The code identifies this order only. It cannot tell you the price or size you signed for.',
    stillWaiting: 'Still waiting for your wallet...',
    encrypting: (epoch: string) => `Encrypting to epoch #${epoch} key`,
    keyVerified: 'key verified',
    submitting: 'Submitting',
    receipt: 'Relay receipt verified',
    sealed: (epoch: string) => `Sealed - #${epoch}`,
    queued: (from: string, to: string) => `Queued - #${from}-#${to}`,
    done: 'Done',
    cancel: 'Cancel',
    close: 'Close',
    retry: 'Retry',
    signAgain: 'Sign again',
    rejected: 'Not sent (declined in wallet). Nothing was sent.',
    abandoned: 'Not sent (cancelled). A late wallet signature is discarded.',
    tooLate: 'Nothing was sent. Sign again.',
    unsupported: `This wallet can't sign ${name} orders.`,
    failed: (reason: string) => `Not sent: ${reason}`,
    resendFailed: (reason: string) => `Not sent again: ${reason}`,
    paused: 'New orders are paused in this market.',
    unverified: "This market's checks have not passed on this device, so nothing was sealed.",
    secondPromptTitle: 'Another wallet signature',
    secondPrompt: (why: string) => `This needs another wallet signature: ${why}.`,
    secondPromptWhyClosed: 'the epoch closed before your wallet signed',
    secondPromptSign: 'Sign',
  },

  selfTrade: `${name} rejects all of your orders in this book if you are on both sides in one epoch (self-trade prevention). Cancel the other side first.`,

  states: {
    noWallet: 'Connect a wallet to seal orders.',
    connect: 'Connect wallet',
    noSession:
      'Start a trading session to submit orders. Your wallet signs once. Each order still needs its own signature.',
    startSession: 'Start session',
    noAccount: `Open a ${name} account first.`,
    openAccount: 'Go to Funds',
    paused: (reason: string, resume: string) =>
      `New orders paused: ${reason} Already-sealed orders are unaffected. ${resume}`,
    resumeUnknown: 'It resumes when the cause clears.',
    resumeNextEpoch: 'Expected to resume with the next epoch.',
    halted: 'Market halted by its administrator. Withdrawals remain available.',
    unverified: (reason: string) =>
      `Could not verify this market (${reason}). Don't rely on its data. Trading in this market is paused on this device.`,
    recheck: 'Re-check',
    checking: 'Checking this market against Solana...',
  },

  pauseReasons: {
    pipeline_backlog: 'The previous batch is still settling.',
    epoch_key_unavailable: "The next encryption key isn't ready yet.",
    halted: 'The market is halted by its administrator.',
    operator: 'Paused by the operator.',
    low_relay_balance: "The operator's account needs funds.",
    recovering: 'The service is recovering.',
    fenced: 'The service stopped itself after a safety check.',
    draining: 'The service is restarting.',
    governance_due: 'A scheduled governance change is being applied.',
    unknown: 'The service did not say why.',
  },

  chart: {
    title: 'Clearing prices',
    summary: (pair: string, book: string, n: number, lo: string, hi: string) =>
      n === 0
        ? `Clearing prices for ${pair}, ${book}: no epochs yet.`
        : `Clearing prices for ${pair}, ${book}, last ${n} epochs, from ${lo} to ${hi}.`,
    point: (epoch: string, price: string, fills: number) =>
      `Epoch ${epoch}, cleared ${price}, ${fills} ${fills === 1 ? 'fill' : 'fills'}`,
    pointNoClear: (epoch: string, phase: string) => `Epoch ${epoch}, ${phase}, no clearing price`,
    ownFill: 'your fill',
    viewTable: 'View as table',
    book: 'Book',
    keyboardHint: 'Arrow keys move between epochs. Enter opens one.',
  },

  tape: {
    title: 'Clearing tape',
    caption: 'Clearing tape: one row per epoch, newest first',
    epoch: 'Epoch',
    cutoff: 'Cutoff',
    clearing: 'Clearing price',
    matched: 'Matched',
    fills: 'Fills',
    status: 'Status',
    settled: 'Settled',
    notCleared: '-',
    noVolume: 'no match',
    empty:
      'No epochs have cleared in this market yet. The first result appears about one interval after the first cutoff.',
    older: 'Older epochs',
    newer: 'Newest epochs',
    page: 'Clearing tape pages',
    loadFailed: "The clearing tape can't be loaded right now.",
  },

  myOrders: {
    title: 'My orders here',
    empty: 'No working orders in this market.',
    side: 'Side',
    qty: 'Qty',
    limit: 'Limit',
    status: 'Status',
    marketOrder: 'Market',
    all: 'All orders',
    details: 'Details',
    detailsLabel: (side: string, status: string) => `Details of ${side} order, ${status}`,
    openRail: 'My orders here',
  },

  errors: {
    EPOCH_KEY_UNAVAILABLE: (epoch: string) =>
      `The encryption key for #${epoch} could not be verified, so nothing was sealed.`,
    QUOTA_EXCEEDED: "You've reached the number of orders allowed this epoch.",
    BATCH_FULL: (epoch: string) => `Epoch #${epoch} is full.`,
    EPOCH_CLOSED: 'Cutoff passed.',
    INTAKE_PAUSED: 'New orders are paused.',
    MARKET_HALTED: 'Market halted by its administrator.',
    RATE_LIMITED: (seconds: number) => `Busy, retrying in ${seconds}s.`,
    OVERLOADED: (seconds: number) => `Busy, retrying in ${seconds}s.`,
    DUPLICATE_COMMITMENT: 'This order was already submitted from another tab or device.',
    WALLET_NOT_ELIGIBLE: `This wallet can't trade yet. Open a ${name} account and deposit first.`,
    session: 'Session expired. Renew (1 wallet signature).',
    sessionRevoked: 'You signed in elsewhere, so this session ended. Renew (1 wallet signature).',
    refusalSaved: "The relay's signed refusal is saved.",
    storage: 'This device is out of storage. Nothing was sent.',
    network: `Can't reach the ${name} service. Retrying...`,
    schema: `The ${name} service sent data this app can't read. Nothing was changed.`,
    wallet: {
      rejected: 'Declined in wallet. Nothing was sent.',
      unsupported_feature: `This wallet can't sign ${name} orders.`,
      modified_message: `This wallet can't sign ${name} orders.`,
      bad_signature: `This wallet can't sign ${name} orders.`,
      disconnected: 'Wallet disconnected.',
      account_changed: 'Your wallet switched to another account. Nothing was sent.',
      locked: 'Unlock your wallet to continue.',
      busy: 'Your wallet already has a request open.',
      timeout: 'Your wallet did not answer in time.',
      abandoned: 'Not sent (cancelled).',
      unknown: 'The wallet reported an error. Nothing was sent.',
    },
    generic: 'Something went wrong. Nothing was sent.',
    versionMismatch: 'This app version is not compatible with the server. Reload.',
    SKEW: 'Your clock is off. Times shown use server time. Try again.',
    SESSION_TEMPLATE_INVALID: "Your wallet's sign-in message isn't in a format this app accepts.",
    SESSION_DOMAIN_MISMATCH: 'This sign-in was for another site.',
    SESSION_NONCE_INVALID: 'Sign-in expired. Try again.',
    SESSION_METHOD_REFUSED: 'This deployment needs a wallet that supports Sign-In.',
    MARKET_UNKNOWN: 'This market is not available.',
    pruned: 'This epoch is older than the service keeps. Its public data is in the archive.',
    NOT_YET_AVAILABLE: 'Still checking against Solana...',
    EPOCH_TOO_FAR: (epoch: string) => `Queued up to #${epoch}; later epochs need the app open.`,
    MARKET_UNAVAILABLE: 'Service is recovering. Orders can’t be placed right now.',
    DRAINING: 'The service is restarting. Try again shortly.',
  },

  /** A tick whose price has no finite decimal. */
  tickFallback: (tick: string) => `tick ${tick}`,
} as const;
