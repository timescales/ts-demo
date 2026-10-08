// Orders screen copy (normative). Product-name strings
// interpolate brand.name so a rename stays a one-file change.
import { brand } from '../../design/brand';

const name = brand.name;

export const ordersCopy = {
  title: 'Orders',
  noWallet:
    'Connect a wallet to see your orders. Order details are stored only on the device that sealed them.',
  noSession:
    'Start a trading session to load your orders. Your wallet signs once. Each order still needs its own signature.',
  connect: 'Connect wallet',
  startSession: 'Start session',
  loading: 'Loading orders',

  tabs: {
    label: 'Order lists',
    working: 'Working',
    history: 'History',
    fills: 'Fills',
    evidence: 'Evidence',
  },

  table: {
    working: 'Working orders',
    history: 'Order history',
    market: 'Market',
    side: 'Side',
    role: 'Role',
    qty: 'Qty',
    limit: 'Limit',
    filled: 'Filled',
    epochs: 'Epochs',
    status: 'Status',
    updated: 'Updated',
    open: 'Details',
    openLabel: (market: string, epochs: string) => `Order details, ${market}, epochs ${epochs}`,
    maker: 'Maker',
    taker: 'Taker',
    market_order: 'Market',
    epochRange: (from: string, to: string) => (from === to ? `#${from}` : `#${from}-#${to}`),
    percent: (p: string) => `${p}%`,
  },

  empty: {
    working: 'No working orders. Sealed orders appear here with their epoch and status.',
    history: 'Nothing yet.',
    fills: 'Nothing yet.',
    evidence:
      'No evidence. If a relay ever breaks a promise or a check fails, the proof is kept here.',
  },

  /**: one text per SDK state. `epoch` and the extras come from the record. */
  badge: {
    draft: 'Draft',
    awaiting_wallet: 'Confirm in wallet',
    wallet_rejected: 'Not sent (declined in wallet)',
    unsupported_wallet: `This wallet can't sign ${name} orders`,
    abandoned: 'Not sent (cancelled)',
    signed_too_late: 'Nothing was sent. Sign again',
    submitting: 'Submitting',
    submit_failed: (reason: string) => `Not sent: ${reason}`,
    working: 'Working',
    paused_needs_app: `Paused: open ${name} to continue`,
    reseal_needs_consent: (epoch: string) => `Details public after voided #${epoch}: re-place?`,
    filled: 'Filled',
    expired: 'Expired',
    cancel_pending: (epoch: string) => `Cancelling in #${epoch}`,
    cancelled: 'Cancelled',
    cancel_too_late: 'Too late: already traded',
    verification_failed: (what: string) => `Could not verify ${what}: do not rely on this result`,
    sealed: (epoch: string) => `Sealed - #${epoch}`,
    parked: (from: string, to: string) =>
      from === to ? `Queued - #${from}` : `Queued - #${from}-#${to}`,
    not_submitted: (after: string) => `Epochs after #${after} need ${name} open`,
    not_submitted_reason: {
      quota: (epoch: string) => `Not queued for #${epoch}: quota reached, needs ${name} open`,
      batch_full: (epoch: string) => `Not sealed into #${epoch}: the batch was full`,
      key_unavailable: (epoch: string) => `Not sealed into #${epoch}: its key was not ready`,
      invalidated: (epoch: string) => `Not submitted for #${epoch}`,
    },
    locked: 'Locked for clearing',
    included: (epoch: string) => `In batch #${epoch} ✓`,
    excluded: (epoch: string) =>
      `Left out of batch #${epoch} although the relay promised it, evidence saved`,
    clearing: 'Clearing...',
    clearingDelayed: 'Clearing delayed',
    provisional: (have: number, need: number) =>
      `Result posted, awaiting co-signature (${have}/${need})`,
    verifiedFilled: (percent: string, price: string) => `Filled ${percent}% at ${price} - settling`,
    betterThanLimit: (percent: string) => `${percent}% better than your limit`,
    verifiedNone: (epoch: string) => `Not filled in #${epoch}`,
    settling: (done: number, total: number) => `Settling on Solana ${done}/${total}`,
    settledFilled: 'Filled - settled ✓',
    settled: 'Settled ✓',
    voidedContinues: (epoch: string, next: string) =>
      `Epoch #${epoch} voided: nothing traded. Your order continues in #${next}`,
    voidedEnded: (epoch: string) => `Epoch #${epoch} voided: nothing traded. Your order has ended`,
  },

  whyNotFilled: 'Why?',
  whyNotFilledText: `${name} does not publish reasons. Possible causes: your limit was outside where the batch cleared, your available balance did not cover it when the batch was sealed, you had orders on both sides of this book (self-trade prevention), rationing at the clearing price, or your price was outside this epoch's band.`,

  drawer: {
    title: 'Order details',
    summary: 'Order',
    timeline: 'Epochs this order joined',
    lane: (epoch: string) => `Epoch #${epoch}`,
    noLanes: 'Not sealed into any epoch yet.',
    checklist: (epoch: string) => `Checks for epoch #${epoch}`,
    epochLink: (epoch: string) => `Epoch #${epoch} on the explorer`,
    commitment: 'Commitment',
    envelope: 'Envelope digest',
    promise: 'Relay promise',
    relay: 'Relay at submission',
    reveal: 'Reveal',
    hide: 'Hide',
    cancel: 'Cancel order',
    exportEvidence: 'Export evidence',
    privateNote: 'Stored only on this device (encrypted).',
  },

  checks: {
    key: 'Key vouched by committee',
    binding: 'Epoch binding',
    promise: 'Relay promise',
    root: 'In batch root',
    executor: 'Receipt by registered executor',
    quorum: 'Quorum',
    quorumValue: (have: number, need: number) => `Quorum ${have}/${need}`,
    fills: 'Fills recomputed',
    balance: 'Own balance entry',
    settled: 'Settled on chain',
    passed: 'passed',
    failed: 'failed',
    checking: 'checking...',
    pending: 'not yet',
    notApplicable: 'not reached: epoch voided',
    detail: {
      key: 'The epoch key carries at least t signatures of the committee whose digest is on chain (V-3).',
      binding:
        'The announced band, price commitment, key and committee hash to the on-chain terms digest (V-4).',
      promise: (digest: string) => `The relay signed a promise for envelope ${digest} (V-5).`,
      root: 'Your commitment and envelope digest are leaves of the committed batch root (V-6).',
      executor: 'The receipt is signed by an executor registered for this market (V-7).',
      quorum: 'Enough registered executors co-signed the same outcome (V-7).',
      fills: 'Your fills were recomputed from the published artifacts (V-8, V-9).',
      balance: 'Your balance entry in the published sheet matches the chain (V-9).',
      settled: 'The settlement was applied on Solana (V-10).',
    },
  },

  fills: {
    caption: 'Your verified fills',
    market: 'Market',
    epoch: 'Epoch',
    book: 'Book',
    side: 'Side',
    role: 'Role',
    quantity: 'Quantity',
    price: 'Price',
    fee: 'Fee',
    base: 'Base',
    quote: 'Quote',
    status: 'Status',
    provisional: 'Provisional',
    settled: 'Settled',
    exportCsv: 'Export CSV',
    csvName: 'fills.csv',
    csvHint: 'Generated on this device. Nothing is uploaded.',
    single: 'Single book',
  },

  evidence: {
    caption: 'Saved evidence',
    kind: 'Kind',
    market: 'Market',
    epoch: 'Epoch',
    saved: 'Saved',
    export: 'Export',
    exportLabel: (kind: string, epoch: string) => `Export ${kind} evidence for epoch ${epoch}`,
    kinds: {
      exclusion: 'Left out of a batch',
      substitution: 'Envelope substituted',
      terms: 'Terms or binding mismatch',
      refusal: 'Relay refusal',
      verification_failed: 'Verification failed',
    },
    verifyHint: 'Exported evidence can be checked on the Verify page by anyone.',
    loadFailed: 'Saved evidence could not be read on this device.',
  },

  journal: {
    title: 'Order details on this device',
    body: (lastExport: string) =>
      `Order details are stored only on this device (encrypted). Last export: ${lastExport}.`,
    never: 'never',
    memory:
      'Private window: order details will be lost when this tab closes. Keep it open or export.',
    notPersistent: 'This browser may delete your order details. Export a backup.',
    export: 'Export',
    import: 'Import',
    reconcile: 'Reconcile',
  },

  cancel: {
    title: 'Cancel order',
    body: (epoch: string) =>
      `Cancelling seals a cancel into epoch #${epoch} (one wallet signature). Removing your queued envelopes for later epochs relies on the operator. The cancel itself is guaranteed by the protocol once #${epoch} clears.`,
    confirm: 'Seal cancel',
    keep: 'Keep order',
    stepsLabel: 'Cancel progress',
    confirmWallet: 'Confirm in wallet',
    sealing: 'Sealing the cancel',
    submitting: 'Submitting',
    done: (epoch: string) => `Cancelling in #${epoch}`,
    failed: (reason: string) => `Not sent: ${reason}`,
    retry: 'Retry',
    close: 'Close',
  },

  secondPrompt: {
    title: 'Another wallet signature',
    body: (why: string) => `This needs another wallet signature: ${why}.`,
    cancelEpochClosed:
      'the cancel epoch closed before your wallet signed, so the cancel must name a later epoch',
    sign: 'Sign',
    cancel: 'Cancel',
  },

  reseal: {
    title: 'Re-place this order?',
    body: (epoch: string) =>
      `Your order's details became public in voided epoch #${epoch}. Re-place it with a fresh signature?`,
    detail:
      'A fresh signature gives the order a new commitment, so it is not linked to the public one. Nothing is re-sealed without your signature.',
    replace: 'Re-place (1 wallet signature)',
    notNow: 'Not now',
  },

  exportDialog: {
    title: 'Export order details',
    body: 'The backup is encrypted with this passphrase. You need it to import the backup on another device.',
    passphrase: 'Passphrase',
    confirm: 'Repeat passphrase',
    tooShort: 'Use at least 12 characters.',
    mismatch: 'The passphrases differ.',
    export: 'Export',
    exporting: 'Encrypting...',
    done: 'Backup saved.',
    failed: 'The backup could not be created.',
    fileName: 'order-details.backup',
  },

  importDialog: {
    title: 'Import order details',
    body: 'Choose a backup exported from this wallet and enter its passphrase.',
    file: 'Backup file',
    passphrase: 'Passphrase',
    noFile: 'Choose a backup file.',
    import: 'Import',
    importing: 'Decrypting...',
    done: (imported: number, skipped: number) =>
      `Imported ${imported} ${imported === 1 ? 'record' : 'records'}; ${skipped} already here.`,
    errors: {
      bad_passphrase: 'Wrong passphrase, or the backup is damaged.',
      other_wallet: 'This backup belongs to another wallet, program or cluster.',
      unsupported_export: 'This file is not a backup this app can read.',
      generic: 'The backup could not be imported.',
    },
  },

  reconcile: {
    title: 'Reconcile with the chain',
    body: 'Re-sends anything waiting in the outbox, follows every epoch with your orders and scans recent epochs for your fills (at most the last 1024).',
    from: 'From epoch',
    fromHint: 'Scan closed epochs from this one on.',
    invalid: 'Enter an epoch number.',
    run: 'Reconcile',
    running: 'Reconciling...',
    report: (r: {
      attached: number;
      foreignFills: number;
      outboxResent: number;
      inconclusive: number;
    }) =>
      `Attached ${r.attached} fills, re-sent ${r.outboxResent} submissions, ${r.foreignFills} fills from other devices, ${r.inconclusive} epochs still inconclusive.`,
    failed: 'Reconcile did not finish.',
  },

  close: 'Close',
} as const;
