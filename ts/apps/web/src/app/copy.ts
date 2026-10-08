// Copy of the app shell: navigation, the banners, the session dialog and
// the insecure-context guard. Product-name strings interpolate brand.name.
import { brand } from '../design/brand';

const name = brand.name;

export const appCopy = {
  notFoundTitle: 'Page not found',
  notFoundBody: 'There is nothing at this address.',
  notFoundHome: 'Go to the start',
  skipToContent: 'Skip to content',
  loadingPage: 'Loading page',
  pageError: 'This page could not be shown.',
  reload: 'Reload',
  nav: {
    trade: 'Trade',
    orders: 'Orders',
    funds: 'Funds',
    epochs: 'Epochs',
    more: 'More',
    status: 'Status',
    privacy: 'Privacy',
    settings: 'Settings',
    verify: 'Verify',
    help: 'Help',
    activity: 'Activity',
  },
  insecure: {
    title: `${name} needs a secure (https) connection.`,
    body: 'Open this page over https. Device testing over a plain http LAN address fails by design. Use the HTTPS edge of the local stack.',
  },
  noMarket: 'No market is available yet.',
  walletMenu: {
    address: 'wallet address',
    switch: 'Switch wallet',
    disconnect: 'Disconnect',
  },
  lastResult: (epoch: string, price: string, phase: string) =>
    `#${epoch} cleared ${price} - ${phase}`,
  catchingUp: 'Catching up...',
  phaseAnnouncement: (epoch: string, phase: string) => `Epoch ${epoch}: ${phase}`,
  banners: {
    verificationThing: {
      'V-1': 'this market against your Solana RPC',
      'V-2': "this market's key committee",
      'V-3': 'the encryption key of the open epoch',
      'V-4': "the relay's announcement for the open epoch",
      'V-14': "the key committee's release policies",
      'V-16': 'the settlement program',
      fallback: 'this market',
    } as Record<string, string>,
    nodeRpcDisagree: 'The service and your Solana RPC disagree about this market.',
    rpcsDisagree: 'Your Solana RPC and your cross-check RPC disagree about this market.',
    inconclusive: (thing: string) => `Still checking ${thing} against Solana...`,
    keyNotVouched: (epoch: string) =>
      `The encryption key for #${epoch} could not be verified, so nothing was sealed.`,
    retryLater: 'Retry later',
    excluded: (epoch: string) =>
      `Batch #${epoch} didn't include your sealed order although the relay promised it. Evidence saved.`,
    termsMismatch: (epoch: string) =>
      `The relay committed different terms or keys for #${epoch} than it announced. Evidence saved.`,
    exportEvidence: 'Export evidence',
    versionMismatch: 'This app version is not compatible with the server. Reload.',
    apiUnreachable: `Can't reach the ${name} service. Retrying...`,
    responseInvalid: `The ${name} service sent data this app can't read. Nothing was changed.`,
    statusPage: 'Status page',
    streamPaused: (n: number) => `Live updates paused. Reconnecting (${n})...`,
    streamPolling: 'Live updates unavailable. Refreshing every epoch.',
    rpcStale: "Solana RPC isn't responding. Balances and verification may be stale.",
    changeRpc: 'Change RPC',
    clockSkew: (seconds: string) =>
      `Your clock is off by ${seconds}s. Times shown use server time.`,
    intakePaused: (reason: string) =>
      `New orders paused: ${reason} Already-sealed orders are unaffected.`,
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
    halted: 'Market halted by its administrator. Withdrawals remain available.',
    recovering: "Service is recovering. Orders can't be placed right now.",
    settlementLag: 'Settlement is running behind.',
    voided: (epoch: string) => `Epoch #${epoch} was voided: nothing in it traded.`,
    walletSwitched: (address: string) =>
      `Your wallet switched to another account. ${name} reloaded for ${address}.`,
    walletDisconnected: 'Wallet disconnected.',
    walletLocked: 'Unlock your wallet to continue.',
    reconnect: 'Reconnect',
    unpinned: `This build does not pin this market. You can browse its epochs, but ${name} will not verify it or seal orders for it.`,
    noGenesis: `This build pins no genesis hash, so ${name} cannot check which cluster your RPC serves.`,
    funds: 'Funds',
    privacy: 'Privacy',
  },
  session: {
    secondPromptTitle: 'This needs another wallet signature',
    secondPrompt:
      "Your wallet's sign-in message isn't in a format the service accepts. Sign the standard sign-in text instead? This is a second wallet signature.",
    signAgain: 'Sign again',
    cancel: 'Cancel',
    errors: {
      SESSION_TEMPLATE_INVALID: `Your wallet's sign-in message isn't in a format ${name} accepts.`,
      SESSION_DOMAIN_MISMATCH: 'This sign-in was for another site.',
      SESSION_NONCE_INVALID: 'Sign-in expired. Try again.',
      SESSION_EXPIRED: 'Sign-in expired. Try again.',
      SESSION_METHOD_REFUSED: 'This deployment needs a wallet that supports Sign-In.',
      SESSION_REVOKED:
        'You signed in elsewhere, so this session ended. Renew (1 wallet signature).',
      SESSION_UNKNOWN: 'Session expired. Renew (1 wallet signature).',
      WALLET_NOT_ELIGIBLE: `Open a ${name} account and deposit first.`,
      rejected: 'Declined in wallet. Nothing was sent.',
      fallback: 'The session could not be started.',
    } as Record<string, string>,
  },
} as const;

/** Test-mode builds only. */
export const galleryCopy = {
  title: 'Component gallery',
  missing: 'No components are registered in this build yet.',
} as const;
