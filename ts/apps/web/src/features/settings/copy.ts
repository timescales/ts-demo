import { brand } from '../../design/brand';

const name = brand.name;

export const settingsCopy = {
  title: 'Settings',
  lede: 'Stored on this device only.',
  display: {
    title: 'Display',
    theme: 'Theme',
    themes: { system: 'System', dark: 'Dark', light: 'Light' },
    palette: 'Buy and sell colours',
    palettes: { standard: 'Standard', cvd: 'Colour-vision safe' },
    paletteHint: 'Sides always carry ▲ / ▼ and a word as well.',
    reduceMotion: 'Reduce motion',
    reduceMotionHint: 'Removes the slat animations and the ring sweep.',
    numberFormat: 'Number format',
    numberFormatHint:
      'How you type and read quantities and prices. Ambiguous separators are rejected.',
    formats: {
      dot: '1,234.56',
      comma: '1.234,56',
      space: '1 234,56',
      plain: '1234.56',
    },
  },
  accessibility: {
    title: 'Accessibility',
    announcePhases: 'Announce market phase changes',
    announcePhasesHint:
      'Off by default. Screen readers then hear only about your own orders and the steps you take.',
    shortcuts: 'Ticket keyboard shortcuts',
    shortcutsHint:
      'B / S side, M / T role, Enter to review, Ctrl or ⌘ + Enter to seal. Ignored while typing.',
  },
  privacy: {
    title: 'Privacy',
    privacyScreen: 'Privacy screen',
    privacyScreenHint: 'Mask private values until you reveal them. Alt+H hides all values again.',
    autoHide: 'Auto-hide values',
    autoHideHint: 'Masks every value after this much idle time. It is not a lock.',
    autoHideOff: 'Off',
    autoHideMinutes: (n: number) => (n === 1 ? 'After 1 minute' : `After ${n} minutes`),
  },
  network: {
    title: 'Network',
    primary: 'Solana RPC',
    crossCheck: 'Cross-check RPC',
    crossCheckNone: 'None',
    crossCheckHint:
      "Each market is read again through this RPC after it verifies. If the two disagree about the market's fixed fields, trading on it stops. The privacy note below applies to this RPC too.",
    warning:
      'The RPC provider sees your IP address and every query this app makes, including which accounts you look at.',
    allowlist: `Only RPC endpoints vetted for this build are offered. A custom RPC needs a self-hosted build that adds its origin to the allowlist and the content security policy.`,
    noAllowlist: 'This build lists no RPC endpoint.',
    check: 'Check connection',
    checking: 'Checking...',
    healthy: (label: string) => `${label} answered getHealth: ok.`,
    unhealthy: (label: string) => `${label} did not answer getHealth with ok.`,
  },
  session: {
    title: 'This session',
    none: 'No trading session.',
    noWallet: 'Connect a wallet to start a trading session.',
    active: (when: string) => `Expires in ${when}.`,
    ended: 'Ended. Renewing needs one wallet signature.',
    revoke: 'End session',
    evictionNote: 'Creating a new session elsewhere may revoke the oldest one.',
  },
  data: {
    title: 'Local data',
    noWallet: 'Connect a wallet to manage the order details stored for it.',
    persistence: {
      persistent: 'Order details are stored encrypted and the browser keeps them.',
      not_persistent: 'This browser may delete your order details. Export a backup.',
      private_window:
        'Private window: order details will be lost when this tab closes. Keep it open or export.',
      unreadable: 'Some local records can’t be read on this device.',
      full: 'This device is out of storage. Nothing was sent.',
    },
    passphrase: 'Backup passphrase',
    passphraseHint: 'At least 12 characters. Without it the backup cannot be opened.',
    passphraseShort: 'Use at least 12 characters.',
    export: 'Export backup',
    exporting: 'Encrypting...',
    exported: 'Backup saved.',
    importFile: 'Backup file',
    import: 'Import backup',
    importing: 'Decrypting...',
    imported: (n: number, skipped: number) =>
      `Imported ${n} record${n === 1 ? '' : 's'}; ${skipped} already here.`,
    importFailed: 'The backup could not be opened: wrong passphrase or not a backup.',
    wipeTitle: 'Delete local data',
    wipe: 'This deletes order details stored on this device. Fills stay visible on chain, but unfilled orders and their secrets cannot be recovered. Type DELETE to continue.',
    wipeConfirm: 'Type DELETE',
    wipeWord: 'DELETE',
    wipeButton: 'Delete order details',
    wiped: 'Order details on this device were deleted.',
  },
  notifications: {
    title: 'Notifications',
    text: `${name} sends no notifications in this version. If they are added, they will be off by default and will never contain amounts.`,
  },
} as const;
