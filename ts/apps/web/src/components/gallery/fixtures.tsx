// Sample props for the gallery and the component tests. Values are
// illustrative placeholders, not data from any deployment.
import { ArrowLeftRight, Ellipsis, History, Layers, Wallet } from 'lucide-react';

import type { ActivityItem } from '../chrome/ActivityDrawer';
import type { StackBanner } from '../chrome/BannerStack';
import { GovernanceWatch } from '../chrome/GovernanceWatch';
import type { MarketOption } from '../chrome/MarketSelector';
import type { TabBarItem } from '../chrome/MobileTabBar';
import { SimulatedBanner } from '../chrome/SimulatedBanner';
import type { NavItem } from '../chrome/TopBar';
import { VerificationBanner } from '../chrome/VerificationBanner';
import type { WalletOption } from '../chrome/WalletPicker';

export const SAMPLE_ADDRESS = '7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU';
export const SAMPLE_HASH = '70ce57603071452b06ada713d60af73ae164138e2290a7942741a3f519174466';

export const NAV: readonly NavItem[] = [
  { href: '/trade/market', label: 'Trade', current: true },
  { href: '/orders', label: 'Orders' },
  { href: '/funds', label: 'Funds' },
  { href: '/epochs/market', label: 'Epochs' },
];

export const TABS: readonly TabBarItem[] = [
  {
    href: '/trade/market',
    label: 'Trade',
    icon: <ArrowLeftRight size={20} aria-hidden="true" />,
    current: true,
  },
  { href: '/orders', label: 'Orders', icon: <History size={20} aria-hidden="true" /> },
  { href: '/funds', label: 'Funds', icon: <Wallet size={20} aria-hidden="true" /> },
  { href: '/epochs/market', label: 'Epochs', icon: <Layers size={20} aria-hidden="true" /> },
  { href: '/settings', label: 'More', icon: <Ellipsis size={20} aria-hidden="true" /> },
];

export const MARKETS: readonly MarketOption[] = [
  { address: 'market-a', label: 'SOL/USDC', flow: 'dual_flow' },
  { address: 'market-b', label: 'JUP/USDC', flow: 'single_book' },
];

export const WALLETS: readonly WalletOption[] = [
  { id: 'a', name: 'Wallet A', tested: false, supported: true },
  { id: 'b', name: 'Wallet B', tested: true, supported: true },
  { id: 'c', name: 'Wallet C', tested: false, supported: false },
];

export const ACTIVITY: readonly ActivityItem[] = [
  { id: '1', title: 'Sealing order for #18422', status: 'pending', time: '12:01:04' },
  { id: '2', title: 'Deposit confirmed', status: 'done', time: '11:58:40' },
  {
    id: '3',
    title: 'Withdrawal expired before it landed',
    status: 'failed',
    detail: 'Nothing changed.',
  },
  { id: '4', title: 'Session expires soon', status: 'action' },
];

/**
 * The banner stack: the banner components as they are, then two connectivity
 * notices described as data. `sim` drives the collapsible SimulatedBanner.
 */
export function stackBanners(sim: { collapsed: boolean; onToggle: () => void }): StackBanner[] {
  return [
    {
      id: 'gov',
      severity: 'warning',
      element: (
        <GovernanceWatch
          changes={[{ kind: 'relay', eta: '23 h' }]}
          reviewHref="/status"
          fundsHref="/funds"
        />
      ),
    },
    {
      id: 'sim',
      severity: 'simulated',
      element: (
        <SimulatedBanner privacyHref="/privacy" collapsed={sim.collapsed} onToggle={sim.onToggle} />
      ),
    },
    {
      id: 'verify',
      severity: 'critical',
      element: (
        <VerificationBanner
          thing="the receipt for epoch #18421"
          onRecheck={() => undefined}
          onExport={() => undefined}
        />
      ),
    },
    {
      id: 'stream',
      severity: 'info',
      title: 'Live updates unavailable. Refreshing every epoch.',
      dismissible: true,
    },
    { id: 'rpc', severity: 'warning', title: 'Solana RPC isn’t responding.', dismissible: true },
  ];
}

export const BANNERS: readonly StackBanner[] = stackBanners({
  collapsed: false,
  onToggle: () => undefined,
});
