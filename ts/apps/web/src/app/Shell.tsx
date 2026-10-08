// The global chrome around every screen: top bar, epoch strip, banner
// stack, main content, activity drawer, mobile tab bar and the live status
// footer, plus the live regions and the privacy controls.
import {
  ArrowLeftRight,
  BookOpen,
  ClipboardList,
  Ellipsis,
  ListChecks,
  Wallet,
} from 'lucide-react';
import { useCallback, useEffect, useState } from 'react';
import { Link, Outlet, useLocation, useNavigate } from 'react-router';

import type { RenderLink, TabBarItem } from '../components/chrome';
import {
  ActivityDrawer,
  BannerStack,
  MarketSelector,
  MobileTabBar,
  TopBar,
} from '../components/chrome';
import { IconButton, Sheet, Skeleton } from '../components/primitives';
import { LiveRegions } from '../state/announcer';
import { formatDateTime } from '../state/format';
import { rememberMarket, useActivity, useLive, useLiveMarket, useMarketList } from '../state/hooks';
import { usePrivacyControls } from '../state/privacy';
import { useRuntime } from '../state/runtime';
import { applyDocumentSettings, useSettings } from '../state/settings';
import { useStore } from '../state/store';
import type { Address } from '../state/types';
import { parseAddress } from '../state/types';
import { useCriticalAnnouncements, useShellBanners } from './banners';
import { appCopy } from './copy';
import { useEpochChrome, useMarketPhaseAnnouncements } from './EpochChrome';
import { Footer } from './Footer';
import { routerLink } from './links';
import { useRouteMarket } from './routeMarket';
import styles from './Shell.module.css';
import { ShellTraderServices } from './TraderServices';
import { SessionControls, WalletControls } from './WalletControls';

const MORE = '#more';

function section(pathname: string): string {
  return '/' + (pathname.split('/')[1] ?? '');
}

/** Where the market selector goes when the market changes on this route. */
function marketPath(pathname: string, market: Address): string | null {
  const s = section(pathname);
  if (s === '/trade' || s === '/funds' || s === '/epochs') return `${s}/${market}`;
  return null;
}

export function ShellFallback() {
  return (
    <div className={styles.fallback}>
      <Skeleton lines={4} label={appCopy.loadingPage} />
    </div>
  );
}

export function Shell() {
  const runtime = useRuntime();
  const settings = useSettings();
  const navigate = useNavigate();
  const { pathname } = useLocation();
  const market = useRouteMarket();
  const { markets } = useMarketList();
  const current = useLiveMarket(market);
  const live = useLive();
  const activity = useActivity();
  const activityOpen = useStore(runtime.activity.open);
  const [pickerOpen, setPickerOpen] = useState(false);
  const [sessionOpen, setSessionOpen] = useState(false);
  const connectWallet = useCallback(() => setPickerOpen(true), []);
  const startSession = useCallback(() => setSessionOpen(true), []);
  const [moreOpen, setMoreOpen] = useState(false);
  const { strip, pill } = useEpochChrome(market, current);
  const { banners, onDismiss } = useShellBanners({
    market,
    onTrade: section(pathname) === '/trade',
  });

  useCriticalAnnouncements(banners);
  useEffect(() => applyDocumentSettings(settings), [settings]);
  usePrivacyControls(settings);
  useMarketPhaseAnnouncements(market);
  useEffect(() => {
    if (market !== null && parseAddress(pathname.split('/')[2]) === market) rememberMarket(market);
  }, [market, pathname]);

  const here = section(pathname);
  const m = market ?? '';
  const nav = [
    { href: market ? `/trade/${m}` : '/trade', label: appCopy.nav.trade, section: '/trade' },
    { href: '/orders', label: appCopy.nav.orders, section: '/orders' },
    { href: market ? `/funds/${m}` : '/funds', label: appCopy.nav.funds, section: '/funds' },
    { href: market ? `/epochs/${m}` : '/epochs', label: appCopy.nav.epochs, section: '/epochs' },
  ];
  const tabs: TabBarItem[] = [
    { ...nav[0]!, icon: <ArrowLeftRight size={20} aria-hidden="true" /> },
    { ...nav[1]!, icon: <ClipboardList size={20} aria-hidden="true" /> },
    { ...nav[2]!, icon: <Wallet size={20} aria-hidden="true" /> },
    { ...nav[3]!, icon: <BookOpen size={20} aria-hidden="true" /> },
    { href: MORE, label: appCopy.nav.more, icon: <Ellipsis size={20} aria-hidden="true" /> },
  ].map((t) => ({ ...t, current: 'section' in t && t.section === here }));

  const renderTab: RenderLink = (props) =>
    props.href === MORE ? (
      <button
        type="button"
        className={props.className}
        aria-haspopup="dialog"
        onClick={() => setMoreOpen(true)}
      >
        {props.children}
      </button>
    ) : (
      routerLink(props)
    );

  return (
    <div className={styles.app}>
      <a href="#main" className={styles.skip}>
        {appCopy.skipToContent}
      </a>
      <TopBar
        homeHref="/"
        nav={nav.map((n) => ({ href: n.href, label: n.label, current: n.section === here }))}
        market={
          markets.length > 0 && market !== null ? (
            <MarketSelector
              compact
              markets={markets}
              value={market}
              onChange={(next) => {
                const address = parseAddress(next);
                if (address === null) return;
                rememberMarket(address);
                const path = marketPath(pathname, address);
                if (path !== null) void navigate(path);
              }}
            />
          ) : null
        }
        session={
          <SessionControls market={market} open={sessionOpen} onOpenChange={setSessionOpen} />
        }
        wallet={
          <div className={styles.actions}>
            <IconButton
              label={appCopy.nav.activity}
              icon={<ListChecks size={20} aria-hidden="true" />}
              onClick={() => runtime.activity.setOpen(true)}
            />
            <WalletControls pickerOpen={pickerOpen} onPickerOpenChange={setPickerOpen} />
          </div>
        }
        epochPill={pill}
        renderLink={routerLink}
      />
      {strip}
      <div className={styles.banners}>
        <BannerStack banners={banners} onDismiss={onDismiss} />
      </div>
      {live.catchingUp ? <p className={styles.catchingUp}>{appCopy.catchingUp}</p> : null}
      <main id="main" tabIndex={-1} className={styles.main}>
        <ShellTraderServices connectWallet={connectWallet} startSession={startSession}>
          <Outlet />
        </ShellTraderServices>
      </main>
      <ActivityDrawer
        open={activityOpen}
        onClose={() => runtime.activity.setOpen(false)}
        items={activity.map((e) => ({
          id: e.id,
          title: e.title,
          status: e.status,
          detail: e.detail,
          time: formatDateTime(e.atMs),
        }))}
      />
      <Sheet open={moreOpen} onClose={() => setMoreOpen(false)} title={appCopy.nav.more}>
        <ul className={styles.moreList}>
          {(
            [
              ['/verify', appCopy.nav.verify],
              ['/status', appCopy.nav.status],
              ['/privacy', appCopy.nav.privacy],
              ['/settings', appCopy.nav.settings],
            ] as const
          ).map(([href, label]) => (
            <li key={href}>
              <Link to={href} className={styles.moreLink} onClick={() => setMoreOpen(false)}>
                {label}
              </Link>
            </li>
          ))}
          <li>
            <button
              type="button"
              className={styles.moreLink}
              onClick={() => {
                setMoreOpen(false);
                runtime.activity.setOpen(true);
              }}
            >
              {appCopy.nav.activity}
            </button>
          </li>
        </ul>
      </Sheet>
      <MobileTabBar items={tabs} renderLink={renderTab} />
      <Footer market={market} />
      <LiveRegions announcer={runtime.announcer} />
    </div>
  );
}
