import '../../styles/index.css';

import { Lock } from 'lucide-react';
import type { ReactNode } from 'react';
import { useEffect, useState } from 'react';

import { galleryCopy } from '../../app/copy';
import { brand } from '../../design/brand';
import { Wordmark } from '../../design/Wordmark';
import { ActivityDrawer } from '../chrome/ActivityDrawer';
import { BannerStack } from '../chrome/BannerStack';
import { EpochPill } from '../chrome/EpochPill';
import { EpochStrip } from '../chrome/EpochStrip';
import { GovernanceWatch } from '../chrome/GovernanceWatch';
import { MarketSelector } from '../chrome/MarketSelector';
import { MobileTabBar } from '../chrome/MobileTabBar';
import { PersistenceWarning } from '../chrome/PersistenceWarning';
import { SessionChip } from '../chrome/SessionChip';
import { SimulatedBanner } from '../chrome/SimulatedBanner';
import type { EnclaveTrust } from '../chrome/StatusFooter';
import { StatusFooter } from '../chrome/StatusFooter';
import { TopBar } from '../chrome/TopBar';
import { VerificationBanner } from '../chrome/VerificationBanner';
import { WalletButton } from '../chrome/WalletButton';
import { WalletPicker } from '../chrome/WalletPicker';
import { DirectionGlyph } from '../motif/DirectionGlyph';
import { EpochRing } from '../motif/EpochRing';
import { SealGlyph } from '../motif/SealGlyph';
import { SimStripe } from '../motif/SimStripe';
import { Slats } from '../motif/Slats';
import { VerifiedSeal } from '../motif/VerifiedSeal';
import { Badge } from '../primitives/Badge';
import { Banner } from '../primitives/Banner';
import { Button } from '../primitives/Button';
import { CopyHash } from '../primitives/CopyHash';
import { Dialog } from '../primitives/Dialog';
import { Drawer } from '../primitives/Drawer';
import { EmptyState } from '../primitives/EmptyState';
import { IconButton } from '../primitives/IconButton';
import { InlineError } from '../primitives/InlineError';
import { KeyboardShortcut } from '../primitives/KeyboardShortcut';
import { MaskedValue } from '../primitives/MaskedValue';
import { NumberField } from '../primitives/NumberField';
import { PhaseBadge } from '../primitives/PhaseBadge';
import { Select } from '../primitives/Select';
import { Sheet } from '../primitives/Sheet';
import { SimulatedLabel } from '../primitives/SimulatedLabel';
import { Skeleton } from '../primitives/Skeleton';
import { Stepper } from '../primitives/Stepper';
import { Table } from '../primitives/Table';
import { Tabs } from '../primitives/Tabs';
import { TextField } from '../primitives/TextField';
import { ToggleGroup } from '../primitives/ToggleGroup';
import { Tooltip } from '../primitives/Tooltip';
import type { PublicPhase, Side } from '../types';
import {
  ACTIVITY,
  stackBanners,
  MARKETS,
  NAV,
  SAMPLE_ADDRESS,
  SAMPLE_HASH,
  TABS,
  WALLETS,
} from './fixtures';
import styles from './Gallery.module.css';

const PHASES: PublicPhase[] = [
  'scheduled',
  'open',
  'closed',
  'committed',
  'revealed',
  'executing',
  'posted',
  'settled',
  'aborting',
  'aborted',
];

type Overlay = 'dialog' | 'sheet' | 'drawer' | 'activity' | 'wallets' | null;

const OVERLAYS: readonly Exclude<Overlay, null>[] = [
  'dialog',
  'sheet',
  'drawer',
  'activity',
  'wallets',
];

const ENCLAVES: readonly EnclaveTrust[] = ['simulated', 'tdx_vouched', 'tdx_reported'];

function readParams() {
  const params = new URLSearchParams(typeof location === 'undefined' ? '' : location.search);
  const open = params.get('open');
  const enclave = params.get('enclave');
  return {
    theme: params.get('theme'),
    palette: params.get('palette'),
    open: (OVERLAYS as readonly string[]).includes(open ?? '') ? (open as Overlay) : null,
    enclave: (ENCLAVES as readonly string[]).includes(enclave ?? '')
      ? (enclave as EnclaveTrust)
      : 'simulated',
  };
}

function Section({ title, children }: { title: string; children: ReactNode }) {
  return (
    <section className={styles.section} aria-labelledby={`gallery-${title}`}>
      <h2 id={`gallery-${title}`}>{title}</h2>
      <div className={styles.grid}>{children}</div>
    </section>
  );
}

function Item({ name, children }: { name: string; children: ReactNode }) {
  return (
    <div className={styles.item}>
      <h3 className={styles.name}>{name}</h3>
      <div className={styles.states}>{children}</div>
    </div>
  );
}

/**
 * Every shared component in its states, for the browser axe run (contrast,
 * focus visibility, target size). Test-mode builds only. Query
 * parameters: theme=dark|light, palette=cvd, open=dialog|sheet|drawer|activity|wallets,
 * enclave=simulated|tdx_vouched|tdx_reported (the fixed footer's label).
 */
export default function Gallery() {
  const [params] = useState(readParams);
  const [overlay, setOverlay] = useState<Overlay>(params.open);
  const [side, setSide] = useState<Side | ''>('buy');
  const [qty, setQty] = useState('12.5');
  const [price, setPrice] = useState('182.371');
  const [market, setMarket] = useState('market-a');
  const [revealed, setRevealed] = useState(false);
  const [simCollapsed, setSimCollapsed] = useState(false);

  useEffect(() => {
    document.title = galleryCopy.title;
    const root = document.documentElement;
    if (params.theme) root.dataset.theme = params.theme;
    if (params.palette) root.dataset.palette = params.palette;
  }, [params]);

  const close = () => setOverlay(null);

  return (
    <div className={styles.page}>
      <TopBar
        homeHref="/"
        nav={NAV}
        market={
          <MarketSelector
            markets={MARKETS}
            compact
            value={market}
            onChange={setMarket}
            id="topbar-market"
          />
        }
        session={<SessionChip state="active" remainingSeconds={4520} onAction={() => undefined} />}
        wallet={
          <WalletButton
            state="connected"
            walletName="Wallet A"
            address={SAMPLE_ADDRESS}
            onClick={() => undefined}
          />
        }
        epochPill={
          <EpochPill
            market="SOL/USDC"
            epoch="18422"
            phase="open"
            secondsToCutoff={7}
            progress={0.65}
          />
        }
      />
      <EpochStrip
        market="SOL/USDC"
        epoch="18422"
        phase="open"
        secondsToCutoff={7}
        progress={0.65}
        warning
        inFlight={{ epoch: '18421', phase: 'executing' }}
        lastResult="#18420 cleared 182.37 - settled"
      />
      <main id="main" className={styles.main}>
        <h1>{galleryCopy.title}</h1>

        <Section title="Brand">
          <Item name="Wordmark">
            <Wordmark height={40} />
          </Item>
        </Section>

        <Section title="Primitives">
          <Item name="Button">
            <Button variant="primary">Seal order</Button>
            <Button>Review</Button>
            <Button variant="ghost">Cancel</Button>
            <Button variant="danger">Wipe local data</Button>
            <Button variant="primary" busy>
              Submitting
            </Button>
            <Button disabled>Disabled</Button>
          </Item>
          <Item name="IconButton">
            <IconButton label="Lock values" icon={<Lock size={18} aria-hidden="true" />} />
            <IconButton
              variant="secondary"
              label="Lock all values"
              icon={<Lock size={18} aria-hidden="true" />}
            />
          </Item>
          <Item name="ToggleGroup">
            <ToggleGroup
              label="Side"
              value={side}
              onValueChange={setSide}
              options={[
                { value: 'buy', label: 'Buy ▲', tone: 'buy' },
                { value: 'sell', label: 'Sell ▼', tone: 'sell' },
              ]}
            />
          </Item>
          <Item name="TextField">
            <TextField label="Label" hint="Helper text" defaultValue="Text" />
            <TextField label="With error" error="This field needs a value." defaultValue="" />
          </Item>
          <Item name="NumberField">
            <NumberField
              label="Quantity"
              unit="SOL"
              value={qty}
              onValueChange={setQty}
              hint="25 / 50 / 100 % of available"
            />
            <NumberField
              label="Limit price"
              unit="USDC"
              value={price}
              onValueChange={setPrice}
              exact="Signed price: 182.37"
              error="Won't trade at this epoch's band."
            />
          </Item>
          <Item name="Select">
            <Select
              label="Number format"
              value="dot"
              onValueChange={() => undefined}
              options={[
                { value: 'dot', label: '1,234.56' },
                { value: 'comma', label: '1.234,56' },
              ]}
            />
          </Item>
          <Item name="Tabs">
            <Tabs
              label="Orders"
              items={[
                { value: 'working', label: 'Working', content: <p>Working orders</p> },
                { value: 'history', label: 'History', content: <p>History</p> },
                { value: 'fills', label: 'Fills', content: <p>Fills</p> },
              ]}
            />
          </Item>
          <Item name="Tooltip">
            <Tooltip content={`${brand.name} does not publish reasons.`}>
              <Button size="sm">Why?</Button>
            </Tooltip>
          </Item>
          <Item name="Dialog / Sheet / Drawer">
            <Button onClick={() => setOverlay('dialog')}>Open dialog</Button>
            <Button onClick={() => setOverlay('sheet')}>Open sheet</Button>
            <Button onClick={() => setOverlay('drawer')}>Open drawer</Button>
          </Item>
          <Item name="Badge">
            <Badge>Neutral</Badge>
            <Badge tone="accent">Sealed - #18422</Badge>
            <Badge tone="buy">Filled - settled</Badge>
            <Badge tone="sell">Sell</Badge>
            <Badge tone="info">Public</Badge>
            <Badge tone="warning">Clearing delayed</Badge>
            <Badge tone="danger">Verification failed</Badge>
            <Badge tone="simulated">Simulated</Badge>
          </Item>
          <Item name="PhaseBadge">
            {PHASES.map((phase) => (
              <PhaseBadge key={phase} phase={phase} />
            ))}
          </Item>
          <Item name="SimulatedLabel">
            <SimulatedLabel />
            <SimulatedLabel kind="modelled" />
            <SimulatedLabel kind="untested" />
          </Item>
          <Item name="Banner">
            <Banner severity="critical" title="Critical banner">
              Always expanded; cannot be dismissed.
            </Banner>
            <Banner severity="warning" title="Warning banner" onDismiss={() => undefined}>
              Dismissible.
            </Banner>
            <Banner severity="info" title="Info banner" collapsed onToggle={() => undefined}>
              Collapsed body.
            </Banner>
          </Item>
          <Item name="Skeleton">
            <Skeleton lines={3} />
          </Item>
          <Item name="CopyHash">
            <CopyHash value={SAMPLE_HASH} label="state root" onCopy={() => undefined} />
          </Item>
          <Item name="MaskedValue">
            <MaskedValue revealed={revealed} onRevealedChange={setRevealed}>
              12.500 SOL
            </MaskedValue>
            <MaskedValue revealed onRevealedChange={() => undefined}>
              182.37 USDC
            </MaskedValue>
          </Item>
          <Item name="Stepper">
            <Stepper
              label="Seal order"
              steps={[
                { id: 'sign', label: 'Confirm in wallet', status: 'done' },
                { id: 'encrypt', label: 'Encrypting to epoch #18422 key', status: 'current' },
                { id: 'submit', label: 'Submitting', status: 'upcoming' },
                {
                  id: 'receipt',
                  label: 'Relay receipt verified',
                  status: 'error',
                  detail: <InlineError>Not sent: busy.</InlineError>,
                },
              ]}
            />
          </Item>
          <Item name="Table">
            <Table
              caption="Clearing tape"
              columns={[
                {
                  key: 'epoch',
                  header: 'Epoch',
                  cell: (r: { epoch: string; price: string }) => r.epoch,
                  numeric: true,
                },
                {
                  key: 'price',
                  header: 'Clearing price',
                  cell: (r: { epoch: string; price: string }) => r.price,
                  numeric: true,
                },
              ]}
              rows={[
                { epoch: '18421', price: '182.37' },
                { epoch: '18420', price: '182.12' },
              ]}
              rowKey={(r) => r.epoch}
            />
          </Item>
          <Item name="EmptyState">
            <EmptyState
              as="p"
              title="No epochs yet."
              body="The first result appears about one interval after the first cutoff."
            />
          </Item>
          <Item name="InlineError">
            <InlineError>Declined in wallet. Nothing was sent.</InlineError>
          </Item>
          <Item name="KeyboardShortcut">
            <KeyboardShortcut keys={['Ctrl', 'Enter']} />
          </Item>
        </Section>

        <Section title="Motif">
          <Item name="Slats">
            <Slats state="closed" />
            <Slats state="open" />
          </Item>
          <Item name="SealGlyph">
            <SealGlyph epoch="18422" />
          </Item>
          <Item name="VerifiedSeal">
            <VerifiedSeal />
          </Item>
          <Item name="EpochRing">
            <EpochRing progress={0.25} size={48} label="15 of 60 ticks elapsed" />
            <EpochRing progress={0.9} warning size={48} label="54 of 60 ticks elapsed" />
          </Item>
          <Item name="DirectionGlyph">
            <DirectionGlyph side="buy" />
            <DirectionGlyph side="sell" />
          </Item>
          <Item name="SimStripe">
            <SimStripe>
              <SimulatedLabel /> Values here come from a simulated component.
            </SimStripe>
          </Item>
        </Section>

        <Section title="Chrome">
          <Item name="BannerStack">
            <BannerStack
              banners={stackBanners({
                collapsed: simCollapsed,
                onToggle: () => setSimCollapsed((c) => !c),
              })}
              onDismiss={() => undefined}
            />
          </Item>
          <Item name="VerificationBanner">
            <VerificationBanner
              thing="the receipt for epoch #18421"
              onRecheck={() => undefined}
              onExport={() => undefined}
            />
          </Item>
          <Item name="GovernanceWatch">
            <GovernanceWatch
              changes={[
                { kind: 'relay', eta: '23 h' },
                { kind: 'timelock', eta: '2 days', decrease: true },
              ]}
              recentUpgradeAgo="3 h"
              reviewHref="/status"
              fundsHref="/funds"
            />
          </Item>
          <Item name="SimulatedBanner">
            <SimulatedBanner
              privacyHref="/privacy"
              collapsed={simCollapsed}
              onToggle={() => setSimCollapsed((c) => !c)}
            />
          </Item>
          <Item name="PersistenceWarning">
            <PersistenceWarning problem="private_window" onExport={() => undefined} />
          </Item>
          <Item name="WalletButton">
            <WalletButton state="disconnected" onClick={() => setOverlay('wallets')} />
            <WalletButton state="connecting" onClick={() => undefined} />
          </Item>
          <Item name="SessionChip">
            <SessionChip state="none" onAction={() => undefined} />
            <SessionChip state="active" remainingSeconds={120} onAction={() => undefined} />
            <SessionChip state="expired" onAction={() => undefined} />
          </Item>
          <Item name="ActivityDrawer">
            <Button onClick={() => setOverlay('activity')}>Open activity</Button>
          </Item>
          <Item name="StatusFooter (TDX variants)">
            <StatusFooter
              publishHeight={false}
              enclave="tdx_vouched"
              cluster="localnet"
              slot="1234567"
              rpc="ok"
              apiVersion="v1.0"
              api="ok"
              stream="live"
              reference="operator"
              links={{ status: '/status', privacy: '/privacy', help: '/privacy' }}
            />
          </Item>
        </Section>
      </main>

      <MobileTabBar items={TABS} />
      <StatusFooter
        enclave={params.enclave}
        cluster="localnet"
        slot="1234567"
        rpc="ok"
        apiVersion="v1.0"
        api="degraded"
        stream="polling"
        reference="modelled"
        links={{ status: '/status', privacy: '/privacy', help: '/privacy' }}
      />

      <Dialog
        open={overlay === 'dialog'}
        onClose={close}
        title="Cancel order"
        description="Cancelling seals a cancel into epoch #18422 (one wallet signature)."
        footer={
          <>
            <Button onClick={close}>Keep order</Button>
            <Button variant="primary" onClick={close}>
              Cancel order
            </Button>
          </>
        }
      >
        {/* Held open so the axe run checks a tooltip inside a modal dialog. */}
        <Tooltip content="It takes effect when epoch #18422 clears." side="bottom" open>
          <Button size="sm">When does it take effect?</Button>
        </Tooltip>
      </Dialog>
      <Sheet open={overlay === 'sheet'} onClose={close} title="Deposit">
        <NumberField label="Amount" unit="USDC" value="100" onValueChange={() => undefined} />
      </Sheet>
      <Drawer open={overlay === 'drawer'} onClose={close} title="Order details">
        <p>Lifecycle and verification checklist.</p>
      </Drawer>
      <ActivityDrawer open={overlay === 'activity'} onClose={close} items={ACTIVITY} />
      <WalletPicker
        open={overlay === 'wallets'}
        onClose={close}
        wallets={WALLETS}
        onSelect={close}
      />
    </div>
  );
}
