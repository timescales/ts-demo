import { useState } from 'react';

import type { SessionScope } from '../components/chrome';
import {
  SessionChip,
  SessionDialog,
  WalletButton,
  WalletPicker,
  shortAddress,
} from '../components/chrome';
import { componentsCopy } from '../components/copy';
import { Button, CopyHash, Dialog } from '../components/primitives';
import { describeFailure } from '../state/failures';
import { useServerNow, useSession, useWallet } from '../state/hooks';
import { useMarketDetail } from '../state/queries';
import { useRuntime } from '../state/runtime';
import type { Address } from '../state/types';
import { appCopy } from './copy';

/** The picker (connect) and the wallet menu (copy address, switch, disconnect). */
export function WalletControls({
  pickerOpen,
  onPickerOpenChange,
}: {
  pickerOpen: boolean;
  onPickerOpenChange: (open: boolean) => void;
}) {
  const runtime = useRuntime();
  const wallet = useWallet();
  const [menuOpen, setMenuOpen] = useState(false);
  const connected = wallet.status === 'connected' && wallet.address !== null;
  return (
    <>
      {connected ? (
        <WalletButton
          state="connected"
          walletName={wallet.wallet?.name ?? ''}
          address={wallet.address!}
          icon={wallet.icon}
          onClick={() => setMenuOpen(true)}
        />
      ) : (
        <WalletButton
          state={wallet.status === 'connecting' ? 'connecting' : 'disconnected'}
          onClick={() => onPickerOpenChange(true)}
        />
      )}
      <WalletPicker
        open={pickerOpen}
        onClose={() => onPickerOpenChange(false)}
        wallets={wallet.available}
        onSelect={(id) => {
          onPickerOpenChange(false);
          void runtime.wallets.connect(id);
        }}
      />
      {connected ? (
        <Dialog
          open={menuOpen}
          onClose={() => setMenuOpen(false)}
          title={componentsCopy.wallet.menu}
          description={wallet.wallet?.name}
          footer={
            <>
              <Button
                variant="secondary"
                onClick={() => {
                  setMenuOpen(false);
                  onPickerOpenChange(true);
                }}
              >
                {appCopy.walletMenu.switch}
              </Button>
              <Button
                variant="ghost"
                onClick={() => {
                  setMenuOpen(false);
                  void runtime.wallets.disconnect();
                }}
              >
                {appCopy.walletMenu.disconnect}
              </Button>
            </>
          }
        >
          <CopyHash value={wallet.address!} label={appCopy.walletMenu.address} />
        </Dialog>
      ) : null}
    </>
  );
}

/**
 * The session chip, its dialog and the second-prompt confirmation. The
 * shell owns whether the dialog is open, so screens can start a session too.
 */
export function SessionControls({
  market,
  open,
  onOpenChange,
}: {
  market: Address | null;
  open: boolean;
  onOpenChange: (open: boolean) => void;
}) {
  const runtime = useRuntime();
  const wallet = useWallet();
  const session = useSession();
  const now = useServerNow();
  const detail = useMarketDetail(market).data;
  const setOpen = onOpenChange;
  const [scope, setScope] = useState<SessionScope>('all');
  if (wallet.status !== 'connected') return null;
  const remaining =
    session.session === null ? 0 : Math.max(0, (session.session.expiresAtMs - now) / 1000);
  const chipState =
    session.status === 'active'
      ? 'active'
      : session.status === 'expired' || session.status === 'revoked'
        ? session.status
        : 'none';
  const error = session.error === null ? null : describeFailure(session.error).text;
  return (
    <>
      <SessionChip state={chipState} remainingSeconds={remaining} onAction={() => setOpen(true)} />
      <SessionDialog
        open={open}
        onClose={() => setOpen(false)}
        state={chipState}
        remainingSeconds={remaining}
        scope={scope}
        onScopeChange={setScope}
        marketLabel={market === null ? undefined : (detail?.name ?? shortAddress(market))}
        busy={session.status === 'opening'}
        error={error}
        onStart={() => {
          void runtime.session.open({ market: scope === 'market' ? market : null }).then((s) => {
            if (s !== null) setOpen(false);
          });
        }}
        onRevoke={() => {
          void runtime.session.revoke();
          setOpen(false);
        }}
      />
      <Dialog
        open={session.secondPrompt !== null}
        onClose={() => runtime.session.answerSecondPrompt(false)}
        title={appCopy.session.secondPromptTitle}
        description={appCopy.session.secondPrompt}
        footer={
          <>
            <Button variant="ghost" onClick={() => runtime.session.answerSecondPrompt(false)}>
              {appCopy.session.cancel}
            </Button>
            <Button variant="primary" onClick={() => runtime.session.answerSecondPrompt(true)}>
              {appCopy.session.signAgain}
            </Button>
          </>
        }
      />
    </>
  );
}
