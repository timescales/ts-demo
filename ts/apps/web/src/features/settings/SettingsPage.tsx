import { exportJournal, importJournal } from '@timescales/sdk/journal';
import type { ReactNode } from 'react';
import { useState } from 'react';

import { formatRemaining } from '../../components/chrome';
import {
  Banner,
  Button,
  Checkbox,
  InlineError,
  Select,
  TextField,
  ToggleGroup,
} from '../../components/primitives';
import { downloadBytes } from '../../app/download';
import { usePageTitle } from '../../app/links';
import pageStyles from '../../app/Page.module.css';
import { rpcHealthy } from '../../state/chain';
import { useOrders, useServerNow, useSession, useWallet } from '../../state/hooks';
import { useRuntime } from '../../state/runtime';
import { selectedRpc } from '../../state/services';
import type { AutoHideMinutes, NumberFormat, Palette, Settings, Theme } from '../../state/settings';
import { AUTO_HIDE_OPTIONS, updateSettings, useSettings } from '../../state/settings';
import { settingsCopy } from './copy';
import styles from './Settings.module.css';

const MIN_PASSPHRASE = 12;

function Section({ id, title, children }: { id: string; title: string; children: ReactNode }) {
  return (
    <section id={id} className={styles.section} aria-labelledby={`${id}-title`}>
      <h2 id={`${id}-title`}>{title}</h2>
      {children}
    </section>
  );
}

export function DisplaySettings({ settings }: { settings: Settings }) {
  const d = settingsCopy.display;
  return (
    <Section id="display" title={d.title}>
      <div className={styles.field}>
        <span className={styles.label}>{d.theme}</span>
        <ToggleGroup<Theme>
          label={d.theme}
          value={settings.theme}
          onValueChange={(theme) => updateSettings({ theme })}
          options={(['system', 'dark', 'light'] as const).map((t) => ({
            value: t,
            label: d.themes[t],
          }))}
        />
      </div>
      <div className={styles.field}>
        <span className={styles.label}>{d.palette}</span>
        <ToggleGroup<Palette>
          label={d.palette}
          value={settings.palette}
          onValueChange={(palette) => updateSettings({ palette })}
          options={(['standard', 'cvd'] as const).map((p) => ({ value: p, label: d.palettes[p] }))}
        />
        <p className={styles.hint}>{d.paletteHint}</p>
      </div>
      <Checkbox
        label={d.reduceMotion}
        hint={d.reduceMotionHint}
        checked={settings.reduceMotion}
        onCheckedChange={(reduceMotion) => updateSettings({ reduceMotion })}
      />
      <Select
        label={d.numberFormat}
        hint={d.numberFormatHint}
        value={settings.numberFormat}
        onValueChange={(v) => updateSettings({ numberFormat: v as NumberFormat })}
        options={(['dot', 'comma', 'space', 'plain'] as const).map((f) => ({
          value: f,
          label: d.formats[f],
        }))}
      />
    </Section>
  );
}

function AccessibilitySettings({ settings }: { settings: Settings }) {
  const a = settingsCopy.accessibility;
  return (
    <Section id="accessibility" title={a.title}>
      <Checkbox
        label={a.announcePhases}
        hint={a.announcePhasesHint}
        checked={settings.announcePhases}
        onCheckedChange={(announcePhases) => updateSettings({ announcePhases })}
      />
      <Checkbox
        label={a.shortcuts}
        hint={a.shortcutsHint}
        checked={settings.shortcuts}
        onCheckedChange={(shortcuts) => updateSettings({ shortcuts })}
      />
    </Section>
  );
}

function PrivacySettings({ settings }: { settings: Settings }) {
  const p = settingsCopy.privacy;
  return (
    <Section id="privacy" title={p.title}>
      <Checkbox
        label={p.privacyScreen}
        hint={p.privacyScreenHint}
        checked={settings.privacyScreen}
        onCheckedChange={(privacyScreen) => updateSettings({ privacyScreen })}
      />
      <Select
        label={p.autoHide}
        hint={p.autoHideHint}
        value={String(settings.autoHideMinutes)}
        onValueChange={(v) => updateSettings({ autoHideMinutes: Number(v) as AutoHideMinutes })}
        options={AUTO_HIDE_OPTIONS.map((n) => ({
          value: String(n),
          label: n === 0 ? p.autoHideOff : p.autoHideMinutes(n),
        }))}
      />
    </Section>
  );
}

export function NetworkSettings({ settings }: { settings: Settings }) {
  const { config } = useRuntime();
  const n = settingsCopy.network;
  const [health, setHealth] = useState<{ id: string; ok: boolean } | 'checking' | null>(null);
  const primary = selectedRpc(config, settings);
  const options = config.rpcAllowlist.map((r) => ({ value: r.id, label: r.label }));
  return (
    <Section id="network" title={n.title}>
      {primary === null ? (
        <p>{n.noAllowlist}</p>
      ) : (
        <>
          <Select
            label={n.primary}
            value={primary.id}
            onValueChange={(rpcPrimary) => {
              setHealth(null);
              updateSettings({ rpcPrimary });
            }}
            options={options}
          />
          <Select
            label={n.crossCheck}
            hint={n.crossCheckHint}
            value={settings.rpcCrossCheck ?? ''}
            onValueChange={(v) => updateSettings({ rpcCrossCheck: v === '' ? null : v })}
            options={[{ value: '', label: n.crossCheckNone }, ...options]}
          />
          <div className={pageStyles.row}>
            <Button
              variant="secondary"
              busy={health === 'checking'}
              onClick={() => {
                setHealth('checking');
                void rpcHealthy(primary.url).then((ok) => setHealth({ id: primary.id, ok }));
              }}
            >
              {health === 'checking' ? n.checking : n.check}
            </Button>
            {health !== null && health !== 'checking' && health.id === primary.id ? (
              health.ok ? (
                <p>{n.healthy(primary.label)}</p>
              ) : (
                <InlineError>{n.unhealthy(primary.label)}</InlineError>
              )
            ) : null}
          </div>
        </>
      )}
      <Banner severity="info" title={n.warning}>
        {n.allowlist}
      </Banner>
    </Section>
  );
}

function SessionSettings() {
  const runtime = useRuntime();
  const wallet = useWallet();
  const session = useSession();
  const now = useServerNow();
  const s = settingsCopy.session;
  let body;
  if (wallet.status !== 'connected') body = <p>{s.noWallet}</p>;
  else if (session.status === 'active' && session.session !== null) {
    body = (
      <>
        <p>{s.active(formatRemaining((session.session.expiresAtMs - now) / 1000))}</p>
        <div>
          <Button variant="secondary" onClick={() => void runtime.session.revoke()}>
            {s.revoke}
          </Button>
        </div>
      </>
    );
  } else if (session.status === 'expired' || session.status === 'revoked') body = <p>{s.ended}</p>;
  else body = <p>{s.none}</p>;
  return (
    <Section id="session" title={s.title}>
      {body}
      <p className={styles.hint}>{s.evictionNote}</p>
    </Section>
  );
}

export function LocalDataSettings() {
  const runtime = useRuntime();
  const orders = useOrders();
  const d = settingsCopy.data;
  const [passphrase, setPassphrase] = useState('');
  const [file, setFile] = useState<File | null>(null);
  const [confirm, setConfirm] = useState('');
  const [busy, setBusy] = useState<'export' | 'import' | 'wipe' | null>(null);
  const [message, setMessage] = useState<{ ok: boolean; text: string } | null>(null);
  const journal = orders.journal;
  const short = passphrase.length > 0 && passphrase.length < MIN_PASSPHRASE;
  const passphraseOk = passphrase.length >= MIN_PASSPHRASE;

  if (orders.wallet === null) {
    return (
      <Section id="local-data" title={d.title}>
        <p>{d.noWallet}</p>
      </Section>
    );
  }

  const run = async (kind: 'export' | 'import' | 'wipe', task: () => Promise<string>) => {
    setBusy(kind);
    setMessage(null);
    try {
      const text = await task();
      setMessage({ ok: true, text });
      runtime.announcer.announce(text, 'stepper');
    } catch {
      setMessage({
        ok: false,
        text: kind === 'import' ? d.importFailed : d.persistence.unreadable,
      });
    } finally {
      setBusy(null);
    }
  };

  return (
    <Section id="local-data" title={d.title}>
      <p>{d.persistence[orders.persistence ?? 'persistent']}</p>
      <TextField
        label={d.passphrase}
        hint={d.passphraseHint}
        error={short ? d.passphraseShort : undefined}
        type="password"
        autoComplete="new-password"
        value={passphrase}
        onChange={(e) => setPassphrase(e.target.value)}
      />
      <div className={pageStyles.row}>
        <Button
          variant="secondary"
          disabled={!passphraseOk || journal === null}
          busy={busy === 'export'}
          onClick={() =>
            void run('export', async () => {
              const bundle = await exportJournal(journal!, passphrase);
              downloadBytes('order-journal-backup.tsjnl', bundle, 'application/octet-stream');
              return d.exported;
            })
          }
        >
          {busy === 'export' ? d.exporting : d.export}
        </Button>
      </div>
      <div className={styles.field}>
        <label className={styles.label} htmlFor="import-file">
          {d.importFile}
        </label>
        <input
          id="import-file"
          type="file"
          className={styles.file}
          onChange={(e) => setFile(e.target.files?.[0] ?? null)}
        />
      </div>
      <div className={pageStyles.row}>
        <Button
          variant="secondary"
          disabled={!passphraseOk || file === null || journal === null}
          busy={busy === 'import'}
          onClick={() =>
            void run('import', async () => {
              const bytes = new Uint8Array(await file!.arrayBuffer());
              const r = await importJournal(bytes, passphrase, journal!);
              return d.imported(r.imported, r.skipped);
            })
          }
        >
          {busy === 'import' ? d.importing : d.import}
        </Button>
      </div>
      <div className={styles.danger}>
        <h3>{d.wipeTitle}</h3>
        <p>{d.wipe}</p>
        <TextField
          label={d.wipeConfirm}
          value={confirm}
          onChange={(e) => setConfirm(e.target.value)}
        />
        <div>
          <Button
            variant="danger"
            disabled={confirm !== d.wipeWord || journal === null}
            busy={busy === 'wipe'}
            onClick={() =>
              void run('wipe', async () => {
                await journal!.wipe();
                setConfirm('');
                runtime.activity.clear();
                return d.wiped;
              })
            }
          >
            {d.wipeButton}
          </Button>
        </div>
      </div>
      {message ? (
        message.ok ? (
          <p>{message.text}</p>
        ) : (
          <InlineError>{message.text}</InlineError>
        )
      ) : null}
    </Section>
  );
}

export default function SettingsPage() {
  usePageTitle(settingsCopy.title);
  const settings = useSettings();
  return (
    <div className={pageStyles.page}>
      <header className={pageStyles.header}>
        <h1>{settingsCopy.title}</h1>
        <p className={pageStyles.lede}>{settingsCopy.lede}</p>
      </header>
      <div className={styles.sections}>
        <DisplaySettings settings={settings} />
        <AccessibilitySettings settings={settings} />
        <PrivacySettings settings={settings} />
        <NetworkSettings settings={settings} />
        <SessionSettings />
        <LocalDataSettings />
        <Section id="notifications" title={settingsCopy.notifications.title}>
          <p>{settingsCopy.notifications.text}</p>
        </Section>
      </div>
    </div>
  );
}
