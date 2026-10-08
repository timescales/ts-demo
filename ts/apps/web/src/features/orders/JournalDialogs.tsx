import type { ReconcileReport } from '@timescales/sdk/orders';
import { useId, useState } from 'react';

import { Button, Dialog, NumberField, TextField } from '../../components/primitives';
import { errorInfo } from '../trade/errors';
import { readPref, writePref } from '../trade/prefs';
import type { JournalPort, OrdersPort } from '../trade/services';
import { ordersCopy } from './copy';
import { saveFile } from './download';
import styles from './orders.module.css';

const MIN_PASSPHRASE = 12;

const exportKey = (wallet: string) => `ts.orders.lastExport:${wallet}`;

export function lastExportAt(wallet: string): number | null {
  const v = Number(readPref(exportKey(wallet)));
  return Number.isFinite(v) && v > 0 ? v : null;
}

type Status =
  | { kind: 'idle' }
  | { kind: 'busy' }
  | { kind: 'done'; text: string }
  | { kind: 'error'; text: string };

function StatusLine({ status }: { status: Status }) {
  if (status.kind === 'done')
    return (
      <p role="status" className={styles.result}>
        {status.text}
      </p>
    );
  if (status.kind === 'error')
    return (
      <p role="alert" className={styles.result}>
        {status.text}
      </p>
    );
  return null;
}

export interface ExportDialogProps {
  open: boolean;
  journal: JournalPort;
  wallet: string;
  onClose: () => void;
  onExported?: (atMs: number) => void;
}

export function ExportDialog({ open, journal, wallet, onClose, onExported }: ExportDialogProps) {
  const copy = ordersCopy.exportDialog;
  const [pass, setPass] = useState('');
  const [again, setAgain] = useState('');
  const [tried, setTried] = useState(false);
  const [status, setStatus] = useState<Status>({ kind: 'idle' });
  const tooShort = pass.length < MIN_PASSPHRASE;
  const mismatch = pass !== again;

  const run = async () => {
    setTried(true);
    if (tooShort || mismatch) return;
    setStatus({ kind: 'busy' });
    try {
      const bundle = await journal.exportBackup(pass);
      saveFile(bundle, copy.fileName, 'application/octet-stream');
      const at = Date.now();
      writePref(exportKey(wallet), String(at));
      onExported?.(at);
      setStatus({ kind: 'done', text: copy.done });
    } catch {
      setStatus({ kind: 'error', text: copy.failed });
    }
  };

  const close = () => {
    setPass('');
    setAgain('');
    setTried(false);
    setStatus({ kind: 'idle' });
    onClose();
  };

  return (
    <Dialog
      open={open}
      onClose={close}
      title={copy.title}
      description={copy.body}
      footer={
        <div className={styles.dialogActions}>
          <Button onClick={close}>{ordersCopy.close}</Button>
          <Button variant="primary" busy={status.kind === 'busy'} onClick={() => void run()}>
            {status.kind === 'busy' ? copy.exporting : copy.export}
          </Button>
        </div>
      }
    >
      <TextField
        label={copy.passphrase}
        type="password"
        autoComplete="new-password"
        value={pass}
        onChange={(e) => setPass(e.target.value)}
        error={tried && tooShort ? copy.tooShort : null}
      />
      <TextField
        label={copy.confirm}
        type="password"
        autoComplete="new-password"
        value={again}
        onChange={(e) => setAgain(e.target.value)}
        error={tried && !tooShort && mismatch ? copy.mismatch : null}
      />
      <StatusLine status={status} />
    </Dialog>
  );
}

export interface ImportDialogProps {
  open: boolean;
  journal: JournalPort;
  onClose: () => void;
}

export function ImportDialog({ open, journal, onClose }: ImportDialogProps) {
  const copy = ordersCopy.importDialog;
  const fileId = useId();
  const [file, setFile] = useState<File | null>(null);
  const [pass, setPass] = useState('');
  const [tried, setTried] = useState(false);
  const [status, setStatus] = useState<Status>({ kind: 'idle' });

  const run = async () => {
    setTried(true);
    if (file === null) return;
    setStatus({ kind: 'busy' });
    try {
      const bytes = new Uint8Array(await file.arrayBuffer());
      const r = await journal.importBackup(bytes, pass);
      setStatus({ kind: 'done', text: copy.done(r.imported, r.skipped) });
    } catch (e) {
      const code = errorInfo(e).code;
      const text =
        code === 'bad_passphrase' || code === 'other_wallet' || code === 'unsupported_export'
          ? copy.errors[code]
          : copy.errors.generic;
      setStatus({ kind: 'error', text });
    }
  };

  const close = () => {
    setFile(null);
    setPass('');
    setTried(false);
    setStatus({ kind: 'idle' });
    onClose();
  };

  return (
    <Dialog
      open={open}
      onClose={close}
      title={copy.title}
      description={copy.body}
      footer={
        <div className={styles.dialogActions}>
          <Button onClick={close}>{ordersCopy.close}</Button>
          <Button variant="primary" busy={status.kind === 'busy'} onClick={() => void run()}>
            {status.kind === 'busy' ? copy.importing : copy.import}
          </Button>
        </div>
      }
    >
      <div className={styles.fileField}>
        <label htmlFor={fileId}>{copy.file}</label>
        <input
          id={fileId}
          type="file"
          onChange={(e) => setFile(e.target.files?.[0] ?? null)}
          aria-invalid={tried && file === null ? true : undefined}
          aria-describedby={tried && file === null ? `${fileId}-error` : undefined}
        />
        {tried && file === null ? (
          <p id={`${fileId}-error`} className={styles.fieldError}>
            {copy.noFile}
          </p>
        ) : null}
      </div>
      <TextField
        label={copy.passphrase}
        type="password"
        autoComplete="current-password"
        value={pass}
        onChange={(e) => setPass(e.target.value)}
      />
      <StatusLine status={status} />
    </Dialog>
  );
}

export interface ReconcileDialogProps {
  open: boolean;
  orders: OrdersPort;
  /** Suggested start: the oldest epoch still kept by the chain's batch retention. */
  defaultFrom: bigint;
  onClose: () => void;
}

export function ReconcileDialog({ open, orders, defaultFrom, onClose }: ReconcileDialogProps) {
  const copy = ordersCopy.reconcile;
  const [from, setFrom] = useState(defaultFrom.toString());
  const [status, setStatus] = useState<Status>({ kind: 'idle' });
  const valid = /^\d+$/.test(from.trim());

  const run = async () => {
    if (!valid) return;
    setStatus({ kind: 'busy' });
    try {
      const report: ReconcileReport = await orders.reconcile(BigInt(from.trim()));
      setStatus({ kind: 'done', text: copy.report(report) });
    } catch {
      setStatus({ kind: 'error', text: copy.failed });
    }
  };

  const close = () => {
    setStatus({ kind: 'idle' });
    onClose();
  };

  return (
    <Dialog
      open={open}
      onClose={close}
      title={copy.title}
      description={copy.body}
      footer={
        <div className={styles.dialogActions}>
          <Button onClick={close}>{ordersCopy.close}</Button>
          <Button
            variant="primary"
            busy={status.kind === 'busy'}
            disabled={!valid}
            onClick={() => void run()}
          >
            {status.kind === 'busy' ? copy.running : copy.run}
          </Button>
        </div>
      }
    >
      <NumberField
        label={copy.from}
        value={from}
        onValueChange={setFrom}
        hint={copy.fromHint}
        error={valid ? null : copy.invalid}
        inputMode="numeric"
      />
      <StatusLine status={status} />
    </Dialog>
  );
}
