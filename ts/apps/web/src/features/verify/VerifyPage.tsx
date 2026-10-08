import { b64 } from '@timescales/sdk/core';
import type { DragEvent } from 'react';
import { useId, useState } from 'react';

import { shortAddress } from '../../components/chrome';
import { Button, InlineError } from '../../components/primitives';
import { usePageTitle } from '../../app/links';
import pageStyles from '../../app/Page.module.css';
import { useVerification } from '../../state/hooks';
import { useRuntime } from '../../state/runtime';
import { CheckList } from '../epochs/CheckList';
import { verifyCopy } from './copy';
import type { Report } from './verifyInput';
import { parseInput, runVerify } from './verifyInput';
import styles from './Verify.module.css';

/** File bytes as text: JSON stays text, anything else becomes base64. */
async function fileText(file: Blob): Promise<string> {
  const bytes = new Uint8Array(await file.arrayBuffer());
  const text = new TextDecoder().decode(bytes);
  return text.trimStart().startsWith('{') ? text : b64.encode(bytes);
}

export function EvidenceInput({
  value,
  onChange,
  onSubmit,
  busy,
  error,
}: {
  value: string;
  onChange: (v: string) => void;
  onSubmit: () => void;
  busy: boolean;
  error: string | null;
}) {
  const id = useId();
  const c = verifyCopy.input;
  const onDrop = (e: DragEvent<HTMLTextAreaElement>) => {
    const file = e.dataTransfer.files[0];
    if (file === undefined) return;
    e.preventDefault();
    void fileText(file).then(onChange);
  };
  return (
    <form
      className={styles.form}
      onSubmit={(e) => {
        e.preventDefault();
        onSubmit();
      }}
    >
      <label htmlFor={id} className={styles.label}>
        {c.label}
      </label>
      <p id={`${id}-hint`} className={styles.hint}>
        {c.hint}
      </p>
      <textarea
        id={id}
        className={styles.textarea}
        rows={6}
        spellCheck={false}
        value={value}
        aria-describedby={`${id}-hint${error ? ` ${id}-error` : ''}`}
        aria-invalid={error ? true : undefined}
        onChange={(e) => onChange(e.target.value)}
        onDrop={onDrop}
      />
      <label htmlFor={`${id}-file`} className={styles.label}>
        {c.file}
      </label>
      <input
        id={`${id}-file`}
        type="file"
        onChange={(e) => {
          const file = e.target.files?.[0];
          if (file) void fileText(file).then(onChange);
        }}
      />
      {error ? <InlineError id={`${id}-error`}>{error}</InlineError> : null}
      <div>
        <Button type="submit" variant="primary" busy={busy}>
          {busy ? c.running : c.submit}
        </Button>
      </div>
    </form>
  );
}

export function VerificationReport({ report }: { report: Report }) {
  const r = verifyCopy.report;
  const statuses = report.rows.map((row) => row.result.status);
  // "Holds" only when every row passed. A check that was skipped or could
  // not run leaves the evidence unconfirmed.
  const summary = statuses.includes('fail')
    ? r.summaryFails
    : statuses.every((s) => s === 'ok')
      ? r.summaryHolds
      : r.summaryPending;
  return (
    <section className={pageStyles.card} aria-labelledby="verify-report">
      <h2 id="verify-report">{r.kinds[report.kind]}</h2>
      {report.market !== null && report.epoch !== null ? (
        <p className={pageStyles.muted}>{r.subject(shortAddress(report.market), report.epoch)}</p>
      ) : null}
      <p>{summary}</p>
      <CheckList label={r.label} rows={report.rows} />
    </section>
  );
}

export default function VerifyPage() {
  usePageTitle(verifyCopy.title);
  const runtime = useRuntime();
  const verification = useVerification();
  const [text, setText] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [report, setReport] = useState<Report | null>(null);

  const submit = async () => {
    if (text.trim().length === 0) {
      setError(verifyCopy.input.empty);
      return;
    }
    const parsed = parseInput(text);
    if (parsed.kind === 'unreadable') {
      setError(verifyCopy.input.unreadable);
      setReport(null);
      return;
    }
    setBusy(true);
    setError(null);
    try {
      const out = await runVerify(parsed, {
        api: runtime.services.api,
        rpc: runtime.rpc.get().rpc,
        programId: runtime.config.programId,
        markets: verification.markets,
      });
      setReport(out);
      if (out !== null) runtime.announcer.announce(verifyCopy.report.title, 'stepper');
    } catch (e) {
      setError(e instanceof Error ? e.message : verifyCopy.input.unreadable);
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className={pageStyles.page}>
      <header className={pageStyles.header}>
        <h1>{verifyCopy.title}</h1>
        <p className={pageStyles.lede}>{verifyCopy.lede}</p>
      </header>
      <EvidenceInput
        value={text}
        onChange={setText}
        onSubmit={() => void submit()}
        busy={busy}
        error={error}
      />
      {report ? <VerificationReport report={report} /> : null}
    </div>
  );
}
