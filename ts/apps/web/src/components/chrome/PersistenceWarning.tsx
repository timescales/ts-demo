import { componentsCopy } from '../copy';
import { Banner } from '../primitives/Banner';
import { Button } from '../primitives/Button';

export type PersistenceProblem = 'private_window' | 'unreadable' | 'not_persistent' | 'full';

export interface PersistenceWarningProps {
  problem: PersistenceProblem;
  onExport?: (() => void) | undefined;
  onImport?: (() => void) | undefined;
}

/** The journal cannot keep order details reliably. Persistent, not dismissible. */
export function PersistenceWarning({ problem, onExport, onImport }: PersistenceWarningProps) {
  const copy = componentsCopy.persistence;
  const actions =
    onExport || onImport ? (
      <>
        {onExport ? (
          <Button variant="secondary" size="sm" onClick={onExport}>
            {copy.exportBackup}
          </Button>
        ) : null}
        {onImport ? (
          <Button variant="ghost" size="sm" onClick={onImport}>
            {copy.importBackup}
          </Button>
        ) : null}
      </>
    ) : undefined;
  return (
    <Banner severity="warning" title={copy.title} actions={actions}>
      {copy[problem]}
    </Banner>
  );
}
