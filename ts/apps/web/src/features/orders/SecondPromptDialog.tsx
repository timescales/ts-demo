import { Button, Dialog } from '../../components/primitives';
import { ordersCopy } from './copy';
import styles from './orders.module.css';

export interface SecondPromptDialogProps {
  open: boolean;
  /** Why another signature is needed, completing "This needs another wallet signature:...". */
  why: string;
  onSign: () => void;
  onCancel: () => void;
}

/** Asks before any second wallet prompt. Nothing is ever re-signed silently. */
export function SecondPromptDialog({ open, why, onSign, onCancel }: SecondPromptDialogProps) {
  const copy = ordersCopy.secondPrompt;
  return (
    <Dialog
      open={open}
      onClose={onCancel}
      title={copy.title}
      description={copy.body(why)}
      footer={
        <div className={styles.dialogActions}>
          <Button onClick={onCancel}>{copy.cancel}</Button>
          <Button variant="primary" onClick={onSign}>
            {copy.sign}
          </Button>
        </div>
      }
    />
  );
}
