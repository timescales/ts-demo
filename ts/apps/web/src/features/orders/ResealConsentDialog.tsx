import { Button, Dialog } from '../../components/primitives';
import { ordersCopy } from './copy';
import styles from './orders.module.css';

export interface ResealConsentDialogProps {
  open: boolean;
  /** The voided epoch whose public outcome named this order. */
  epoch: bigint;
  onReplace: () => void;
  onClose: () => void;
}

/**
 * After a voided epoch made an order's side, size and price public, the SDK
 * does not re-seal that commitment silently. A fresh signature gives
 * a new commitment.
 */
export function ResealConsentDialog({ open, epoch, onReplace, onClose }: ResealConsentDialogProps) {
  const copy = ordersCopy.reseal;
  return (
    <Dialog
      open={open}
      onClose={onClose}
      title={copy.title}
      description={copy.body(epoch.toString())}
      footer={
        <div className={styles.dialogActions}>
          <Button onClick={onClose}>{copy.notNow}</Button>
          <Button variant="primary" onClick={onReplace}>
            {copy.replace}
          </Button>
        </div>
      }
    >
      <p className={styles.muted}>{copy.detail}</p>
    </Dialog>
  );
}
