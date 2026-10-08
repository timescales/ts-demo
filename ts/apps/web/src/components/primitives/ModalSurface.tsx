import { X } from 'lucide-react';
import type { MouseEvent, ReactNode } from 'react';
import { useEffect, useId, useRef } from 'react';

import { componentsCopy } from '../copy';
import { cx } from '../cx';
import { IconButton } from './IconButton';
import styles from './ModalSurface.module.css';

export interface ModalProps {
  open: boolean;
  /** Called when the user closes it: Escape, the close button or the backdrop. */
  onClose: () => void;
  title: ReactNode;
  description?: ReactNode;
  children?: ReactNode;
  footer?: ReactNode;
  className?: string | undefined;
}

type Placement = 'center' | 'bottom' | 'side';

/**
 * Native modal <dialog> (showModal): the browser makes the page inert, traps
 * and restores focus and handles Escape. base.css locks page scroll while
 * any dialog is open. No portal and no injected styles.
 */
export function ModalSurface({
  placement,
  open,
  onClose,
  title,
  description,
  children,
  footer,
  className,
}: ModalProps & { placement: Placement }) {
  const ref = useRef<HTMLDialogElement>(null);
  const titleId = useId();
  const descriptionId = useId();

  useEffect(() => {
    const dialog = ref.current;
    if (!dialog) return;
    if (open && !dialog.open) dialog.showModal();
    if (!open && dialog.open) dialog.close();
  }, [open]);

  // Clicks on the dialog element itself land on the backdrop area.
  const onBackdrop = (event: MouseEvent<HTMLDialogElement>) => {
    if (event.target === event.currentTarget && placement !== 'center') onClose();
  };

  return (
    <dialog
      ref={ref}
      className={cx(styles.dialog, styles[placement], className)}
      aria-labelledby={titleId}
      aria-describedby={description ? descriptionId : undefined}
      // `close` also fires after Escape. Ignore the one we caused ourselves.
      onClose={() => {
        if (open) onClose();
      }}
      onClick={onBackdrop}
    >
      <div className={styles.panel}>
        <header className={styles.header}>
          <h2 id={titleId} className={styles.title}>
            {title}
          </h2>
          <IconButton
            label={componentsCopy.close}
            icon={<X size={20} aria-hidden="true" />}
            onClick={onClose}
          />
        </header>
        {description ? (
          <p id={descriptionId} className={styles.description}>
            {description}
          </p>
        ) : null}
        <div className={styles.body}>{children}</div>
        {footer ? <footer className={styles.footer}>{footer}</footer> : null}
      </div>
    </dialog>
  );
}
