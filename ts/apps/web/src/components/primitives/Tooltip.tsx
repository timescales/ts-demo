import * as RadixTooltip from '@radix-ui/react-tooltip';
import type { ReactElement, ReactNode } from 'react';
import { useCallback, useState } from 'react';

import styles from './Tooltip.module.css';

export interface TooltipProps {
  content: ReactNode;
  /** One focusable element. The tooltip opens on hover and on keyboard focus. */
  children: ReactElement;
  side?: 'top' | 'right' | 'bottom' | 'left' | undefined;
  /** Controlled open state, for tests and the gallery. */
  open?: boolean | undefined;
  onOpenChange?: ((open: boolean) => void) | undefined;
}

/** Supplementary text only: anything a user must read goes inline instead. */
export function Tooltip({ content, children, side = 'top', open, onOpenChange }: TooltipProps) {
  // A modal <dialog> sits in the top layer, above anything portalled to
  // <body>, so a tooltip inside Dialog, Sheet or Drawer is portalled into
  // that dialog instead.
  const [container, setContainer] = useState<HTMLElement | null>(null);
  const trigger = useCallback((node: HTMLElement | null) => {
    setContainer(node?.closest('dialog') ?? null);
  }, []);
  return (
    <RadixTooltip.Provider delayDuration={300}>
      <RadixTooltip.Root
        {...(open !== undefined ? { open } : {})}
        {...(onOpenChange ? { onOpenChange } : {})}
      >
        <RadixTooltip.Trigger asChild ref={trigger}>
          {children}
        </RadixTooltip.Trigger>
        <RadixTooltip.Portal container={container}>
          <RadixTooltip.Content side={side} sideOffset={6} className={styles.content}>
            {content}
          </RadixTooltip.Content>
        </RadixTooltip.Portal>
      </RadixTooltip.Root>
    </RadixTooltip.Provider>
  );
}
