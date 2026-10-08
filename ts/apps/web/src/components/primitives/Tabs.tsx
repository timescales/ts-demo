import * as RadixTabs from '@radix-ui/react-tabs';
import type { ReactNode } from 'react';

import { cx } from '../cx';
import styles from './Tabs.module.css';

export interface TabItem {
  value: string;
  label: ReactNode;
  content: ReactNode;
}

export interface TabsProps {
  /** Accessible name of the tab list. */
  label: string;
  items: readonly TabItem[];
  value?: string | undefined;
  defaultValue?: string | undefined;
  onValueChange?: ((value: string) => void) | undefined;
  className?: string | undefined;
}

export function Tabs({ label, items, value, defaultValue, onValueChange, className }: TabsProps) {
  const control =
    value !== undefined ? { value } : { defaultValue: defaultValue ?? items[0]?.value ?? '' };
  return (
    <RadixTabs.Root
      {...control}
      {...(onValueChange ? { onValueChange } : {})}
      className={cx(styles.root, className)}
    >
      <RadixTabs.List aria-label={label} className={styles.list}>
        {items.map((item) => (
          <RadixTabs.Trigger key={item.value} value={item.value} className={styles.trigger}>
            {item.label}
          </RadixTabs.Trigger>
        ))}
      </RadixTabs.List>
      {items.map((item) => (
        <RadixTabs.Content key={item.value} value={item.value} className={styles.panel}>
          {item.content}
        </RadixTabs.Content>
      ))}
    </RadixTabs.Root>
  );
}
