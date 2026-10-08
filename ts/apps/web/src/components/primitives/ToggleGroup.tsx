import * as RadixToggleGroup from '@radix-ui/react-toggle-group';
import type { ReactNode } from 'react';

import { cx } from '../cx';
import styles from './ToggleGroup.module.css';

export interface ToggleOption<T extends string> {
  value: T;
  label: ReactNode;
  icon?: ReactNode;
  /** Colours the selected option (side toggles). Never the only signal. */
  tone?: 'buy' | 'sell' | undefined;
  disabled?: boolean | undefined;
}

export interface ToggleGroupProps<T extends string> {
  /** Accessible name of the group. */
  label: string;
  options: readonly ToggleOption<T>[];
  /** '' when nothing is selected yet. */
  value: T | '';
  onValueChange: (value: T) => void;
  disabled?: boolean | undefined;
  className?: string | undefined;
}

/** Single-choice segmented control. A selection cannot be cleared by clicking it again. */
export function ToggleGroup<T extends string>({
  label,
  options,
  value,
  onValueChange,
  disabled = false,
  className,
}: ToggleGroupProps<T>) {
  return (
    <RadixToggleGroup.Root
      type="single"
      aria-label={label}
      className={cx(styles.group, className)}
      value={value}
      disabled={disabled}
      onValueChange={(next) => {
        const option = options.find((o) => o.value === next);
        if (option) onValueChange(option.value);
      }}
    >
      {options.map((option) => (
        <RadixToggleGroup.Item
          key={option.value}
          value={option.value}
          disabled={option.disabled ?? false}
          className={cx(styles.item, option.tone && styles[option.tone])}
        >
          {option.icon}
          {option.label}
        </RadixToggleGroup.Item>
      ))}
    </RadixToggleGroup.Root>
  );
}
