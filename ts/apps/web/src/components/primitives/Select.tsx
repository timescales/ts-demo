import type { ComponentPropsWithRef, ReactNode } from 'react';
import { useId } from 'react';

import { cx } from '../cx';
import { Field, describedBy } from './Field';
import fieldStyles from './Field.module.css';
import styles from './Select.module.css';

export interface SelectOption {
  value: string;
  label: string;
  disabled?: boolean | undefined;
}

export interface SelectProps extends Omit<
  ComponentPropsWithRef<'select'>,
  'id' | 'value' | 'onChange' | 'children'
> {
  label: ReactNode;
  options: readonly SelectOption[];
  value: string;
  onValueChange: (value: string) => void;
  hint?: ReactNode;
  error?: ReactNode;
  id?: string | undefined;
  layout?: 'stacked' | 'inline' | undefined;
}

/** A native select: keyboard, touch and screen-reader behaviour come from the platform. */
export function Select({
  label,
  options,
  value,
  onValueChange,
  hint,
  error,
  id,
  layout,
  className,
  ...rest
}: SelectProps) {
  const autoId = useId();
  const selectId = id ?? autoId;
  return (
    <Field id={selectId} label={label} hint={hint} error={error} layout={layout}>
      <select
        {...rest}
        id={selectId}
        value={value}
        onChange={(event) => onValueChange(event.target.value)}
        className={cx(fieldStyles.control, styles.select, className)}
        aria-invalid={error ? true : undefined}
        aria-describedby={describedBy(selectId, hint, error)}
      >
        {options.map((option) => (
          <option key={option.value} value={option.value} disabled={option.disabled}>
            {option.label}
          </option>
        ))}
      </select>
    </Field>
  );
}
