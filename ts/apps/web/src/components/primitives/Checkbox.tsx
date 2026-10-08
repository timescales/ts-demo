import type { ComponentPropsWithRef, ReactNode } from 'react';
import { useId } from 'react';

import { cx } from '../cx';
import styles from './Checkbox.module.css';
import { hintId } from './Field';

export interface CheckboxProps extends Omit<
  ComponentPropsWithRef<'input'>,
  'id' | 'type' | 'checked' | 'onChange'
> {
  label: ReactNode;
  hint?: ReactNode;
  checked: boolean;
  onCheckedChange: (checked: boolean) => void;
  id?: string | undefined;
}

/** A native checkbox with an always-visible label and optional helper text. */
export function Checkbox({
  label,
  hint,
  checked,
  onCheckedChange,
  id,
  className,
  ...rest
}: CheckboxProps) {
  const autoId = useId();
  const inputId = id ?? autoId;
  return (
    <div className={cx(styles.root, className)}>
      <input
        {...rest}
        id={inputId}
        type="checkbox"
        className={styles.input}
        checked={checked}
        onChange={(event) => onCheckedChange(event.target.checked)}
        aria-describedby={hint ? hintId(inputId) : undefined}
      />
      <div className={styles.text}>
        <label htmlFor={inputId} className={styles.label}>
          {label}
        </label>
        {hint ? (
          <p id={hintId(inputId)} className={styles.hint}>
            {hint}
          </p>
        ) : null}
      </div>
    </div>
  );
}
