import type { ComponentPropsWithRef, ReactNode } from 'react';
import { useId } from 'react';

import { cx } from '../cx';
import { Field, describedBy } from './Field';
import fieldStyles from './Field.module.css';
import styles from './NumberField.module.css';

export interface NumberFieldProps extends Omit<
  ComponentPropsWithRef<'input'>,
  'id' | 'value' | 'onChange' | 'type'
> {
  label: ReactNode;
  /** The text as typed. Amounts stay strings here: parsing in the user's
   *  declared number format (the SDK's parseDecimal, into bigint) is the
   *  caller's, so no value ever passes through a float. */
  value: string;
  onValueChange: (text: string) => void;
  unit?: ReactNode;
  /** The exact value that will be used when it differs from what was typed,
   *  e.g. the price of the tick that will be signed. */
  exact?: ReactNode;
  hint?: ReactNode;
  error?: ReactNode;
  id?: string | undefined;
}

export function NumberField({
  label,
  value,
  onValueChange,
  unit,
  exact,
  hint,
  error,
  id,
  className,
  ...rest
}: NumberFieldProps) {
  const autoId = useId();
  const inputId = id ?? autoId;
  const exactId = `${inputId}-exact`;
  const described = [exact ? exactId : null, describedBy(inputId, hint, error)]
    .filter(Boolean)
    .join(' ');
  return (
    <Field
      id={inputId}
      label={label}
      hint={hint}
      error={error}
      after={
        exact ? (
          <p className={styles.exact} id={exactId}>
            {exact}
          </p>
        ) : null
      }
    >
      <div className={styles.wrap}>
        <input
          {...rest}
          id={inputId}
          type="text"
          inputMode="decimal"
          autoComplete="off"
          spellCheck={false}
          value={value}
          onChange={(event) => onValueChange(event.target.value)}
          className={cx(fieldStyles.control, styles.input, className)}
          aria-invalid={error ? true : undefined}
          aria-describedby={described || undefined}
        />
        {unit ? (
          <span className={styles.unit} aria-hidden="true">
            {unit}
          </span>
        ) : null}
      </div>
    </Field>
  );
}
