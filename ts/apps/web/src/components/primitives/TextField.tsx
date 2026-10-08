import type { ComponentPropsWithRef, ReactNode } from 'react';
import { useId } from 'react';

import { cx } from '../cx';
import { Field, describedBy } from './Field';
import fieldStyles from './Field.module.css';

export interface TextFieldProps extends Omit<ComponentPropsWithRef<'input'>, 'id'> {
  label: ReactNode;
  hint?: ReactNode;
  error?: ReactNode;
  id?: string | undefined;
}

export function TextField({ label, hint, error, id, className, ...rest }: TextFieldProps) {
  const autoId = useId();
  const inputId = id ?? autoId;
  return (
    <Field id={inputId} label={label} hint={hint} error={error}>
      <input
        {...rest}
        id={inputId}
        className={cx(fieldStyles.control, className)}
        aria-invalid={error ? true : undefined}
        aria-describedby={describedBy(inputId, hint, error)}
      />
    </Field>
  );
}
