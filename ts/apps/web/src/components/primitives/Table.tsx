import type { ReactNode } from 'react';
import { useId } from 'react';

import { cx } from '../cx';
import styles from './Table.module.css';

export interface Column<Row> {
  key: string;
  header: ReactNode;
  cell: (row: Row) => ReactNode;
  /** Right-aligned tabular figures. */
  numeric?: boolean | undefined;
}

export interface TableProps<Row> {
  caption: ReactNode;
  /** Keeps the caption for screen readers only. */
  captionHidden?: boolean | undefined;
  columns: readonly Column<Row>[];
  rows: readonly Row[];
  rowKey: (row: Row) => string;
  /** Shown in a single row when there are no rows. */
  empty?: ReactNode;
  className?: string | undefined;
}

/**
 * A data table. Only data tables scroll horizontally (reflow): the
 * wrapper is a focusable, labelled region and the first column is sticky.
 */
export function Table<Row>({
  caption,
  captionHidden = false,
  columns,
  rows,
  rowKey,
  empty,
  className,
}: TableProps<Row>) {
  const captionId = useId();
  return (
    <div
      className={cx(styles.scroll, className)}
      role="region"
      aria-labelledby={captionId}
      tabIndex={0}
    >
      <table className={styles.table}>
        <caption id={captionId} className={captionHidden ? styles.hiddenCaption : styles.caption}>
          {caption}
        </caption>
        <thead>
          <tr>
            {columns.map((column) => (
              <th
                key={column.key}
                scope="col"
                className={cx(styles.th, column.numeric && styles.numeric)}
              >
                {column.header}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {rows.length === 0 && empty ? (
            <tr>
              <td className={styles.empty} colSpan={columns.length}>
                {empty}
              </td>
            </tr>
          ) : (
            rows.map((row) => (
              <tr key={rowKey(row)} className={styles.row}>
                {columns.map((column, index) =>
                  index === 0 ? (
                    <th
                      key={column.key}
                      scope="row"
                      className={cx(styles.td, styles.first, column.numeric && styles.numeric)}
                    >
                      {column.cell(row)}
                    </th>
                  ) : (
                    <td
                      key={column.key}
                      className={cx(styles.td, column.numeric && styles.numeric)}
                    >
                      {column.cell(row)}
                    </td>
                  ),
                )}
              </tr>
            ))
          )}
        </tbody>
      </table>
    </div>
  );
}
