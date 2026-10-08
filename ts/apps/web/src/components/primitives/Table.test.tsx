import { render, screen } from '@testing-library/react';
import { describe, expect, it } from 'vitest';

import { expectNoSeriousAxeViolations } from '../testing/a11y';
import type { Column } from './Table';
import { Table } from './Table';

interface Row {
  epoch: string;
  price: string;
}

const COLUMNS: Column<Row>[] = [
  { key: 'epoch', header: 'Epoch', cell: (r) => r.epoch, numeric: true },
  { key: 'price', header: 'Clearing price', cell: (r) => r.price, numeric: true },
];

describe('Table', () => {
  it('renders a captioned table in a focusable scroll region', async () => {
    render(
      <Table
        caption="Clearing tape"
        columns={COLUMNS}
        rows={[
          { epoch: '18421', price: '182.37' },
          { epoch: '18420', price: '182.12' },
        ]}
        rowKey={(r) => r.epoch}
      />,
    );
    const region = screen.getByRole('region', { name: 'Clearing tape' });
    expect(region.tabIndex).toBe(0);
    expect(screen.getByRole('table', { name: 'Clearing tape' })).toBeTruthy();
    expect(screen.getAllByRole('columnheader').map((th) => th.textContent)).toEqual([
      'Epoch',
      'Clearing price',
    ]);
    expect(screen.getAllByRole('rowheader').map((th) => th.textContent)).toEqual([
      '18421',
      '18420',
    ]);
    await expectNoSeriousAxeViolations();
  });

  it('renders the empty row', async () => {
    render(
      <Table
        caption="Clearing tape"
        captionHidden
        columns={COLUMNS}
        rows={[]}
        rowKey={(r) => r.epoch}
        empty="No epochs yet."
      />,
    );
    expect(screen.getByRole('cell').textContent).toBe('No epochs yet.');
    expect(screen.getByRole('cell').getAttribute('colspan')).toBe('2');
    await expectNoSeriousAxeViolations();
  });
});
