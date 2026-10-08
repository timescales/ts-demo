import type { LucideIcon } from 'lucide-react';
import { Eye, Globe, Lock, Minus } from 'lucide-react';
import type { ReactNode } from 'react';
import { useId } from 'react';

import type { EnclaveTrust } from '../../components/chrome';
import { privacyCopy } from './copy';
import styles from './Privacy.module.css';

type Reach = 'private' | 'operator' | 'public' | 'never' | 'none';

const ICONS: Record<Reach, LucideIcon> = {
  private: Lock,
  operator: Eye,
  public: Globe,
  never: Lock,
  none: Minus,
};

interface Cell {
  reach: Reach;
  text: ReactNode;
}

interface Row {
  id: string;
  label: string;
  cells: [Cell, Cell, Cell, Cell];
}

const c = privacyCopy.matrix.cells;
const none: Cell = { reach: 'none', text: c.none };

/**: the matrix's rows for one trust variant (V-14). Simulated-mode values are bold. */
export function matrixRows(enclave: EnclaveTrust, o: { summary?: boolean } = {}): Row[] {
  const simulated = enclave === 'simulated';
  const contents: Cell = {
    reach: 'private',
    text: (
      <>
        {c.youOnly}, {c.plusDealer} {c.plusCommittee}
        {simulated ? (
          <>
            {' '}
            <strong>{c.plusHost}</strong>
          </>
        ) : null}
      </>
    ),
  };
  const enclaveCell: Cell = simulated
    ? { reach: 'operator', text: <strong>{c.hostOperator}</strong> }
    : {
        reach: 'private',
        text: enclave === 'tdx_vouched' ? c.enclaveTdx : c.enclaveTdxReported,
      };
  const rows: Row[] = [
    {
      id: 'wallet',
      label: privacyCopy.matrix.rows.wallet,
      cells: [
        { reach: 'operator', text: c.relayViaSession },
        { reach: 'operator', text: c.relay },
        { reach: 'public', text: <strong>{c.publicIfFilled}</strong> },
        { reach: 'public', text: c.publicAccount },
      ],
    },
    {
      id: 'submitted',
      label: privacyCopy.matrix.rows.submitted,
      cells: [
        { reach: 'operator', text: c.relay },
        { reach: 'operator', text: c.relay },
        { reach: 'operator', text: c.relay },
        none,
      ],
    },
    {
      id: 'contents',
      label: privacyCopy.matrix.rows.contents,
      cells: [contents, enclaveCell, { reach: 'public', text: c.publicOnlyFills }, none],
    },
    {
      id: 'resting',
      label: privacyCopy.matrix.rows.resting,
      cells: [
        { reach: 'operator', text: c.commitmentRepeats },
        { reach: 'operator', text: c.same },
        { reach: 'operator', text: c.same },
        none,
      ],
    },
    {
      id: 'isolation',
      label: privacyCopy.matrix.rows.isolation,
      cells: [
        none,
        { reach: 'operator', text: <strong>{c.isolation}</strong> },
        { reach: 'public', text: c.publicFillsOfEpoch },
        none,
      ],
    },
    {
      id: 'fills',
      label: privacyCopy.matrix.rows.fills,
      cells: [none, none, { reach: 'public', text: c.public }, none],
    },
    {
      id: 'unfilled',
      label: privacyCopy.matrix.rows.unfilled,
      cells: [
        { reach: 'never', text: c.never },
        { reach: 'never', text: c.never },
        { reach: 'never', text: c.never },
        none,
      ],
    },
    {
      id: 'balances',
      label: privacyCopy.matrix.rows.balances,
      cells: [
        { reach: 'public', text: c.public },
        { reach: 'public', text: c.public },
        { reach: 'public', text: c.public },
        { reach: 'public', text: c.public },
      ],
    },
  ];
  return o.summary
    ? rows.filter((r) => ['contents', 'isolation', 'fills', 'balances'].includes(r.id))
    : rows;
}

function CellView({ cell }: { cell: Cell }) {
  const Icon = ICONS[cell.reach];
  return (
    <span className={styles.cell} data-reach={cell.reach}>
      <Icon size={16} aria-hidden="true" className={styles.cellIcon} />
      <span>{cell.text}</span>
    </span>
  );
}

export interface WhoSeesWhatMatrixProps {
  enclave: EnclaveTrust;
  /** The four rows Welcome shows. */
  summary?: boolean | undefined;
}

/**  "who sees what", a captioned table. Cells are icon + text. */
export function WhoSeesWhatMatrix({ enclave, summary = false }: WhoSeesWhatMatrixProps) {
  const cols = privacyCopy.matrix.columns;
  const captionId = useId();
  return (
    <div className={styles.scroll} role="region" aria-labelledby={captionId} tabIndex={0}>
      <table className={styles.matrix}>
        <caption id={captionId} className={styles.caption}>
          {summary ? privacyCopy.matrix.summaryCaption : privacyCopy.matrix.caption}
        </caption>
        <thead>
          <tr>
            <th scope="col">{cols.data}</th>
            <th scope="col">{cols.before}</th>
            <th scope="col">{cols.clearing}</th>
            <th scope="col">{cols.after}</th>
            <th scope="col">{cols.always}</th>
          </tr>
        </thead>
        <tbody>
          {matrixRows(enclave, { summary }).map((row) => (
            <tr key={row.id} data-row={row.id}>
              <th scope="row">{row.label}</th>
              {row.cells.map((cell, i) => (
                <td key={i}>
                  <CellView cell={cell} />
                </td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
