import type { MarketDetail } from '@timescales/sdk/api';
import { Info } from 'lucide-react';

import type { Column } from '../../components/primitives';
import { IconButton, Table, Tooltip } from '../../components/primitives';
import type { Amounts } from '../trade/reservation';
import type { NumberFormat } from '../trade/services';
import { atomsToDecimal, localize } from '../trade/units';
import type { Buckets } from './balances';
import { fundsCopy } from './copy';
import styles from './funds.module.css';

interface Row {
  key: keyof Omit<Buckets, 'unlockEpoch'>;
  label: string;
  info: string;
  visibility: string;
  base: string;
  quote: string;
}

export interface BalanceBucketsProps {
  detail: MarketDetail;
  buckets: Buckets;
  numberFormat: NumberFormat;
}

/** Where the trader's tokens are, and who can see each bucket. */
export function BalanceBuckets({ detail, buckets, numberFormat }: BalanceBucketsProps) {
  const c = fundsCopy.buckets;
  const fmt = (atoms: bigint, decimals: number) =>
    localize(atomsToDecimal(atoms, decimals), numberFormat);
  const pair = (a: Amounts | null, missing: string): [string, string] =>
    a === null
      ? [missing, missing]
      : [fmt(a.base, detail.baseDecimals), fmt(a.quote, detail.quoteDecimals)];
  const wallet: [string, string] = [
    buckets.wallet.base === null ? c.noAta : fmt(buckets.wallet.base, detail.baseDecimals),
    buckets.wallet.quote === null ? c.noAta : fmt(buckets.wallet.quote, detail.quoteDecimals),
  ];
  const rows: Row[] = [
    {
      key: 'wallet',
      label: c.wallet,
      info: c.walletInfo,
      visibility: c.public,
      ...amounts(wallet),
    },
    {
      key: 'inAccount',
      label: c.timescales,
      info: c.timescalesInfo,
      visibility: c.public,
      ...amounts(pair(buckets.inAccount, c.noAccount)),
    },
    {
      key: 'reserved',
      label: c.reserved,
      info: c.reservedInfo,
      visibility: c.private,
      ...amounts(pair(buckets.reserved, c.unknown)),
    },
    {
      key: 'pending',
      label: c.pending,
      info: c.pendingInfo,
      visibility: c.publicOncePosted,
      ...amounts(pair(buckets.pending, c.unknown)),
    },
    {
      key: 'requested',
      label: c.requested,
      info: c.requestedInfo,
      visibility: c.public,
      ...amounts(pair(buckets.requested, c.noAccount)),
    },
    {
      key: 'withdrawable',
      label: c.withdrawable,
      info: c.withdrawableInfo,
      visibility: c.public,
      ...amounts(pair(buckets.withdrawable, c.noAccount)),
    },
  ];
  const columns: Column<Row>[] = [
    {
      key: 'bucket',
      header: c.bucket,
      cell: (r) => (
        <span className={styles.bucket}>
          {r.label}
          <Tooltip content={r.info}>
            <IconButton label={c.info(r.label)} icon={<Info size={16} aria-hidden="true" />} />
          </Tooltip>
        </span>
      ),
    },
    { key: 'base', header: detail.baseSymbol, cell: (r) => r.base, numeric: true },
    { key: 'quote', header: detail.quoteSymbol, cell: (r) => r.quote, numeric: true },
    { key: 'visibility', header: c.visibility, cell: (r) => r.visibility },
  ];
  return (
    <section aria-labelledby="balance-buckets-title" className={styles.section}>
      <h2 id="balance-buckets-title">{c.title}</h2>
      <Table
        caption={c.caption}
        captionHidden
        columns={columns}
        rows={rows}
        rowKey={(r) => r.key}
      />
    </section>
  );
}

function amounts([base, quote]: [string, string]): { base: string; quote: string } {
  return { base, quote };
}
