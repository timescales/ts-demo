import type { MarketDetail, Trust } from '@timescales/sdk/api';
import type { PriceBand } from '@timescales/sdk/core';

import { Badge, SimulatedLabel } from '../../components/primitives';
import { tradeCopy } from './copy';
import type { NumberFormat } from './services';
import styles from './trade.module.css';
import { unitsOf } from './data';
import { localize, priceOf } from './units';

export interface MarketHeaderProps {
  detail: MarketDetail;
  band: PriceBand | null;
  referenceSource: Trust['referencePrice'];
  numberFormat: NumberFormat;
}

/** Pair, flow mode, this epoch's band in price units and where the reference comes from. */
export function MarketHeader({ detail, band, referenceSource, numberFormat }: MarketHeaderProps) {
  const copy = tradeCopy.header;
  const u = unitsOf(detail);
  const price = (tick: bigint) => localize(priceOf(u, tick), numberFormat);
  return (
    <header className={styles.marketHeader} aria-label={copy.label}>
      <h1 className={styles.pair}>{detail.name}</h1>
      <dl className={styles.facts}>
        <div>
          <dt>{copy.flowLabel}</dt>
          <dd>{detail.params.flow === 1 ? copy.flow.dual : copy.flow.single}</dd>
        </div>
        <div>
          <dt>{copy.band}</dt>
          <dd className={styles.mono}>
            {band ? copy.bandValue(price(band.lo), price(band.hi)) : copy.noBand}
          </dd>
        </div>
        <div>
          <dt>{copy.reference}</dt>
          <dd>
            {copy.referenceSource[referenceSource]}
            {referenceSource === 'modelled_tlsnotary' ? <SimulatedLabel kind="modelled" /> : null}
          </dd>
        </div>
      </dl>
      {detail.halted ? <Badge tone="danger">{copy.halted}</Badge> : null}
    </header>
  );
}
