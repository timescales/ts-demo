import { TimescalesError } from '@timescales/sdk';
import { useParams } from 'react-router';

import { EmptyState, Skeleton } from '../../components/primitives';
import { routerLink, usePageTitle } from '../../app/links';
import pageStyles from '../../app/Page.module.css';
import { useLiveMarket } from '../../state/hooks';
import { useEpoch, useMarketDetail } from '../../state/queries';
import { parseAddress, parseU64 } from '../../state/types';
import { epochsCopy } from './copy';
import { EpochDetailView } from './EpochDetailView';
import { EpochExplorer } from './EpochExplorer';
import styles from './Epochs.module.css';

function errorCopy(e: unknown): string {
  if (e instanceof TimescalesError && e.code === 'PRUNED') return epochsCopy.pruned;
  if (e instanceof TimescalesError && e.code === 'NOT_FOUND') return epochsCopy.notFound;
  return epochsCopy.loadFailed;
}

/** `/epochs/:market` (explorer) and `/epochs/:market/:epoch` (detail). */
export default function EpochsPage() {
  const params = useParams();
  const market = parseAddress(params.market);
  const epoch = params.epoch === undefined ? null : parseU64(params.epoch);
  const invalid = market === null || (params.epoch !== undefined && epoch === null);
  const detail = useMarketDetail(market).data;
  useLiveMarket(market);
  const query = useEpoch(epoch === null ? null : market, epoch);
  const title = epoch === null ? epochsCopy.title : epochsCopy.detailTitle(String(epoch));
  usePageTitle(title);
  if (invalid) {
    return (
      <div className={pageStyles.page}>
        <EmptyState as="h1" title={epochsCopy.title} body={epochsCopy.invalid} />
      </div>
    );
  }
  return (
    <div className={pageStyles.page}>
      <header className={pageStyles.header}>
        {epoch !== null ? (
          <span className={styles.back}>
            {routerLink({ href: `/epochs/${market}`, children: epochsCopy.back })}
          </span>
        ) : null}
        <h1>{title}</h1>
        <p className={pageStyles.lede}>
          {detail ? `${detail.name} - ` : ''}
          {epochsCopy.lede}
        </p>
      </header>
      {epoch === null ? (
        <EpochExplorer market={market} />
      ) : query.data ? (
        <EpochDetailView market={market} detail={query.data} marketDetail={detail} />
      ) : query.isError ? (
        <p>{errorCopy(query.error)}</p>
      ) : (
        <Skeleton lines={6} />
      )}
    </div>
  );
}
