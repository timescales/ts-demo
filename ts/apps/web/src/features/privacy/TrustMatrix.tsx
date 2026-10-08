import type { Info } from '@timescales/sdk/api';
import type { VerifiedMarketContext } from '@timescales/sdk/verify';

import { SimulatedLabel } from '../../components/primitives';
import type { SimulatedKind } from '../../components/primitives';
import { privacyCopy } from './copy';
import styles from './Privacy.module.css';

type Trust = Info['trust'];

const v = privacyCopy.trust.values;

function valueOf(key: string): string {
  const value = (v as Record<string, unknown>)[key];
  return typeof value === 'string' ? value : v.unknown;
}

interface TrustRow {
  id: string;
  label: string;
  value: string;
  /** A plum label when the component is simulated, modelled or untested. */
  kind?: SimulatedKind | undefined;
  verified: boolean;
}

/**
 * The live trust configuration: every value comes from `/v1/info.trust`
 * and says it is operator-reported, except the enclave platform once the key
 * committee's signed policies verified it (V-14).
 */
export function trustRows(
  trust: Trust,
  label: VerifiedMarketContext['enclaveLabel'] | null,
): TrustRow[] {
  const enclaveVerified = label === 'intel_tdx_vouched';
  return [
    {
      id: 'enclave',
      label: privacyCopy.trust.labels.enclave,
      value: enclaveVerified ? v.tdxVouched : valueOf(trust.enclave),
      kind: trust.enclave === 'simulated' || label === 'simulated' ? 'simulated' : undefined,
      verified: enclaveVerified,
    },
    {
      id: 'quoteGeneration',
      label: privacyCopy.trust.labels.quoteGeneration,
      value: valueOf(trust.quoteGeneration),
      kind:
        trust.quoteGeneration === 'simulated'
          ? 'simulated'
          : trust.quoteGeneration === 'configfs_tsm_untested_on_hardware'
            ? 'untested'
            : undefined,
      verified: false,
    },
    {
      id: 'quoteVerification',
      label: privacyCopy.trust.labels.quoteVerification,
      value: valueOf(trust.quoteVerification),
      kind: trust.quoteVerification === 'simulated_vendor' ? 'simulated' : undefined,
      verified: false,
    },
    {
      id: 'keyGeneration',
      label: privacyCopy.trust.labels.keyGeneration,
      value: valueOf(trust.keyGeneration),
      verified: false,
    },
    { id: 'dkg', label: privacyCopy.trust.labels.dkg, value: v.dkgNo, verified: false },
    { id: 'mpc', label: privacyCopy.trust.labels.mpc, value: valueOf(trust.mpc), verified: false },
    {
      id: 'reference',
      label: privacyCopy.trust.labels.reference,
      value: valueOf(trust.referencePrice),
      kind: trust.referencePrice === 'modelled_tlsnotary' ? 'modelled' : undefined,
      verified: false,
    },
    {
      id: 'quorum',
      label: privacyCopy.trust.labels.quorum,
      value: v.quorum(trust.receiptQuorum),
      verified: false,
    },
    {
      id: 'executors',
      label: privacyCopy.trust.labels.executors,
      value: String(trust.registeredExecutors),
      verified: false,
    },
  ];
}

/** The rows Welcome shows: what is simulated or modelled today. */
const COMPACT_ROWS = new Set(['enclave', 'keyGeneration', 'reference']);

export function TrustMatrix({
  trust,
  label,
  compact = false,
}: {
  trust: Trust;
  label: VerifiedMarketContext['enclaveLabel'] | null;
  /** Only the enclave, key and reference rows, without the notes. */
  compact?: boolean;
}) {
  const rows = trustRows(trust, label).filter((row) => !compact || COMPACT_ROWS.has(row.id));
  return (
    <div className={styles.card}>
      <dl className={styles.trust} aria-label={privacyCopy.trust.caption}>
        {rows.map((row) => (
          <div key={row.id} className={styles.trustRow} data-row={row.id}>
            <dt>{row.label}</dt>
            <dd>
              <span>{row.value}</span>
              {row.kind ? <SimulatedLabel kind={row.kind} /> : null}
              <span className={styles.qualifier}>
                {row.verified ? privacyCopy.trust.verified : privacyCopy.trust.reported}
              </span>
            </dd>
          </div>
        ))}
      </dl>
      {!compact && trust.notes.length > 0 ? (
        <>
          <h3>{privacyCopy.trust.notes}</h3>
          <ul className={styles.notes}>
            {trust.notes.map((note) => (
              <li key={note}>{note}</li>
            ))}
          </ul>
        </>
      ) : null}
    </div>
  );
}
