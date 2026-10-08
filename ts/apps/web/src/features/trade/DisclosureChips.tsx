import type { Trust } from '@timescales/sdk/api';
import type { VerifiedMarketContext } from '@timescales/sdk/verify';
import { Eye, EyeOff, Globe, Link2 } from 'lucide-react';

import { SimulatedLabel } from '../../components/primitives';
import { tradeCopy } from './copy';
import styles from './trade.module.css';

export type EnclaveLabel = VerifiedMarketContext['enclaveLabel'];

/**
 * The enclave label to disclose: the verified one (V-14) when this device
 * checked the market, otherwise what the operator reports, which can never
 * read as verified TDX.
 */
export function enclaveLabel(
  verified: EnclaveLabel | undefined,
  reported: Trust['enclave'] | undefined,
): EnclaveLabel {
  if (verified !== undefined) return verified;
  return reported === 'intel_tdx' ? 'operator_reported' : 'simulated';
}

/** Who can read the sealed order, per verified trust variant. */
export function DisclosureChips({ enclave }: { enclave: EnclaveLabel }) {
  const copy = tradeCopy.disclosure;
  return (
    <ul className={styles.chips} aria-label={copy.label}>
      <li className={styles.chip} data-tone={enclave === 'simulated' ? 'simulated' : undefined}>
        {enclave === 'simulated' ? (
          <>
            <SimulatedLabel />
            <span>{copy.simulated}</span>
          </>
        ) : (
          <>
            <EyeOff size={16} aria-hidden="true" />
            <span>
              {copy.tdx}
              {enclave === 'operator_reported' ? ` ${copy.operatorReported}` : ''}
            </span>
          </>
        )}
      </li>
      <li className={styles.chip}>
        <Eye size={16} aria-hidden="true" />
        <span>{copy.publicIfFilled}</span>
      </li>
      <li className={styles.chip}>
        <Globe size={16} aria-hidden="true" />
        <span>{copy.alwaysPublic}</span>
      </li>
      <li className={styles.chip}>
        <Link2 size={16} aria-hidden="true" />
        <span>{copy.linkable}</span>
      </li>
    </ul>
  );
}
