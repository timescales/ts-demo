import { componentsCopy } from '../copy';
import { Banner } from '../primitives/Banner';
import type { RenderLink } from './links';
import { renderAnchor } from './links';
import styles from './GovernanceWatch.module.css';

export type GovernanceKind = keyof typeof componentsCopy.governance.kinds;

export interface PendingChange {
  kind: GovernanceKind;
  /** Time until it applies, preformatted ("23 h"). */
  eta: string;
  /** A timelock or quorum decrease (: warning). */
  decrease?: boolean | undefined;
}

export interface GovernanceWatchProps {
  changes: readonly PendingChange[];
  noEffectiveTimelock?: boolean | undefined;
  /** Preformatted time since the last program upgrade, when recent. */
  recentUpgradeAgo?: string | null | undefined;
  /** The upgrade authority is not the expected one (critical). */
  unexpectedAuthority?: boolean | undefined;
  reviewHref: string;
  fundsHref: string;
  renderLink?: RenderLink | undefined;
}

/** Pending trust changes and recent program upgrades, before they apply. */
export function GovernanceWatch({
  changes,
  noEffectiveTimelock = false,
  recentUpgradeAgo,
  unexpectedAuthority = false,
  reviewHref,
  fundsHref,
  renderLink = renderAnchor,
}: GovernanceWatchProps) {
  const copy = componentsCopy.governance;
  const lines: { key: string; text: string }[] = [];
  if (unexpectedAuthority) lines.push({ key: 'authority', text: copy.unexpectedAuthority });
  for (const change of changes) {
    lines.push({
      key: `change-${change.kind}`,
      text: change.decrease
        ? `${copy.change(change.eta, copy.kinds[change.kind])} ${copy.decrease}`
        : copy.change(change.eta, copy.kinds[change.kind]),
    });
  }
  if (noEffectiveTimelock) lines.push({ key: 'timelock', text: copy.noTimelock });
  if (recentUpgradeAgo) lines.push({ key: 'upgrade', text: copy.upgraded(recentUpgradeAgo) });
  if (lines.length === 0) return null;

  return (
    <Banner
      severity={unexpectedAuthority ? 'critical' : 'warning'}
      title={copy.title}
      actions={
        <>
          {renderLink({ href: reviewHref, className: styles.link, children: copy.review })}
          {renderLink({ href: fundsHref, className: styles.link, children: copy.funds })}
        </>
      }
    >
      <ul className={styles.list}>
        {lines.map((line) => (
          <li key={line.key}>{line.text}</li>
        ))}
      </ul>
    </Banner>
  );
}
