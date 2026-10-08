import { componentsCopy } from '../copy';
import { Banner } from '../primitives/Banner';
import type { RenderLink } from './links';
import { renderAnchor } from './links';
import styles from './SimulatedBanner.module.css';

export interface SimulatedBannerProps {
  privacyHref: string;
  collapsed: boolean;
  onToggle: () => void;
  renderLink?: RenderLink | undefined;
}

/** The collapsible simulated-enclave notice on Trade. The footer label stays pinned. */
export function SimulatedBanner({
  privacyHref,
  collapsed,
  onToggle,
  renderLink = renderAnchor,
}: SimulatedBannerProps) {
  const copy = componentsCopy.simulatedBanner;
  return (
    <Banner
      severity="simulated"
      title={copy.title}
      collapsed={collapsed}
      onToggle={onToggle}
      actions={renderLink({ href: privacyHref, className: styles.link, children: copy.privacy })}
    >
      {copy.body}
    </Banner>
  );
}
