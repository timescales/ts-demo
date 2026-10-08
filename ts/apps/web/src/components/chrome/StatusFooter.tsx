import { useLayoutEffect, useRef } from 'react';

import { componentsCopy } from '../copy';
import { cx } from '../cx';
import { SimulatedLabel } from '../primitives/SimulatedLabel';
import type { U64 } from '../types';
import type { RenderLink } from './links';
import { renderAnchor } from './links';
import styles from './StatusFooter.module.css';

/** The enclave trust label (V-14): only the key committee can vouch for TDX. */
export type EnclaveTrust = 'simulated' | 'tdx_vouched' | 'tdx_reported';
export type Health = 'ok' | 'degraded' | 'down';
export type StreamState = 'live' | 'polling' | 'reconnecting';

export interface StatusFooterProps {
  enclave: EnclaveTrust;
  cluster: string;
  slot: U64 | null;
  rpc: Health;
  apiVersion: string;
  api: Health;
  stream: StreamState;
  reference: 'operator' | 'modelled';
  /**
   * Footer links in this fixed order: Status, Privacy, Verify, Settings, Help.
   * Verify and Settings are shown from 600 px up, where the tab bar's "More"
   * menu is hidden.
   */
  links: { status: string; privacy: string; verify?: string; settings?: string; help: string };
  renderLink?: RenderLink | undefined;
  /**
   * Publish the measured height as --footer-h (default). Turn it off for a
   * footer shown in place, such as a sample in the gallery.
   */
  publishHeight?: boolean | undefined;
}

const STREAM_HEALTH: Record<StreamState, Health> = {
  live: 'ok',
  polling: 'degraded',
  reconnecting: 'down',
};

function Dot({ health, children }: { health: Health; children: string }) {
  return (
    <span className={styles.dot} data-health={health}>
      <span aria-hidden="true" className={styles.mark}>
        ●
      </span>
      {children}
    </span>
  );
}

/**
 * Publishes the element's rendered height as a custom property on <html>.
 * The footer's height depends on the width, the text size and its content,
 * so the scroll padding that keeps focus clear of it reads the measured
 * value rather than a constant. Set through the CSSOM, which the CSP allows.
 */
function usePublishedHeight<T extends HTMLElement>(property: string, enabled: boolean) {
  const ref = useRef<T>(null);
  useLayoutEffect(() => {
    const element = ref.current;
    if (!enabled || !element || typeof ResizeObserver === 'undefined') return;
    const root = document.documentElement;
    const publish = () => {
      const height = Math.ceil(element.getBoundingClientRect().height);
      // Not laid out (hidden or no layout engine): keep the nominal token.
      if (height > 0) root.style.setProperty(property, `${height}px`);
      else root.style.removeProperty(property);
    };
    publish();
    const observer = new ResizeObserver(publish);
    observer.observe(element);
    return () => {
      observer.disconnect();
      root.style.removeProperty(property);
    };
  }, [property, enabled]);
  return ref;
}

/**
 * The live status bar. The enclave label comes first and stays pinned.
 * The other items wrap onto further lines on narrow screens rather than
 * scrolling (WCAG 1.4.10). Items keep the same order everywhere (3.2.6).
 * Its measured height is published as --footer-h for --chrome-bottom.
 */
export function StatusFooter({
  enclave,
  cluster,
  slot,
  rpc,
  apiVersion,
  api,
  stream,
  reference,
  links,
  renderLink = renderAnchor,
  publishHeight = true,
}: StatusFooterProps) {
  const copy = componentsCopy.footer;
  const ref = usePublishedHeight<HTMLElement>('--footer-h', publishHeight);
  return (
    <footer ref={ref} className={styles.footer} aria-label={copy.label}>
      <div className={styles.enclave}>
        {enclave === 'simulated' ? (
          <SimulatedLabel>{copy.enclaveSimulated}</SimulatedLabel>
        ) : enclave === 'tdx_vouched' ? (
          <>
            <span className={styles.tdx}>{copy.enclaveTdxVouched}</span>
            <span aria-hidden="true">*</span>
            {/* TDX quote generation is untested on hardware (K). */}
            <SimulatedLabel kind="untested" className={styles.untested}>
              {copy.quoteUntested}
            </SimulatedLabel>
          </>
        ) : (
          <span className={styles.tdx}>{copy.enclaveTdxReported}</span>
        )}
      </div>
      <ul className={styles.items}>
        <li>
          {cluster}
          {slot !== null ? ` - ${copy.slot(String(slot))}` : null}
          {' - '}
          <Dot health={rpc}>{`${copy.rpc} ${copy.health[rpc]}`}</Dot>
        </li>
        <li>
          <Dot health={api}>{`${copy.api(apiVersion)} ${copy.health[api]}`}</Dot>
        </li>
        <li>
          <Dot health={STREAM_HEALTH[stream]}>{`${copy.stream} ${copy.streamState[stream]}`}</Dot>
        </li>
        <li>{copy.keys}</li>
        <li>
          {reference === 'modelled' ? (
            <SimulatedLabel kind="modelled">{copy.reference.modelled}</SimulatedLabel>
          ) : (
            copy.reference.operator
          )}
        </li>
        <li className={styles.links}>
          {renderLink({ href: links.status, className: styles.link, children: copy.links.status })}
          {renderLink({
            href: links.privacy,
            className: styles.link,
            children: copy.links.privacy,
          })}
          {links.verify !== undefined
            ? renderLink({
                href: links.verify,
                className: cx(styles.link, styles.wide),
                children: copy.links.verify,
              })
            : null}
          {links.settings !== undefined
            ? renderLink({
                href: links.settings,
                className: cx(styles.link, styles.wide),
                children: copy.links.settings,
              })
            : null}
          {renderLink({ href: links.help, className: cx(styles.link), children: copy.links.help })}
        </li>
      </ul>
    </footer>
  );
}
