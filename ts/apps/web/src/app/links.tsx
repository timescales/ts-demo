import { useEffect } from 'react';
import { Link } from 'react-router';

import type { RenderLink } from '../components/chrome';
import { brand } from '../design/brand';

/** Router links for the chrome components, which stay router-agnostic. */
export const routerLink: RenderLink = ({ href, children, ...props }) => (
  <Link to={href} {...props}>
    {children}
  </Link>
);

/**
 * Sets the document title. Titles name the screen and, at most, a public
 * market or epoch. Never an order, price or size.
 */
export function usePageTitle(title: string): void {
  useEffect(() => {
    document.title = `${title} - ${brand.name}`;
  }, [title]);
}
