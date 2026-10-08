import type { ReactNode } from 'react';

export interface LinkProps {
  href: string;
  className?: string | undefined;
  'aria-current'?: 'page' | undefined;
  children: ReactNode;
}

/** Lets the app shell render router links. The components stay router-agnostic. */
export type RenderLink = (props: LinkProps) => ReactNode;

export const renderAnchor: RenderLink = ({ children, ...props }) => <a {...props}>{children}</a>;
