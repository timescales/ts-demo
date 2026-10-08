import { EmptyState } from '../components/primitives';
import { appCopy } from './copy';
import { routerLink, usePageTitle } from './links';
import styles from './Page.module.css';

export function NotFound() {
  usePageTitle(appCopy.notFoundTitle);
  return (
    <div className={styles.page}>
      <EmptyState
        as="h1"
        title={appCopy.notFoundTitle}
        body={appCopy.notFoundBody}
        action={routerLink({ href: '/', children: appCopy.notFoundHome })}
      />
    </div>
  );
}
