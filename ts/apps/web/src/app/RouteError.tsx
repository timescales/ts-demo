import { Banner, Button } from '../components/primitives';
import { appCopy } from './copy';
import styles from './Page.module.css';

/**
 * A screen that failed to load or render (for example a lazy chunk that
 * could not be fetched). The details stay in the console. The copy does not
 * echo them, since they may name the route's parameters.
 */
export function RouteError() {
  return (
    <main id="main" className={styles.standalone}>
      <Banner
        severity="critical"
        title={appCopy.pageError}
        actions={
          <Button variant="secondary" size="sm" onClick={() => window.location.reload()}>
            {appCopy.reload}
          </Button>
        }
      />
    </main>
  );
}
