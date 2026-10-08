import { Banner } from '../components/primitives';
import { appCopy } from './copy';
import styles from './Page.module.css';

/**
 * Shown instead of the app on an insecure origin (critical and
 * blocking): WebCrypto session keys and the journal need a secure context,
 * so nothing else is started.
 */
export function InsecureContext() {
  return (
    <main id="main" className={styles.standalone}>
      <Banner severity="critical" title={appCopy.insecure.title}>
        {appCopy.insecure.body}
      </Banner>
    </main>
  );
}

export function isSecure(w: { isSecureContext?: boolean } = globalThis): boolean {
  return w.isSecureContext === true;
}
