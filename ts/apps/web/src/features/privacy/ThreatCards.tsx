import { ShieldAlert, ShieldCheck } from 'lucide-react';

import { privacyCopy } from './copy';
import styles from './Privacy.module.css';

/**  threat cards: what the design protects against and what it does not. */
export function ThreatCards() {
  const t = privacyCopy.threats;
  return (
    <div className={styles.cards}>
      <section className={styles.card} aria-labelledby="threats-protects">
        <h3 id="threats-protects" className={styles.cell}>
          <ShieldCheck size={20} aria-hidden="true" />
          {t.protects}
        </h3>
        <ul>
          {t.protectsList.map((item) => (
            <li key={item}>{item}</li>
          ))}
        </ul>
      </section>
      <section className={styles.card} aria-labelledby="threats-does-not">
        <h3 id="threats-does-not" className={styles.cell}>
          <ShieldAlert size={20} aria-hidden="true" />
          {t.doesNot}
        </h3>
        <ul>
          {t.doesNotList.map((item) => (
            <li key={item.text}>{item.strong ? <strong>{item.text}</strong> : item.text}</li>
          ))}
        </ul>
      </section>
    </div>
  );
}
