import { usePageTitle } from './links';
import styles from './Page.module.css';

export interface PlaceholderPageProps {
  title: string;
  body: string;
}

/** A screen whose feature is not built yet. The shell provides <main>. */
export function PlaceholderPage({ title, body }: PlaceholderPageProps) {
  usePageTitle(title);
  return (
    <div className={styles.page}>
      <h1>{title}</h1>
      <p>{body}</p>
    </div>
  );
}
