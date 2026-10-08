import { Skeleton } from '../../components/primitives';
import { routerLink, usePageTitle } from '../../app/links';
import pageStyles from '../../app/Page.module.css';
import { useRouteMarket } from '../../app/routeMarket';
import { enclaveTrust } from '../../app/Footer';
import { useMarketCheck } from '../../state/hooks';
import { useInfo } from '../../state/queries';
import { privacyCopy } from './copy';
import { ThreatCards } from './ThreatCards';
import { TrustMatrix } from './TrustMatrix';
import { WhoSeesWhatMatrix } from './WhoSeesWhatMatrix';

export default function PrivacyPage() {
  usePageTitle(privacyCopy.title);
  const market = useRouteMarket();
  const info = useInfo();
  const check = useMarketCheck(market);
  const enclave = enclaveTrust(check, info.data);
  const label = check?.status === 'ok' ? check.ctx.enclaveLabel : null;
  return (
    <div className={pageStyles.page}>
      <header className={pageStyles.header}>
        <h1>{privacyCopy.title}</h1>
        <p className={pageStyles.lede}>{privacyCopy.lede}</p>
      </header>
      <WhoSeesWhatMatrix enclave={enclave} />
      <section className={pageStyles.section} aria-labelledby="privacy-trust">
        <h2 id="privacy-trust">{privacyCopy.trust.title}</h2>
        {info.data ? (
          <TrustMatrix trust={info.data.trust} label={label} />
        ) : info.isError ? (
          <p className={pageStyles.muted}>{privacyCopy.trust.unavailable}</p>
        ) : (
          <Skeleton lines={4} label={privacyCopy.trust.loading} />
        )}
      </section>
      <section className={pageStyles.section} aria-labelledby="privacy-threats">
        <h2 id="privacy-threats">{privacyCopy.threats.title}</h2>
        <ThreatCards />
      </section>
      <section className={pageStyles.section} aria-labelledby="privacy-retention">
        <h2 id="privacy-retention">{privacyCopy.retention.title}</h2>
        {privacyCopy.retention.text.map((p) => (
          <p key={p} className={pageStyles.lede}>
            {p}
          </p>
        ))}
      </section>
      <section className={pageStyles.section} aria-labelledby="privacy-device">
        <h2 id="privacy-device">{privacyCopy.device.title}</h2>
        {privacyCopy.device.text.map((p) => (
          <p key={p} className={pageStyles.lede}>
            {p}
          </p>
        ))}
        <p>
          {routerLink({ href: '/settings#local-data', children: privacyCopy.device.settingsLink })}
        </p>
      </section>
    </div>
  );
}
