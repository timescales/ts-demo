import { componentsCopy } from '../copy';
import { Banner } from '../primitives/Banner';
import { Button } from '../primitives/Button';

export interface VerificationBannerProps {
  /** What failed, e.g. "the receipt for epoch #18421". */
  thing: string;
  onRecheck: () => void;
  onExport: () => void;
}

/**
 * A failed client-side check (critical and blocking): the caller also
 * disables trading on the market. Always expanded, never dismissible.
 */
export function VerificationBanner({ thing, onRecheck, onExport }: VerificationBannerProps) {
  const copy = componentsCopy.verification;
  return (
    <Banner
      severity="critical"
      title={copy.title(thing)}
      actions={
        <>
          <Button variant="secondary" size="sm" onClick={onRecheck}>
            {copy.recheck}
          </Button>
          <Button variant="ghost" size="sm" onClick={onExport}>
            {copy.exportDetails}
          </Button>
        </>
      }
    >
      {copy.body}
    </Banner>
  );
}
