// Platform hints for wallet discovery. Detection only chooses what to
// offer. Nothing here is a security decision.

export function isAndroid(userAgent: string): boolean {
  return /\bAndroid\b/.test(userAgent);
}

/** iPhone, iPod and iPad (iPadOS reports a Mac with touch). */
export function isIOS(userAgent: string, maxTouchPoints = 0): boolean {
  return (
    /\b(iPhone|iPad|iPod)\b/.test(userAgent) ||
    (/\bMacintosh\b/.test(userAgent) && maxTouchPoints > 1)
  );
}

export interface HandoffLink {
  wallet: string;
  href: string;
}

/**
 * Links that open this page in a wallet's in-app browser, the only way to
 * connect a wallet on iOS Safari. The URL formats are the wallets' published
 * universal-link schemes (an external claim, checked by the manual wallet
 * matrix).
 */
export function walletHandoffLinks(pageUrl: string): HandoffLink[] {
  const url = encodeURIComponent(pageUrl);
  const ref = encodeURIComponent(new URL(pageUrl).origin);
  return [
    { wallet: 'Phantom', href: `https://phantom.app/ul/browse/${url}?ref=${ref}` },
    { wallet: 'Solflare', href: `https://solflare.com/ul/v1/browse/${url}?ref=${ref}` },
    { wallet: 'Backpack', href: `https://backpack.app/ul/v1/browse/${url}?ref=${ref}` },
  ];
}
