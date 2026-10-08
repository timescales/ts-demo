import {
  createDefaultAuthorizationCache,
  createDefaultChainSelector,
  registerMwa,
} from '@solana-mobile/wallet-standard-mobile';

import { reportWalletNotFound } from './walletNotFound';

/**
 * Registers the Mobile Wallet Adapter as a Wallet Standard wallet (Android).
 *
 * The library's default wallet-not-found handler opens a modal built by
 * assigning HTML strings to innerHTML and appending a <style> element. The
 * CSP (require-trusted-types-for 'script', style-src 'self') blocks both, so
 * the app records the condition and shows its own notice instead.
 */
export function registerMobileWalletAdapter(): void {
  registerMwa({
    appIdentity: { uri: window.location.origin },
    authorizationCache: createDefaultAuthorizationCache(),
    chains: ['solana:mainnet', 'solana:devnet', 'solana:localnet'],
    chainSelector: createDefaultChainSelector(),
    onWalletNotFound: () => {
      reportWalletNotFound();
      return Promise.resolve();
    },
  });
}
