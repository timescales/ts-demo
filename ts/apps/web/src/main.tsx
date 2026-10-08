import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';

import { App } from './app/App';

const root = document.getElementById('root');
if (!root) {
  throw new Error('index.html has no #root element');
}
createRoot(root).render(
  <StrictMode>
    <App />
  </StrictMode>,
);

// Mobile Wallet Adapter only matters on Android. Everywhere else its code is
// never downloaded.
if (/\bAndroid\b/.test(navigator.userAgent)) {
  void import('./app/mwa').then(({ registerMobileWalletAdapter }) => {
    registerMobileWalletAdapter();
  });
}
