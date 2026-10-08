import { readFileSync } from 'node:fs';

import react from '@vitejs/plugin-react';
import { defaultClientConditions, defineConfig } from 'vite';

// The production edge serves the same headers. `vite preview` uses
// them so local and browser-test runs see the real CSP.
const securityHeaders = JSON.parse(
  readFileSync(new URL('./security-headers.json', import.meta.url), 'utf8'),
) as Record<string, string>;
// Extra connect-src origins for a preview against a remote cluster.
const extraConnect = (process.env.TIMESCALES_PREVIEW_CONNECT_SRC ?? '').trim();
if (extraConnect.length > 0) {
  const csp = securityHeaders['Content-Security-Policy'] ?? '';
  securityHeaders['Content-Security-Policy'] = csp.replace(
    /connect-src ([^;]*)/,
    (_, list: string) => `connect-src ${list} ${extraConnect}`,
  );
}

export default defineConfig({
  plugins: [react()],
  resolve: {
    // `source` resolves @timescales/sdk to its TypeScript sources, so the app
    // builds without a prior SDK build.
    conditions: ['source', ...defaultClientConditions],
  },
  build: {
    target: 'es2022',
    // Fonts and images are never inlined as data: URIs.
    assetsInlineLimit: 0,
    sourcemap: true,
  },
  preview: {
    headers: securityHeaders,
  },
});
