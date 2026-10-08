import '../styles/index.css';

import { QueryClientProvider } from '@tanstack/react-query';
import { createBrowserRouter } from 'react-router';
import { RouterProvider } from 'react-router/dom';

import { appRoutes } from '../routes/routes';
import type { Runtime } from '../state/runtime';
import { RuntimeProvider, createRuntime } from '../state/runtime';
import { applyDocumentSettings, settingsStore } from '../state/settings';
import { readConfig } from './config';
import { InsecureContext, isSecure } from './InsecureContext';

type Router = ReturnType<typeof createBrowserRouter>;

/** Providers around a router: the runtime's services, stores and query cache. */
export function AppProviders({ runtime, router }: { runtime: Runtime; router: Router }) {
  return (
    <RuntimeProvider runtime={runtime}>
      <QueryClientProvider client={runtime.queryClient}>
        <RouterProvider router={router} />
      </QueryClientProvider>
    </RuntimeProvider>
  );
}

// One runtime per page load: it owns the stream socket, the wallet registry
// and the order service's tab leadership, which outlive any component.
let app: { runtime: Runtime; router: Router } | null = null;

function SecureApp() {
  app ??= {
    runtime: createRuntime(readConfig(import.meta.env)),
    router: createBrowserRouter(appRoutes()),
  };
  return <AppProviders runtime={app.runtime} router={app.router} />;
}

export function App() {
  // Theme attributes before the first paint, so the page never flashes.
  applyDocumentSettings(settingsStore.get());
  if (!isSecure()) return <InsecureContext />;
  return <SecureApp />;
}
