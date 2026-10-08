// Test-only: renders a screen with the trader services, a query client and
// a memory router, the way the app shell mounts it.
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { render } from '@testing-library/react';
import type { ReactElement } from 'react';
import { createMemoryRouter, RouterProvider } from 'react-router';

import type { TraderServices } from '../services';
import { TraderServicesProvider } from '../services';

export function renderScreen(
  element: ReactElement,
  o: { services: TraderServices | null; path: string; url: string; extra?: string[] },
) {
  const client = new QueryClient({
    defaultOptions: { queries: { retry: false, refetchOnWindowFocus: false } },
  });
  const router = createMemoryRouter(
    [
      { path: o.path, element },
      ...(o.extra ?? []).map((path) => ({ path, element: <p>{`route ${path}`}</p> })),
      { path: '*', element: <p>elsewhere</p> },
    ],
    { initialEntries: [o.url] },
  );
  const tree = <RouterProvider router={router} />;
  const result = render(
    <QueryClientProvider client={client}>
      {o.services ? (
        <TraderServicesProvider value={o.services}>{tree}</TraderServicesProvider>
      ) : (
        tree
      )}
    </QueryClientProvider>,
  );
  return { ...result, router, client };
}
