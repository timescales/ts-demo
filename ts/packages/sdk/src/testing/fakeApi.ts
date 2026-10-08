import { TimescalesApi } from '../api/client.js';

export interface FakeApiOptions {
  now?: () => number;
  latencyMs?: number;
}

/** An in-memory node behind a real `TimescalesApi` (its `fetch` is faked). */
export interface FakeApi {
  readonly api: TimescalesApi;
  readonly requests: readonly { method: string; path: string; body: Uint8Array | null }[];
  respond(method: string, path: string, status: number, body: unknown): void;
  reset(): void;
}

/** What a route handler sees. `params` holds the `{name}` segments of the route's path. */
export interface FakeRequest {
  method: string;
  path: string;
  query: URLSearchParams;
  params: Record<string, string>;
  headers: Headers;
  body: Uint8Array | null;
}

interface Route {
  method: string;
  segments: string[];
  query: string | null;
  status: number;
  body: unknown;
}

export const FAKE_API_BASE_URL = 'http://node.timescales.test';

function json(status: number, body: unknown): Response {
  const problem =
    status >= 400 &&
    typeof body === 'object' &&
    body !== null &&
    'code' in body &&
    'request_id' in body;
  return new Response(
    JSON.stringify(body, (_k, v: unknown) => (typeof v === 'bigint' ? v.toString() : v)),
    {
      status,
      headers: {
        'content-type': problem ? 'application/problem+json' : 'application/json',
        'x-request-id': 'fake',
      },
    },
  );
}

function toResponse(status: number, body: unknown): Response {
  if (body instanceof Response) return body;
  if (body === undefined || body === null || status === 204) return new Response(null, { status });
  if (body instanceof Uint8Array) {
    return new Response(body.slice().buffer, {
      status,
      headers: { 'content-type': 'application/octet-stream' },
    });
  }
  return json(status, body);
}

function notFound(path: string): Response {
  return json(404, {
    type: 'urn:timescales:error:not_found',
    title: 'Not found',
    status: 404,
    code: 'NOT_FOUND',
    detail: `no fake response for ${path}`,
    retryable: false,
    request_id: 'fake',
  });
}

function match(route: Route, segments: string[], query: string): Record<string, string> | null {
  if (route.segments.length !== segments.length) return null;
  if (route.query !== null && route.query !== query) return null;
  const params: Record<string, string> = {};
  for (let i = 0; i < segments.length; i++) {
    const want = route.segments[i]!;
    const got = segments[i]!;
    if (want.startsWith('{') && want.endsWith('}'))
      params[want.slice(1, -1)] = decodeURIComponent(got);
    else if (want !== got) return null;
  }
  return params;
}

/**
 * A scriptable node. `respond(method, path, status, body)` registers a
 * response. For a request the most specific registration wins (fewest
 * `{param}` segments), then the newest. `path` may name
 * segments as `{param}` and may carry a query that must match exactly.
 * `body` is JSON (bigints become decimal strings), a `Uint8Array` served as
 * `application/octet-stream`, a `Response`, or a function of the
 * {@link FakeRequest} returning one of those. `GET /v1/time` answers with
 * `now` unless overridden. Any other unregistered request gets a 404
 * `NOT_FOUND` problem. Every request is recorded with its body.
 */
export function createFakeApi(o?: FakeApiOptions): FakeApi {
  const now = o?.now ?? (() => Date.now());
  const routes: Route[] = [];
  const requests: { method: string; path: string; body: Uint8Array | null }[] = [];

  const fakeFetch = async (
    input: string | URL | Request,
    init?: RequestInit,
  ): Promise<Response> => {
    const url = new URL(typeof input === 'string' || input instanceof URL ? input : input.url);
    const method = (init?.method ?? 'GET').toUpperCase();
    const raw = init?.body;
    const body =
      raw === undefined || raw === null
        ? null
        : typeof raw === 'string'
          ? new TextEncoder().encode(raw)
          : raw instanceof Uint8Array
            ? raw.slice()
            : null;
    requests.push({ method, path: url.pathname + url.search, body });
    if (o?.latencyMs !== undefined && o.latencyMs > 0) {
      await new Promise((resolve) => setTimeout(resolve, o.latencyMs));
    }
    if (init?.signal?.aborted === true) throw new DOMException('aborted', 'AbortError');
    const segments = url.pathname.split('/').filter((s) => s.length > 0);
    const query = url.search.startsWith('?') ? url.search.slice(1) : url.search;
    // The most specific route wins (fewest `{param}` segments), then the newest.
    let best: { route: Route; params: Record<string, string>; wild: number } | null = null;
    for (let i = routes.length - 1; i >= 0; i--) {
      const route = routes[i]!;
      if (route.method !== method) continue;
      const params = match(route, segments, query);
      if (params === null) continue;
      const wild = Object.keys(params).length;
      if (best === null || wild < best.wild) best = { route, params, wild };
    }
    if (best !== null) {
      let out = best.route.body;
      if (typeof out === 'function') {
        out = await (out as (r: FakeRequest) => unknown)({
          method,
          path: url.pathname,
          query: url.searchParams,
          params: best.params,
          headers: new Headers(init?.headers),
          body,
        });
      }
      return toResponse(best.route.status, out);
    }
    if (method === 'GET' && url.pathname === '/v1/time') {
      return json(200, { server_time_ms: Math.floor(now()), slot: '0' });
    }
    return notFound(url.pathname);
  };

  return {
    api: new TimescalesApi({ baseUrl: FAKE_API_BASE_URL, fetch: fakeFetch as typeof fetch }),
    requests,
    respond(method, path, status, body) {
      const [p, q] = path.split('?', 2) as [string, string | undefined];
      routes.push({
        method: method.toUpperCase(),
        segments: p.split('/').filter((s) => s.length > 0),
        query: q ?? null,
        status,
        body,
      });
    },
    reset() {
      routes.length = 0;
      requests.length = 0;
    },
  };
}
