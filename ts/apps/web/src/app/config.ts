// Build-time configuration (pins, RPC allowlist). Everything here is
// fixed when the app is built. Nothing the node reports may stand in for it.
import type { AppPins } from '@timescales/sdk/verify';

import type { Address, Cluster } from '../state/types';
import { parseAddress } from '../state/types';

export interface RpcOption {
  /** Stable id stored in settings. */
  id: string;
  label: string;
  url: string;
}

export interface AppConfig {
  /** Origin of the node's public API (`/v1/...`). */
  apiBaseUrl: string;
  /** WebSocket URL of `GET /v1/stream`. */
  streamUrl: string;
  /** The vetted RPC endpoints Settings may choose from. Also listed in the CSP. */
  rpcAllowlist: readonly RpcOption[];
  cluster: Cluster;
  programId: Address | null;
  /** Empty when the build pins none: market verification then fails closed. */
  genesisHash: string;
  /** Pinned market addresses. The first is the default market. */
  markets: readonly Address[];
  upgradeAuthority: Address | null;
  /** Wallets listed as PASSED in the signed-off wallet matrix (none until it is performed). */
  testedWallets: readonly string[];
}

type Env = Record<string, string | boolean | undefined>;

function str(env: Env, key: string): string | undefined {
  const v = env[key];
  return typeof v === 'string' && v.trim().length > 0 ? v.trim() : undefined;
}

function cluster(text: string | undefined): Cluster {
  return text === 'devnet' || text === 'mainnet-beta' ? text : 'localnet';
}

/** `label|url` entries separated by commas. A bare URL is its own label. */
export function parseRpcAllowlist(text: string | undefined): RpcOption[] {
  if (text === undefined) return [];
  const out: RpcOption[] = [];
  for (const entry of text.split(',')) {
    const trimmed = entry.trim();
    if (trimmed.length === 0) continue;
    const bar = trimmed.indexOf('|');
    const label = bar >= 0 ? trimmed.slice(0, bar).trim() : trimmed;
    const url = (bar >= 0 ? trimmed.slice(bar + 1) : trimmed).trim();
    let parsed: URL;
    try {
      parsed = new URL(url);
    } catch {
      continue;
    }
    if (parsed.protocol !== 'https:' && parsed.protocol !== 'http:') continue;
    out.push({ id: parsed.origin + parsed.pathname, label, url: parsed.href });
  }
  return out;
}

function streamUrlFor(apiBaseUrl: string): string {
  const url = new URL('/v1/stream', apiBaseUrl);
  url.protocol = url.protocol === 'https:' ? 'wss:' : 'ws:';
  return url.href;
}

const LOCAL_API = 'http://localhost:8080';
const LOCAL_RPC: RpcOption = {
  id: 'http://127.0.0.1:8899/',
  label: 'Local validator',
  url: 'http://127.0.0.1:8899/',
};
/** The dev program id the local stack deploys. */
const LOCAL_PROGRAM = 'FDQqHeaCY2iG9kbjkGGJngY2rgend8dW4JjfXmCQytQL';

export function readConfig(env: Env): AppConfig {
  const clusterName = cluster(str(env, 'VITE_CLUSTER'));
  const apiBaseUrl = str(env, 'VITE_API_URL') ?? LOCAL_API;
  const allowlist = parseRpcAllowlist(str(env, 'VITE_RPC_ALLOWLIST'));
  const markets = (str(env, 'VITE_MARKETS') ?? '')
    .split(',')
    .map((m) => parseAddress(m.trim()))
    .filter((m): m is Address => m !== null);
  return {
    apiBaseUrl,
    streamUrl: str(env, 'VITE_STREAM_URL') ?? streamUrlFor(apiBaseUrl),
    rpcAllowlist: allowlist.length > 0 ? allowlist : clusterName === 'localnet' ? [LOCAL_RPC] : [],
    cluster: clusterName,
    programId: parseAddress(
      str(env, 'VITE_PROGRAM_ID') ?? (clusterName === 'localnet' ? LOCAL_PROGRAM : undefined),
    ),
    genesisHash: str(env, 'VITE_GENESIS_HASH') ?? '',
    markets,
    upgradeAuthority: parseAddress(str(env, 'VITE_UPGRADE_AUTHORITY')),
    testedWallets: (str(env, 'VITE_TESTED_WALLETS') ?? '')
      .split(',')
      .map((w) => w.trim())
      .filter((w) => w.length > 0),
  };
}

/**
 * The pins for one market. A market the build does not pin, or a
 * build without a program id, yields null: such a market is never verified
 * and never traded.
 */
export function pinsFor(config: AppConfig, market: Address): AppPins | null {
  if (config.programId === null || !config.markets.includes(market)) return null;
  return {
    programId: config.programId,
    genesisHash: config.genesisHash,
    cluster: config.cluster,
    market,
    upgradeAuthority: config.upgradeAuthority,
  };
}

export function allPins(config: AppConfig): AppPins[] {
  return config.markets.map((m) => pinsFor(config, m)).filter((p): p is AppPins => p !== null);
}
