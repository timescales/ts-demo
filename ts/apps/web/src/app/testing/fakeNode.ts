/* eslint-disable @typescript-eslint/no-restricted-imports --
   Test-only module: the SDK's fake node, relay, committee and chain sign
   everything with real keys, so the app's  checks run unmodified. It is
   imported by *.test.tsx files only and never reaches a build (the bundle
   check greps dist/ for test markers). */
import type { FakeNode, FakeNodeOptions } from '@timescales/sdk/testing';
import { createFakeNode, createTestWallet } from '@timescales/sdk/testing';
import type { TestWallet, TestWalletOptions } from '@timescales/sdk/testing';
import type { TimescalesRpc } from '@timescales/sdk/solana';

import type { AppConfig } from '../config';
import type { RuntimeOptions } from '../../state/runtime';
import { testConfig } from './renderApp';

export type { FakeNode, TestWallet };

export function fakeNode(o: FakeNodeOptions = {}): FakeNode {
  return createFakeNode({ cluster: 'localnet', scheme: 'feldman', ...o });
}

export function testWallet(o: TestWalletOptions): TestWallet {
  return createTestWallet(o);
}

/** Config pinned to the fake node's program, cluster and market. */
export function nodeConfig(node: FakeNode, patch: Partial<AppConfig> = {}): AppConfig {
  return testConfig({
    apiBaseUrl: 'http://node.timescales.test',
    streamUrl: node.streamUrl,
    cluster: node.pins.cluster,
    programId: node.pins.programId,
    genesisHash: node.pins.genesisHash,
    markets: [node.market],
    upgradeAuthority: node.pins.upgradeAuthority,
    ...patch,
  });
}

/** Runtime options that put the app on the fake node, with an optional RPC wrapper. */
export function nodeRuntime(
  node: FakeNode,
  o: { wrapRpc?: (rpc: TimescalesRpc) => TimescalesRpc } & Omit<RuntimeOptions, 'rpc'> = {},
): RuntimeOptions {
  const { wrapRpc: wrap, ...rest } = o;
  const rpc = wrap ? wrap(node.rpc) : node.rpc;
  return { api: node.api, rpc: () => rpc, WebSocketImpl: node.WebSocket, ...rest };
}

/** A 32-byte test seed from one byte. */
export function seed(n: number): Uint8Array {
  return new Uint8Array(32).fill(n);
}

/** The fake node's session domain: grants are domain-checked. */
export const NODE_ORIGIN = 'https://app.timescales.test';

/** Puts the test page on an origin (happy-dom). Returns a restore function. */
export function setPageUrl(url: string): () => void {
  const dom = (window as unknown as { happyDOM?: { setURL(u: string): void } }).happyDOM;
  const before = window.location.href;
  dom?.setURL(url);
  return () => dom?.setURL(before);
}

/**
 * The node's API client with some methods replaced. The client keeps its
 * state per instance, so every method stays bound to the original.
 */
export function overrideApi<T extends object>(api: T, overrides: Partial<T>): T {
  const proto = Object.getPrototypeOf(api) as Record<string, unknown>;
  const out: Record<string, unknown> = Object.create(proto) as Record<string, unknown>;
  for (const name of Object.getOwnPropertyNames(proto)) {
    const v = proto[name];
    if (name !== 'constructor' && typeof v === 'function') out[name] = v.bind(api);
  }
  return Object.assign(out, overrides) as T;
}
