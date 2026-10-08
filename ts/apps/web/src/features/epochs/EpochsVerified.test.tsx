// The epoch detail against the SDK's fake node, whose data is signed with
// real keys: every check that passes here ran on real bytes.
import { fireEvent, screen, waitFor, within } from '@testing-library/react';
import { afterEach, describe, expect, it } from 'vitest';

import { expectNoSeriousAxeViolations } from '../../components/testing/a11y';
import type { FakeNode } from '../../app/testing/fakeNode';
import { fakeNode, nodeConfig, nodeRuntime, overrideApi } from '../../app/testing/fakeNode';
import type { RenderedApp } from '../../app/testing/renderApp';
import { renderApp, resetAppState } from '../../app/testing/renderApp';
import { revealDue } from './checks';

let app: RenderedApp | null = null;

afterEach(() => {
  app?.unmount();
  app = null;
  resetAppState();
});

function statusOf(list: HTMLElement, label: string): string | null {
  return within(list).getByText(label).closest('li')?.getAttribute('data-status') ?? null;
}

function posted(): FakeNode {
  const node = fakeNode({ receiptQuorum: 1 });
  node.closeEpoch();
  node.commit(1n);
  node.reveal(1n);
  node.post(1n, { fills: [] });
  node.cosign(1n);
  return node;
}

describe('Epoch detail on a verified market', () => {
  it('checks the root on chain, the terms and, on request, the receipt (V-4, V-7, V-8)', async () => {
    const node = posted();
    app = renderApp(`/epochs/${node.market}/1`, {
      config: nodeConfig(node),
      runtime: nodeRuntime(node),
    });
    const root = await screen.findByRole('list', { name: 'Batch root' });
    await waitFor(() => expect(statusOf(root, 'Matches the Batch account on Solana')).toBe('ok'), {
      timeout: 4000,
    });
    expect(statusOf(root, 'Leaves hash to the committed root')).toBe('ok');
    const terms = screen.getByRole('list', { name: 'Terms' });
    await waitFor(() =>
      expect(statusOf(terms, 'Relay-signed announcement and epoch key binding')).toBe('ok'),
    );
    expect(statusOf(terms, 'Terms digest equals the one committed on Solana')).toBe('ok');
    const verify = screen.getByRole('button', { name: 'Verify receipt' }) as HTMLButtonElement;
    await waitFor(() => expect(verify.disabled).toBe(false));
    fireEvent.click(verify);
    const receipt = await screen.findByRole('list', { name: 'Receipt' });
    await waitFor(() =>
      expect(
        statusOf(receipt, 'Receipt signed by a registered executor and posted on chain (V-7)'),
      ).toBe('ok'),
    );
    expect(statusOf(receipt, 'Co-signature quorum met')).toBe('ok');
    await waitFor(() =>
      expect(statusOf(receipt, 'Fills and settlement recomputed from the artifacts (V-8)')).toBe(
        'ok',
      ),
    );
    await expectNoSeriousAxeViolations();
  });

  it('flags terms the batch committed that the relay never announced', async () => {
    const node = fakeNode();
    node.closeEpoch();
    node.commit(1n, { terms: new Uint8Array(32).fill(7) });
    app = renderApp(`/epochs/${node.market}/1`, {
      config: nodeConfig(node),
      runtime: nodeRuntime(node),
    });
    const terms = await screen.findByRole('list', { name: 'Terms' });
    await waitFor(() =>
      expect(statusOf(terms, 'Terms digest equals the one committed on Solana')).toBe('fail'),
    );
  });

  it('offers the manual Reveal only when the reveal is overdue, and never sends it by itself', async () => {
    const node = fakeNode();
    node.closeEpoch();
    node.commit(1n);
    let ahead = 0n;
    app = renderApp(`/epochs/${node.market}/1`, {
      config: nodeConfig(node),
      runtime: nodeRuntime(node, {
        wrapRpc: (rpc) => ({ ...rpc, slot: async () => (await rpc.slot()) + ahead }),
      }),
    });
    await screen.findByRole('list', { name: 'Batch root' });
    expect(screen.queryByText('Reveal overdue')).toBeNull();
    // d = 4 in the fake market: overdue after commit + 2d + 8, expired after commit + d + 400.
    ahead = 20n;
    await screen.findByText('Reveal overdue', undefined, { timeout: 5000 });
    expect(screen.getByText('Connect a wallet to reveal.')).toBeTruthy();
    expect(screen.getByText(/never sent|Nothing is sent unless you start it/)).toBeTruthy();
    ahead = 500n;
    await waitFor(() => expect(screen.queryByText('Reveal overdue')).toBeNull(), { timeout: 5000 });
  });

  it('does not let the node hide the manual Reveal by misreporting the beacon delay', async () => {
    const node = fakeNode();
    node.closeEpoch();
    node.commit(1n);
    let ahead = 0n;
    // The fake market's d is 4. The node claims 64, which would push "overdue" past slot +136.
    const api = overrideApi(node.api, {
      market: async (m) => {
        const detail = await node.api.market(m);
        return { ...detail, timing: { ...detail.timing, beaconDelaySlots: 64 } };
      },
    });
    app = renderApp(`/epochs/${node.market}/1`, {
      config: nodeConfig(node),
      runtime: nodeRuntime(node, {
        api,
        wrapRpc: (rpc) => ({ ...rpc, slot: async () => (await rpc.slot()) + ahead }),
      }),
    });
    await screen.findByRole('list', { name: 'Batch root' });
    await waitFor(
      () =>
        expect(app?.runtime.verification.state.get().markets.get(node.market)?.status).toBe('fail'),
      { timeout: 5000 },
    );
    ahead = 20n;
    await screen.findByText('Reveal overdue', undefined, { timeout: 5000 });
  });
});

describe('revealDue', () => {
  it('uses the verified delay', () => {
    expect(revealDue(116n, 100n, 4n)).toBe(false);
    expect(revealDue(117n, 100n, 4n)).toBe(true);
    expect(revealDue(504n, 100n, 4n)).toBe(true);
    expect(revealDue(505n, 100n, 4n)).toBe(false);
  });

  it('without a verified delay, shows the action from the earliest overdue slot to the latest expiry', () => {
    expect(revealDue(116n, 100n, null)).toBe(false);
    expect(revealDue(117n, 100n, null)).toBe(true);
    expect(revealDue(564n, 100n, null)).toBe(true);
    expect(revealDue(565n, 100n, null)).toBe(false);
  });
});
