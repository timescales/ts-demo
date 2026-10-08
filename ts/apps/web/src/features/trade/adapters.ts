// Builds the trader ports from SDK services. The app shell calls these when
// a wallet connects and when a trading session opens.
import type { EvidenceRecord } from '@timescales/sdk/verify';
import type { Journal } from '@timescales/sdk/journal';
import { exportJournal, importJournal } from '@timescales/sdk/journal';
import type { TimescalesRpc } from '@timescales/sdk/solana';
import { traderPda } from '@timescales/sdk/solana';
import type { TraderWallet } from '@timescales/sdk/wallet';

import type { Address, JournalPort, OrdersPort, TraderPort } from './services';

/**
 * The journals `openJournal` returns also list saved evidence, but the
 * public `Journal` type does not declare it yet (see the package's request
 * file). Without it the Evidence tab shows an empty list.
 */
function listEvidence(j: Journal): Promise<EvidenceRecord[]> {
  const f = (j as Journal & { listEvidence?: () => Promise<EvidenceRecord[]> }).listEvidence;
  return typeof f === 'function' ? f.call(j) : Promise.resolve([]);
}

export function journalPort(j: Journal): JournalPort {
  return {
    get available() {
      return j.available;
    },
    get persisted() {
      return j.persisted;
    },
    listEvidence: () => listEvidence(j),
    exportBackup: (passphrase) => exportJournal(j, passphrase),
    importBackup: (bundle, passphrase) => importJournal(bundle, passphrase, j),
  };
}

export function traderPort(a: {
  wallet: TraderWallet;
  rpc: TimescalesRpc;
  /** The pinned settlement program (AppPins.programId). */
  program: Address;
  /** Null until a trading session is open. */
  orders: OrdersPort | null;
  journal: Journal | null;
}): TraderPort {
  return {
    wallet: { address: a.wallet.address, name: a.wallet.name },
    orders: a.orders,
    journal: a.journal === null ? null : journalPort(a.journal),
    async account(market) {
      const [address] = await traderPda(a.program, market, a.wallet.address);
      return a.rpc.trader(address);
    },
  };
}
