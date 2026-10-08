import type { Address } from '@solana/kit';
import type { MarketDetail } from '../api/schemas.js';
import { equal } from '../core/encoding/bytes.js';
import { hex } from '../core/encoding/hex.js';
import type { CommitteeDescription } from '../core/protocol/committee.js';
import { deriveMarketId } from '../core/protocol/marketId.js';
import { encodeMarketParams, paramsDigest, validateMarketParams } from '../core/protocol/params.js';
import type { ReleasePolicyStatement } from '../core/protocol/policy.js';
import type { UnitContext } from '../core/protocol/units.js';
import {
  GOVERNANCE_KINDS,
  decodeMint,
  decodePending,
  type MarketAccount,
  type Observed,
  type PendingChange,
} from '../solana/accounts.js';
import { findProgramAddressSync, marketSeeds } from '../solana/pdas.js';
import {
  CheckFailed,
  CheckInconclusive,
  check,
  must,
  mustBeReady,
  type Verdict,
} from './verdict.js';

/** Values the app pins at build time. Nothing the node says can override them. */
export interface AppPins {
  programId: Address;
  genesisHash: string;
  cluster: 'localnet' | 'devnet' | 'mainnet-beta';
  market: Address;
  upgradeAuthority: Address | null;
}

/** Everything verified about a market before the client seals to it. */
export interface VerifiedMarketContext {
  market: MarketAccount;
  detail: MarketDetail;
  committee: CommitteeDescription;
  units: UnitContext;
  policies: ReleasePolicyStatement[];
  enclaveLabel: 'intel_tdx_vouched' | 'simulated' | 'operator_reported';
  program: { upgradeAuthority: Address | null; lastDeploySlot: bigint };
  pins: AppPins;
  verifiedAtSlot: bigint;
}

function sameOptionalBytes(a: Uint8Array | null, b: Uint8Array | null): boolean {
  return a === null || b === null ? a === b : equal(a, b);
}

/** The payload of a pending change, as a comparable string. */
function payloadKey(p: PendingChange): string {
  switch (p.kind) {
    case 'set_relay':
      return `relay ${p.relay}`;
    case 'set_executors':
      return `executors ${p.executors.join(',')} quorum ${p.quorum}`;
    case 'set_committee_digest':
      return `committee ${hex.encode(p.digest)}`;
    case 'set_admin':
      return `admin ${p.admin}`;
    case 'set_timings':
      return `timings ${p.beaconDelaySlots} ${p.execTimeoutSlots} ${p.settleTimeoutSlots}`;
    case 'set_timelock':
      return `timelock ${p.slots}`;
  }
}

/** Pending changes compared by kind, eta and payload. `due` depends on the slot each side read at. */
function samePending(node: MarketDetail['pendingChange'], chain: MarketAccount): boolean {
  const c = chain.pending;
  if (node === null || c === null) return node === null && c === null;
  if (node.kind !== c.kind || node.etaSlot !== c.etaSlot) return false;
  const kind = GOVERNANCE_KINDS.indexOf(c.kind) + 1;
  return payloadKey(decodePending(kind, node.etaSlot, node.payloadBytes, chain)) === payloadKey(c);
}

/**
 * V-1. `chain` must come from the client's own RPC read at
 * `minContextSlot = node.chain.contextSlot`. Immutable fields must equal the
 * node's. Slow fields must equal at the same slot and make the check
 * inconclusive otherwise. Volatile fields must be equal at the same slot and
 * may only move forward later. The address is the market PDA of the pinned
 * program, which (with the RPC's owner check) pins the owning program. Mints
 * are read raw: their decimals must match the node's, and their mint and
 * freeze authorities, which the issuer can change, are slow fields, so
 * `node.mintAuthorities` holds verified values. A freeze authority is
 * reported as a warning.
 */
export function verifyMarket(
  node: MarketDetail,
  chain: Observed<MarketAccount>,
  mints: { base: Uint8Array; quote: Uint8Array },
  pins: AppPins,
): Verdict<{ freezeWarnings: ('base' | 'quote')[] }> {
  return check('V-1 market', () => {
    const m = chain.value;
    must(m.address === pins.market, 'the market account is not the pinned market');
    must(node.market === pins.market, 'the node describes another market');
    must(
      deriveMarketId(pins.programId, m.creator, m.salt) === m.marketId,
      'the market id is not derived from the program, creator and salt',
    );
    must(
      findProgramAddressSync(marketSeeds(m.marketId), pins.programId)[0] === m.address,
      "the market address is not the pinned program's address for its id",
    );
    must(equal(paramsDigest(m.params), m.paramsDigest), 'the params digest does not match');
    try {
      validateMarketParams(m.params, { onchain: true });
    } catch (e) {
      throw new CheckFailed(`the market params are invalid: ${(e as Error).message}`);
    }
    must(m.params.market === m.marketId, 'the params name another market id');

    // Immutable: must equal the node's view at any slot.
    must(node.marketId === m.marketId, 'the node reports another market id');
    must(equal(node.marketIdSalt, m.salt), 'the node reports another salt');
    must(node.creator === m.creator, 'the node reports another creator');
    must(
      node.baseMint === m.baseMint &&
        node.quoteMint === m.quoteMint &&
        node.baseVault === m.baseVault &&
        node.quoteVault === m.quoteVault,
      'the node reports other mints or vaults',
    );
    const params = encodeMarketParams(m.params);
    must(
      equal(node.paramsBytes, params) && equal(encodeMarketParams(node.params), params),
      'the node reports other params',
    );
    must(equal(node.paramsDigest, m.paramsDigest), 'the node reports another params digest');

    const base = decodeMint(mints.base);
    const quote = decodeMint(mints.quote);
    must(
      base.decimals === node.baseDecimals && quote.decimals === node.quoteDecimals,
      'the node reports other token decimals',
    );

    const nodeSlot = node.chain.contextSlot;
    mustBeReady(chain.contextSlot >= nodeSlot, 'the RPC has not reached the slot the node read');
    const sameSlot = chain.contextSlot === nodeSlot;
    const slow = (cond: boolean, what: string): void => {
      if (cond) return;
      if (sameSlot) throw new CheckFailed(`the node and the RPC disagree about ${what}`);
      throw new CheckInconclusive(`${what} changed between the node's and the RPC's reads`);
    };
    slow(node.admin === m.admin, 'the admin');
    slow(node.relay === m.relay, 'the relay');
    const executors = m.executors.filter((e): e is Address => e !== null);
    slow(
      executors.length === node.executors.length &&
        executors.every((e, i) => e === node.executors[i]),
      'the executors',
    );
    slow(node.receiptQuorum === m.receiptQuorum, 'the receipt quorum');
    slow(equal(node.committee.digest, m.committeeDigest), 'the committee digest');
    slow(
      sameOptionalBytes(node.committee.prevDigest, m.prevCommitteeDigest),
      'the previous committee digest',
    );
    slow(
      node.timing.beaconDelaySlots === m.beaconDelaySlots &&
        node.timing.execTimeoutSlots === m.execTimeoutSlots &&
        node.timing.settleTimeoutSlots === m.settleTimeoutSlots &&
        node.timing.timelockSlots === m.timelockSlots,
      'the timings',
    );
    slow(samePending(node.pendingChange, m), 'the pending governance change');
    slow(node.halted === m.halted, 'the halt flag');
    const sameAuthorities = (
      n: MarketDetail['mintAuthorities']['base'],
      mint: ReturnType<typeof decodeMint>,
    ): boolean => n.mint === mint.mintAuthority && n.freeze === mint.freezeAuthority;
    slow(
      sameAuthorities(node.mintAuthorities.base, base) &&
        sameAuthorities(node.mintAuthorities.quote, quote),
      'the mint authorities',
    );

    const c = node.chain;
    if (sameSlot) {
      must(
        c.lastCommitted === m.lastCommitted &&
          c.lastSettled === m.lastSettled &&
          equal(c.stateRoot, m.stateRoot) &&
          equal(c.prevReceipt, m.prevReceipt),
        'the node and the RPC disagree about the batch counters at the same slot',
      );
    } else {
      must(
        m.lastCommitted >= c.lastCommitted && m.lastSettled >= c.lastSettled,
        'the batch counters moved backwards between the node and the RPC',
      );
      if (m.lastSettled === c.lastSettled) {
        must(
          equal(c.stateRoot, m.stateRoot) && equal(c.prevReceipt, m.prevReceipt),
          'the state root or receipt chain changed without a settled batch',
        );
      }
    }

    const freezeWarnings: ('base' | 'quote')[] = [];
    if (base.freezeAuthority !== null) freezeWarnings.push('base');
    if (quote.freezeAuthority !== null) freezeWarnings.push('quote');
    return { freezeWarnings };
  });
}
