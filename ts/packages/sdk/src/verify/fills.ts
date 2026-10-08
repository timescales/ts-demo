import { equal } from '../core/encoding/bytes.js';
import { encodeFill, type ExecutionArtifacts, type Fill } from '../core/protocol/artifacts.js';
import { feeOn } from '../core/protocol/band.js';
import { auditPath, leafHash, rootFor } from '../core/protocol/merkle.js';
import type { Order } from '../core/protocol/order.js';
import {
  bookFor,
  type BookId,
  type MarketParams,
  type Role,
  type Side,
} from '../core/protocol/params.js';
import type { ExecutionReceipt } from '../core/protocol/receipt.js';
import { encodeAccountDelta } from '../core/protocol/settlement.js';
import { check, must, type Verdict } from './verdict.js';

export interface OwnFill {
  commitment: Uint8Array;
  book: BookId;
  side: Side;
  role: Role;
  quantity: bigint;
  tick: bigint;
  feeQuote: bigint;
}

/**
 * One wallet's net change from its fills, as `settle` computes it before
 * netting across wallets: per fill `notional = q * tick * tick_size`, the fee
 * by role, buyers receive base and pay `notional + fee`, sellers the reverse.
 */
function netDelta(params: MarketParams, fills: Fill[]): { base: bigint; quote: bigint } {
  let base = 0n;
  let quote = 0n;
  for (const f of fills) {
    const notional = f.quantity * f.tick * params.tickSize;
    const fee = feeOn(f.role === 0 ? params.makerFeeBps : params.takerFeeBps, notional);
    const lots = f.quantity * params.baseLotSize;
    if (f.side === 0) {
      base += lots;
      quote -= notional + fee;
    } else {
      base -= lots;
      quote += notional - fee;
    }
  }
  return { base, quote };
}

function inTree(data: Uint8Array[], index: number, size: number, root: Uint8Array): boolean {
  const r = rootFor(BigInt(index), BigInt(size), auditPath(data, index), leafHash(data[index]!));
  return r !== null && equal(r, root);
}

/**
 * V-9, over artifacts that passed V-8: every fill of an own commitment is in
 * the fills tree (`tree_size = fill_count`), trades at the clearing tick of
 * the entry whose `book` equals the fill's book, matches the order's trader,
 * side, role and derived book, respects a limit order's limit, and keeps the
 * cumulative quantity within the order. The own delta is the sum of the own
 * fills (fee by role). The trader's settlement leaf, which nets every fill of
 * the wallet in the batch, must be the one these fills imply and sit in the
 * settlement tree. A commitment with no fill was not filled.
 */
export function ownFills(
  a: ExecutionArtifacts,
  receipt: ExecutionReceipt,
  mine: { commitment: Uint8Array; order: Order; filledBefore: bigint }[],
  params: MarketParams,
): Verdict<{ fills: OwnFill[]; delta: { base: bigint; quote: bigint } }> {
  return check('V-9 own fills', () => {
    const o = receipt.outcome;
    const encoded = a.fills.map(encodeFill);
    const fills: OwnFill[] = [];
    const traders: Uint8Array[] = [];
    let base = 0n;
    let quote = 0n;
    for (const own of mine) {
      const order = own.order;
      if (!traders.some((t) => equal(t, order.trader))) traders.push(order.trader);
      let quantity = 0n;
      a.fills.forEach((f, i) => {
        if (!equal(f.commitment, own.commitment)) return;
        must(inTree(encoded, i, o.fillCount, o.fillsRoot), 'an own fill is not in the fills tree');
        const clearing = o.clearing.find((c) => c.book === f.book);
        must(
          clearing !== undefined && clearing.tick === f.tick,
          "a fill is not at its book's clearing tick",
        );
        must(equal(f.trader, order.trader), 'a fill of an own order names another trader');
        must(
          f.side === order.side && f.role === order.role,
          'a fill has another side or role than the order',
        );
        must(
          f.book === bookFor(params.flow, order.side, order.role),
          'a fill is in another book than the order',
        );
        must(
          order.kind === 1 || (order.side === 0 ? f.tick <= order.limit : f.tick >= order.limit),
          'a fill is beyond the order limit',
        );
        quantity += f.quantity;
        const notional = f.quantity * f.tick * params.tickSize;
        const fee = feeOn(f.role === 0 ? params.makerFeeBps : params.takerFeeBps, notional);
        fills.push({
          commitment: f.commitment,
          book: f.book,
          side: f.side,
          role: f.role,
          quantity: f.quantity,
          tick: f.tick,
          feeQuote: fee,
        });
        const lots = f.quantity * params.baseLotSize;
        if (f.side === 0) {
          base += lots;
          quote -= notional + fee;
        } else {
          base -= lots;
          quote += notional - fee;
        }
      });
      must(own.filledBefore + quantity <= order.quantity, 'an order filled beyond its quantity');
    }
    const deltas = a.settlement.deltas.map(encodeAccountDelta);
    for (const trader of traders) {
      const net = netDelta(
        params,
        a.fills.filter((f) => equal(f.trader, trader)),
      );
      const index = a.settlement.deltas.findIndex((d) => equal(d.trader, trader));
      if (net.base === 0n && net.quote === 0n) {
        must(index < 0, 'the settlement moves a wallet whose fills net to zero');
        continue;
      }
      must(index >= 0, "the wallet's settlement leaf is missing");
      must(
        equal(deltas[index]!, encodeAccountDelta({ trader, base: net.base, quote: net.quote })),
        "the wallet's settlement leaf is not the one its fills imply",
      );
      must(
        inTree(deltas, index, o.settlementCount, o.settlementRoot),
        "the wallet's settlement leaf is not in the settlement tree",
      );
    }
    return { fills, delta: { base, quote } };
  });
}
