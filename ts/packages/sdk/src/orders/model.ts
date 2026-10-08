import type { Address } from '@solana/kit';
import type { IntentBody } from '../core/protocol/intent.js';
import type { Order } from '../core/protocol/order.js';
import type { BookId, OrderKind, Role, Side } from '../core/protocol/params.js';
import type { Inclusion } from '../verify/inclusion.js';
import type { OwnFill } from '../verify/fills.js';

export interface OrderDraft {
  market: Address;
  side: Side;
  role: Role;
  kind: OrderKind;
  limitTick?: bigint;
  quantityLots: bigint;
  lifetimeEpochs: number;
}

export interface PreparedOrder {
  draft: OrderDraft;
  order: Omit<Order, 'nonce'>;
  book: BookId;
  epochs: { from: bigint; to: bigint; parkedTo: bigint };
  collateral: { base: bigint; quote: bigint; shortfall: boolean };
  feeEstimate: bigint;
  worstNotional: bigint;
  signBudgetMs: number;
  warnings: ('outside_band' | 'undercapitalized' | 'long_rest_linkable' | 'second_prompt_needed')[];
  blockers: ('self_trade' | 'paused' | 'unverified')[];
}

export type ParticipationState =
  | { kind: 'sealed' }
  | { kind: 'parked' }
  | { kind: 'locked' }
  | { kind: 'included' }
  | { kind: 'excluded'; evidenceId: string }
  | { kind: 'clearing'; delayed: boolean }
  | { kind: 'provisional'; have: number; need: number }
  | { kind: 'verified'; filled: bigint }
  | { kind: 'settling'; done: number; total: number }
  | { kind: 'settled'; filled: bigint }
  | { kind: 'voided'; outcomeWasPublic: boolean }
  | { kind: 'not_submitted'; reason: 'quota' | 'batch_full' | 'key_unavailable' | 'invalidated' };

export interface Participation {
  epoch: bigint;
  envelopeDigest: Uint8Array;
  /** Exact submitted bytes (outbox). */
  submission: Uint8Array;
  promise: Uint8Array | null;
  relayAtSubmission: Address;
  state: ParticipationState;
}

export type OrderState =
  | { kind: 'draft' }
  | { kind: 'awaiting_wallet' }
  | { kind: 'wallet_rejected' }
  | { kind: 'unsupported_wallet' }
  | { kind: 'abandoned' }
  | { kind: 'signed_too_late' }
  | { kind: 'submitting' }
  | { kind: 'submit_failed'; code: string; retryable: boolean }
  | { kind: 'working' }
  | { kind: 'paused_needs_app' }
  | { kind: 'reseal_needs_consent'; epoch: bigint }
  | { kind: 'filled' }
  | { kind: 'expired' }
  | { kind: 'cancel_pending'; epoch: bigint }
  | { kind: 'cancelled' }
  | { kind: 'cancel_too_late' }
  | { kind: 'verification_failed'; check: string };

export type OrderEvent = { atMs: number } & (
  | { kind: 'prepared' }
  | { kind: 'wallet_prompted' }
  | { kind: 'wallet_rejected' }
  | { kind: 'wallet_unsupported' }
  | { kind: 'abandoned' }
  | { kind: 'signed'; late: boolean }
  | { kind: 'submitted'; epoch: bigint; result: 'accepted' | 'parked' | 'refused'; code?: string }
  | { kind: 'promise_verified'; epoch: bigint }
  | { kind: 'epoch_locked'; epoch: bigint }
  | { kind: 'inclusion'; epoch: bigint; inclusion: Inclusion['status'] }
  | { kind: 'revealed'; epoch: bigint }
  | { kind: 'receipt'; epoch: bigint; quorumMet: boolean }
  | { kind: 'fills'; epoch: bigint; filled: bigint }
  | { kind: 'settlement'; epoch: bigint; done: number; total: number }
  | { kind: 'settled'; epoch: bigint }
  | { kind: 'aborted'; epoch: bigint; outcomeWasPublic: boolean }
  | { kind: 'governance_applied'; change: string }
  | { kind: 'parked_invalidated'; epochs: bigint[] }
  | { kind: 'expired' }
  | { kind: 'cancel_submitted'; epoch: bigint }
  | { kind: 'cancel_result'; result: 'cancelled' | 'too_late' }
  | { kind: 'verification_failed'; check: string }
);

export interface OrderRecord {
  id: string;
  version: number;
  market: Address;
  body: IntentBody;
  salt: Uint8Array;
  signature: Uint8Array;
  commitment: Uint8Array;
  state: OrderState;
  epochs: Map<bigint, Participation>;
  filled: bigint;
  fills: OwnFill[];
  history: OrderEvent[];
  evidence: string[];
}

export interface OutboxItem {
  orderId: string;
  epoch: bigint;
  submission: Uint8Array;
  createdAtMs: number;
}

export type SubmitStep =
  'validating' | 'awaiting_wallet' | 'sealing' | 'submitting' | 'verifying_promise' | 'done';

export interface ReconcileReport {
  attached: number;
  foreignFills: number;
  outboxResent: number;
  inconclusive: number;
}
