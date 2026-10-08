// @timescales/sdk: the public API. Applications import subpaths.
import { z } from 'zod';

z.config({ jitless: true });

export {
  type TimescalesErrorKind,
  type ErrorCode,
  type WalletErrorCode,
  TimescalesError,
} from './errors.js';

// core/encoding
export { Writer, Reader, DecodeError, decodeExact } from './core/encoding/codec.js';
export { hex } from './core/encoding/hex.js';
export { b64 } from './core/encoding/base64.js';

// core/crypto
export { DOMAIN, type DomainName } from './core/crypto/tags.js';
export { H } from './core/crypto/hash.js';
export { verifyStrict } from './core/crypto/verifyStrict.js';
export { sealEnvelope } from './core/crypto/seal.js';
export { edwardsU } from './core/crypto/edwards.js';
export { envelopeDigest } from './core/protocol/envelope.js';

// core/protocol
export {
  type Side,
  type Role,
  type OrderKind,
  type BookId,
  type MarketParams,
  decodeMarketParams,
  encodeMarketParams,
  validateMarketParams,
  paramsDigest,
  bookFor,
} from './core/protocol/params.js';
export { deriveMarketId } from './core/protocol/marketId.js';
export { type PriceBand, band, slot } from './core/protocol/band.js';
export {
  type UnitContext,
  type Rounding,
  tickToPrice,
  priceToTick,
  lotsToBase,
  baseToLots,
  parseDecimal,
} from './core/protocol/units.js';
export { type Order, type Cancel, validateOrder } from './core/protocol/order.js';
export {
  type IntentBody,
  type PrivateIntent,
  intentDigest,
  intentMessage,
  encodePrivateIntent,
  decodePrivateIntent,
} from './core/protocol/intent.js';
export { commitment } from './core/protocol/commitment.js';
export { encodeSubmission, submissionDigest } from './core/protocol/submission.js';
export { type PromiseV2, decodePromiseV2, promiseV2Digest } from './core/protocol/promise.js';
export { type RelayRefusal, decodeRelayRefusal } from './core/protocol/refusal.js';
export { type BatchLeaf, batchRootV2, batchRootV1 } from './core/protocol/leaves.js';
export { type BatchHeader, decodeHeader, headerDigest } from './core/protocol/header.js';
export { epochBinding, termsDigest } from './core/protocol/binding.js';
export {
  type ExecutionOutcome,
  type ExecutionReceipt,
  decodeReceipt,
  receiptDigest,
  outcomeDigest,
} from './core/protocol/receipt.js';
export { cosignDigest } from './core/protocol/cosign.js';
export { type Fill, type ExecutionArtifacts, decodeArtifacts } from './core/protocol/artifacts.js';
export { type AccountDelta, type SettlementBatch, settle } from './core/protocol/settlement.js';
export { merkleRoot, rootFor } from './core/protocol/merkle.js';
export {
  type CommitteeDescription,
  decodeCommittee,
  committeeDigest,
} from './core/protocol/committee.js';
export {
  type EpochKeyAnnouncement,
  type EpochKeyBundle,
  decodeBundle,
  announcementDigest,
} from './core/protocol/bundle.js';
export {
  type ReleasePolicyStatement,
  decodePolicyStatement,
  policyDigest,
} from './core/protocol/policy.js';
export { type EpochAnnouncement, decodeAnnouncement } from './core/protocol/announcement.js';
export {
  type SessionGrant,
  renderSessionMessage,
  parseSessionMessage,
} from './core/protocol/sessionText.js';

// solana account models and helpers
export type {
  MarketAccount,
  PendingChange,
  TraderAccount,
  BatchStatus,
  BatchAccount,
  AbortReason,
  Observed,
} from './solana/accounts.js';
export {
  decodeMarketAccount,
  decodeTraderAccount,
  decodeBatchAccount,
  decodeMint,
  availableFor,
  withdrawStatus,
  closeStatus,
} from './solana/accounts.js';
export { decodeProgramData } from './solana/program.js';
export { marketPda, traderPda, batchPda } from './solana/pdas.js';
export { associatedTokenAddress, createAtaIdempotentIx } from './solana/ata.js';
export { computeUnitLimitIx, computeUnitPriceIx } from './solana/computeBudget.js';
export {
  openTraderIx,
  depositIx,
  requestWithdrawIx,
  cancelWithdrawRequestIx,
  withdrawIx,
  closeTraderIx,
  revealBeaconIx,
} from './solana/instructions.js';
export { type TimescalesRpc, createTimescalesRpc } from './solana/rpc.js';
export {
  type TxResult,
  buildTraderTx,
  checkSignedTx,
  sendAndConfirm,
  confirmSignature,
} from './solana/tx.js';
export { type ProgramFailure, decodeProgramFailure } from './solana/errors.js';

// verify
export type { Verdict } from './verify/verdict.js';
export { type VerifiedMarketContext, type AppPins, verifyMarket } from './verify/market.js';
export { verifyCommittee } from './verify/committee.js';
export { verifyEpochKey } from './verify/epochKey.js';
export { verifyAnnouncement } from './verify/announcement.js';
export { verifyPromise } from './verify/promise.js';
export { type Inclusion, checkInclusion } from './verify/inclusion.js';
export { verifyReceipt } from './verify/receipt.js';
export { verifyArtifacts } from './verify/artifacts.js';
export { type OwnFill, ownFills } from './verify/fills.js';
export { verifyPolicies } from './verify/policy.js';
export { verifyOwnBalance } from './verify/balance.js';
export { verifyProgram } from './verify/program.js';
export { decodePendingChange } from './verify/governance.js';
export type { EvidenceRecord } from './verify/evidence.js';

// api
export type {
  Info,
  Status,
  MarketSummary,
  MarketDetail,
  CurrentEpoch,
  EpochKey,
  EpochSummary,
  EpochDetail,
  Artifacts,
  TapeRow,
  ExecutorRegistration,
  SessionNonce,
  CreateSessionRequest,
  Session,
  SubmitResult,
  SubmitItemResult,
  ParkedItem,
  RetractResult,
} from './api/schemas.js';
export { type Page, type PageReq, TimescalesApi } from './api/client.js';
export { type StreamEvent, TimescalesStream } from './api/stream.js';
export { ServerClock } from './api/clock.js';

// wallet / session
export { type SiwsInput, type TraderWallet, WalletError } from './wallet/port.js';
export { walletFromStandard } from './wallet/standard.js';
export { signIntent, TradingSession } from './wallet/session.js';

// journal
export { type Journal, openJournal } from './journal/journal.js';
export { requestPersistence } from './journal/persist.js';
export { exportJournal, importJournal } from './journal/export.js';

// orders
export type {
  OrderDraft,
  PreparedOrder,
  ParticipationState,
  Participation,
  OrderState,
  OrderRecord,
  OrderEvent,
  OutboxItem,
  SubmitStep,
  ReconcileReport,
} from './orders/model.js';
export { PARTICIPATION_LIFECYCLE } from './orders/participation.js';
export { ORDER_LIFECYCLE, badge, reduce } from './orders/lifecycle.js';
export { lifetimePresets } from './orders/presets.js';
export { OrderService } from './orders/service.js';
