// @timescales/sdk/core: encoding, crypto and protocol formats. DOM-free.
import { z } from 'zod';

z.config({ jitless: true });

export {
  utf8,
  fromUtf8,
  concat,
  equal,
  compare,
  isZero,
  u64le,
  u32le,
  readU64le,
  bytesToBigIntLE,
  bigIntToBytesLE,
  U64_MAX,
  I64_MAX,
  I64_MIN,
} from './encoding/bytes.js';
export {
  Writer,
  Reader,
  DecodeError,
  decodeExact,
  type DecodeErrorKind,
} from './encoding/codec.js';
export { hex } from './encoding/hex.js';
export { b64 } from './encoding/base64.js';
export { b58 } from './encoding/base58.js';

export { DOMAIN, type DomainName } from './crypto/tags.js';
export { H, hashTagged } from './crypto/hash.js';
export { verifyStrict, ed25519Sign, ed25519PublicKey } from './crypto/ed25519.js';
export { L as ED25519_ORDER } from './crypto/verifyStrict.js';
export { x25519PublicKey, x25519Shared } from './crypto/x25519.js';
export { sealEnvelope, openEnvelope } from './crypto/seal.js';
export { edwardsU, decompress, isPrimeOrder, montgomeryU } from './crypto/edwards.js';
export { randomBytes, randomU64 } from './crypto/random.js';

export {
  type Side,
  type Role,
  type OrderKind,
  type BookId,
  type MarketParams,
  type ParamsErrorReason,
  SIDE,
  ROLE,
  ORDER_KIND,
  BOOK,
  MARKET_PARAMS_LEN,
  MAX_BAND_TICKS,
  MAX_BATCH_ENVELOPES,
  MAX_SETTLEMENT_DELTAS,
  ParamsError,
  readMarketParams,
  writeMarketParams,
  decodeMarketParams,
  encodeMarketParams,
  maxOrderLots,
  validateMarketParams,
  paramsDigest,
  bookFor,
} from './protocol/params.js';
export {
  type PriceBand,
  type BandErrorReason,
  BandError,
  band,
  bandTicks,
  slot,
  feeCeilPerUnit,
  feeOn,
  readBand,
  writeBand,
  encodeBand,
} from './protocol/band.js';
export {
  type UnitContext,
  type Rounding,
  type UnitsErrorReason,
  UnitsError,
  tickToPrice,
  priceToTick,
  lotsToBase,
  baseToLots,
  parseDecimal,
} from './protocol/units.js';
export {
  type Order,
  type Cancel,
  type OrderErrorReason,
  ORDER_LEN,
  CANCEL_LEN,
  OrderError,
  UnsupportedScheme,
  readOrder,
  writeOrder,
  readCancel,
  writeCancel,
  encodeOrder,
  encodeCancel,
  effectiveLimit,
  validateOrder,
} from './protocol/order.js';
export {
  type IntentBody,
  type PrivateIntent,
  PLAINTEXT_LEN,
  readIntentBody,
  writeIntentBody,
  encodeIntentBody,
  readPrivateIntent,
  encodePrivateIntent,
  decodePrivateIntent,
  intentTrader,
  intentDigest,
  intentMessage,
} from './protocol/intent.js';
export { commitment } from './protocol/commitment.js';
export {
  type SealedEnvelope,
  ENVELOPE_LEN,
  ENVELOPE_VERSION,
  ENVELOPE_AAD_LEN,
  readEnvelope,
  writeEnvelope,
  decodeEnvelope,
  encodeEnvelope,
  envelopeDigest,
} from './protocol/envelope.js';
export {
  SUBMISSION_LEN,
  submissionDigest,
  encodeSubmission,
  decodeSubmission,
} from './protocol/submission.js';
export {
  type PromiseV2,
  type PromiseV1,
  PROMISE_V2_LEN,
  PROMISE_V1_LEN,
  decodePromiseV2,
  encodePromiseV2,
  promiseV2Digest,
  decodePromiseV1,
  encodePromiseV1,
  promiseV1Digest,
} from './protocol/promise.js';
export {
  type RelayRefusal,
  RELAY_REFUSAL_LEN,
  decodeRelayRefusal,
  encodeRelayRefusal,
  relayRefusalDigest,
} from './protocol/refusal.js';
export {
  type BatchHeader,
  HEADER_LEN,
  decodeHeader,
  encodeHeader,
  headerDigest,
  batchSeed,
  batchSeedV2,
  epochSeed,
  priorityKey,
} from './protocol/header.js';
export {
  type BatchLeaf,
  BATCH_LEAF_LEN,
  encodeLeaf,
  batchRootV2,
  batchRootV1,
  decodeLeaves,
  encodeLeaves,
} from './protocol/leaves.js';
export {
  type InclusionProof,
  MAX_PROOF_PATH,
  leafHash,
  nodeHash,
  emptyRoot,
  rootOfLeafHashes,
  merkleRoot,
  auditPath,
  rootFor,
  encodeInclusionProof,
  decodeInclusionProof,
} from './protocol/merkle.js';
export {
  type ClearingPrice,
  type ExecutionOutcome,
  type ExecutionReceipt,
  type Backend,
  RECEIPT_VERSION,
  MAX_CLEARING,
  readBook,
  readOutcome,
  writeOutcome,
  encodeOutcome,
  decodeReceipt,
  encodeReceipt,
  receiptDigest,
  outcomeDigest,
} from './protocol/receipt.js';
export {
  type Fill,
  type ExecutionArtifacts,
  FILL_LEN,
  readFill,
  writeFill,
  encodeFill,
  decodeArtifacts,
  encodeArtifacts,
  fillsRoot,
  cancelledRoot,
} from './protocol/artifacts.js';
export {
  type AccountDelta,
  type SettlementBatch,
  type SettlementErrorReason,
  ACCOUNT_DELTA_LEN,
  SettlementError,
  encodeAccountDelta,
  readSettlementBatch,
  writeSettlementBatch,
  decodeSettlementBatch,
  encodeSettlementBatch,
  settlementRoot,
  checkConservation,
  settle,
} from './protocol/settlement.js';
export {
  type StateEntry,
  type BalanceEntry,
  STATE_ENTRY_LEN,
  BALANCE_ENTRY_LEN,
  encodeStateEntry,
  decodeStateTable,
  stateRoot,
  encodeBalanceEntry,
  decodeBalanceSheet,
  encodeBalanceSheet,
  balancesRoot,
  balancesDigest,
} from './protocol/state.js';
export {
  type CommitteeDescription,
  COMMITTEE_VERSION,
  MAX_COMMITTEE,
  CommitteeError,
  decodeCommittee,
  encodeCommittee,
  committeeDigest,
  validateCommittee,
} from './protocol/committee.js';
export {
  type EpochKeyAnnouncement,
  type EpochKeyBundle,
  ANNOUNCEMENT_VERSION,
  readKeyAnnouncement,
  writeKeyAnnouncement,
  decodeKeyAnnouncement,
  encodeKeyAnnouncement,
  announcementDigest,
  ackDigest,
  decodeBundle,
  encodeBundle,
} from './protocol/bundle.js';
export {
  type ReleasePolicyStatement,
  POLICY_VERSION,
  POLICY_LEN,
  decodePolicyStatement,
  encodePolicyStatement,
  policyDigest,
} from './protocol/policy.js';
export {
  type EpochAnnouncement,
  EPOCH_ANNOUNCEMENT_VERSION,
  EPOCH_ANNOUNCEMENT_LEN,
  decodeAnnouncement,
  encodeAnnouncement,
  epochAnnouncementDigest,
} from './protocol/announcement.js';
export { epochBinding, termsDigest } from './protocol/binding.js';
export { cosignDigest } from './protocol/cosign.js';
export { beaconV2, slotHashesEntry, MAX_SLOT_HASHES } from './protocol/beacon.js';
export { deriveMarketId } from './protocol/marketId.js';
export {
  type SessionGrant,
  SESSION_STATEMENT,
  MAX_SESSION_TEXT_BYTES,
  SessionTextError,
  renderSessionMessage,
  parseSessionMessage,
} from './protocol/sessionText.js';
