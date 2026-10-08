// Decoded domain types of the public API. Raw DTOs (snake_case, string
// u64, hex and base64) stay inside api/. These are what every public method
// returns. Conventions: U64/I64 -> bigint. Hex* -> Uint8Array. B58 account
// keys -> Address. `x_b64` -> `xBytes: Uint8Array`. Enums gain 'unknown' for
// values a newer node may send.
import type { Address } from '@solana/kit';
import { z } from 'zod';
import { b58 } from '../core/encoding/base58.js';
import { b64 } from '../core/encoding/base64.js';
import { I64_MAX, I64_MIN, U64_MAX } from '../core/encoding/bytes.js';
import { hex } from '../core/encoding/hex.js';
import type { PriceBand } from '../core/protocol/band.js';
import { decodeMarketParams, type BookId, type MarketParams } from '../core/protocol/params.js';
import type { ErrorCode } from '../errors.js';
import type { AbortReason } from '../solana/accounts.js';

export type PublicPhase =
  | 'scheduled'
  | 'open'
  | 'closed'
  | 'committed'
  | 'revealed'
  | 'executing'
  | 'posted'
  | 'settled'
  | 'aborting'
  | 'aborted'
  | 'unknown';

export type PauseReason =
  | 'pipeline_backlog'
  | 'epoch_key_unavailable'
  | 'halted'
  | 'operator'
  | 'low_relay_balance'
  | 'recovering'
  | 'fenced'
  | 'draining'
  | 'governance_due'
  | 'unknown';

export type MarketState = 'running' | 'paused' | 'draining' | 'fenced' | 'recovering' | 'unknown';

export interface Clearing {
  book: BookId;
  tick: bigint;
  volume: bigint;
}

/** Operator-reported trust facts. The SDK upgrades `enclave` only through V-14. */
export interface Trust {
  enclave: 'simulated' | 'intel_tdx' | 'unknown';
  quoteGeneration: 'simulated' | 'configfs_tsm_untested_on_hardware' | 'unknown';
  quoteVerification: 'simulated_vendor' | 'intel_dcap' | 'unknown';
  keyGeneration: 'trusted_dealer_feldman' | 'unknown';
  dkg: false;
  mpc: 'disabled' | 'unknown';
  referencePrice: 'fixed' | 'last_clearing' | 'operator' | 'modelled_tlsnotary' | 'unknown';
  receiptQuorum: number;
  registeredExecutors: number;
  notes: string[];
}

export interface Info {
  apiVersion: string;
  protocolVersion: 1;
  headerVersion: 2;
  nodeVersion: string;
  gitSha: string;
  profile: 'local' | 'devnet' | 'production' | 'unknown';
  cluster: 'localnet' | 'devnet' | 'mainnet-beta' | 'unknown';
  genesisHash: string;
  programId: Address;
  serverTimeMs: number;
  markets: Address[];
  trust: Trust;
  limits: { submitMaxBodyBytes: number; sessionMaxTtlS: number };
}

export interface Status {
  status: 'ok' | 'degraded' | 'down' | 'recovering' | 'unknown';
  serverTimeMs: number;
  components: {
    name: string;
    status: 'ok' | 'degraded' | 'down' | 'unknown';
    detail?: string;
    sinceMs: number;
  }[];
  markets: {
    market: Address;
    state: MarketState;
    intake: 'open' | 'paused' | 'unknown';
    pauseReason?: PauseReason;
    currentEpoch: bigint | null;
    lastCommitted: bigint;
    lastSettled: bigint;
    settlementLag: number;
    keysReadyAhead: number;
  }[];
  notice?: { level: 'info' | 'warning' | 'critical' | 'unknown'; message: string; sinceMs: number };
}

export interface MarketSummary {
  market: Address;
  name: string;
  baseSymbol: string;
  quoteSymbol: string;
  state: MarketState;
  halted: boolean;
  lastClearing: Clearing[] | null;
}

export type GovernanceChangeKind =
  | 'set_relay'
  | 'set_executors'
  | 'set_committee_digest'
  | 'set_admin'
  | 'set_timings'
  | 'set_timelock'
  | 'unknown';

export interface MarketDetail extends MarketSummary {
  marketId: bigint;
  creator: Address;
  admin: Address;
  params: MarketParams;
  paramsBytes: Uint8Array;
  paramsDigest: Uint8Array;
  baseMint: Address;
  quoteMint: Address;
  baseVault: Address;
  quoteVault: Address;
  baseDecimals: number;
  quoteDecimals: number;
  relay: Address;
  executors: Address[];
  receiptQuorum: number;
  committee: {
    digest: Uint8Array;
    descriptionBytes: Uint8Array;
    threshold: number;
    members: { index: number; identity: Uint8Array; transport: Uint8Array }[];
    prevDigest: Uint8Array | null;
    prevDescriptionBytes: Uint8Array | null;
    policiesBytes: Uint8Array[];
  };
  timing: {
    epochIntervalMs: number;
    beaconDelaySlots: number;
    execTimeoutSlots: bigint;
    settleTimeoutSlots: bigint;
    timelockSlots: bigint;
    maxParkAheadEpochs: number;
  };
  relayPolicy: {
    padding:
      { kind: 'power_of_two'; min: number } | { kind: 'fixed'; n: number } | { kind: 'unknown' };
    ack: 'immediate' | 'unknown';
    maxEnvelopesPerWalletPerEpoch: number;
    maxParkedPerWallet: number;
    minAvailableValueQuote: bigint;
    minValuePerEnvelopeQuote: bigint;
    requireTraderAccount: boolean;
    idlePolicy: 'commit' | 'extend' | 'unknown';
  };
  marketIdSalt: Uint8Array;
  sessionDomains: string[];
  mintAuthorities: {
    base: { mint: Address | null; freeze: Address | null };
    quote: { mint: Address | null; freeze: Address | null };
  };
  books: { book: BookId; label: string }[];
  pendingChange: null | {
    kind: GovernanceChangeKind;
    etaSlot: bigint;
    payloadBytes: Uint8Array;
    due: boolean;
  };
  program: { upgradeAuthority: Address | null; lastDeploySlot: bigint };
  chain: {
    lastCommitted: bigint;
    lastSettled: bigint;
    stateRoot: Uint8Array;
    prevReceipt: Uint8Array;
    contextSlot: bigint;
  };
}

export interface EpochKey {
  epoch: bigint;
  epochPk: Uint8Array;
  committeeDigest: Uint8Array;
  bundleBytes: Uint8Array;
}

export interface CurrentEpoch {
  market: Address;
  serverTimeMs: number;
  intake: 'open' | 'paused' | 'unknown';
  pauseReason?: PauseReason;
  open: null | {
    epoch: bigint;
    opensAtMs: number;
    cutoffMs: number;
    band: PriceBand;
    binding: Uint8Array;
    termsDigest: Uint8Array;
    priceCommitment: {
      digest: Uint8Array;
      reference: bigint;
      source: Trust['referencePrice'];
      observations: { source: number; tick: bigint; time: bigint }[];
      commitmentBytes: Uint8Array;
    };
    announcementBytes: Uint8Array;
    key: EpochKey;
    realSlotsLeft: 'available' | 'low' | 'full' | 'unknown';
  };
  parkWindow: EpochKey[];
  previous: null | { epoch: bigint; phase: PublicPhase };
  inflight: null | { epoch: bigint; phase: PublicPhase };
  contextSlot: bigint;
}

export interface EpochSummary {
  market: Address;
  epoch: bigint;
  phase: PublicPhase;
  opensAtMs: number;
  cutoffMs: number;
  envelopeCount: number | null;
  clearing: Clearing[] | null;
  fillCount: number | null;
  terminalAtMs: number | null;
  abortReason: AbortReason | null;
  teePlatform: Trust['enclave'] | null;
}

export type EpochTxOp =
  | 'commit'
  | 'reveal'
  | 'post'
  | 'cosign'
  | 'verify'
  | 'finalize'
  | 'apply'
  | 'close'
  | 'abort'
  | 'reclaim'
  | 'unknown';

export interface EpochDetail extends EpochSummary {
  band: PriceBand;
  termsDigest: Uint8Array;
  announcementBytes: Uint8Array;
  key: EpochKey;
  batch: null | {
    address: Address;
    status: string;
    root: Uint8Array;
    count: number;
    termsDigest: Uint8Array;
    commitSlot: bigint;
    commitSignature: string;
    beacon: Uint8Array | null;
    beaconSlots: [bigint, bigint] | null;
    revealSlot: bigint | null;
    headerDigest: Uint8Array | null;
    receiptDigest: Uint8Array | null;
    outcomeDigest: Uint8Array | null;
    cosigners: Address[];
    quorum: { have: number; need: number };
    settlementCount: number | null;
    fees: bigint | null;
    contextSlot: bigint;
  };
  artifactsPublic: boolean;
  headerBytes: Uint8Array | null;
  receiptBytes: Uint8Array | null;
  receipt: null | {
    version: number;
    digest: Uint8Array;
    backend: 'tee' | 'unknown';
    executor: Address;
    attestation: Uint8Array;
    proof: Uint8Array;
    trace: Uint8Array;
    outcome: {
      headerDigest: Uint8Array;
      clearing: Clearing[];
      fillCount: number;
      fillsRoot: Uint8Array;
      cancelledRoot: Uint8Array;
      nextStateRoot: Uint8Array;
      settlementCount: number;
      settlementRoot: Uint8Array;
      fees: bigint;
    };
  };
  settlement: null | {
    status: 'posted' | 'verifying' | 'verified' | 'applying' | 'settled' | 'aborted' | 'unknown';
    verified: number;
    applied: number;
    total: number;
  };
  txs: { op: EpochTxOp; signature: string; slot: bigint | null }[];
  abort: null | { reason: AbortReason; detail: string };
}

export interface Artifacts {
  market: Address;
  epoch: bigint;
  headerBytes: Uint8Array;
  receiptBytes: Uint8Array;
  artifactsBytes: Uint8Array;
  attestationBytes: Uint8Array | null;
  attestationPlatform: Trust['enclave'];
  cosignatures: { executor: Address; signature: Uint8Array }[];
}

export interface TapeRow {
  epoch: bigint;
  cutoffMs: number;
  phase: PublicPhase;
  clearing: Clearing[];
  matchedLots: bigint;
  fillCount: number;
  envelopeCount: number;
  terminalAtMs: number | null;
}

export interface ExecutorRegistration {
  market: Address;
  executor: Address;
  sealKey: Uint8Array;
  platform: Trust['enclave'];
  measurement: Uint8Array;
  nonce: Uint8Array;
  evidenceBytes: Uint8Array;
  registered: boolean;
  label: string;
}

export interface SessionNonce {
  nonce: Uint8Array;
  expiresAtMs: number;
  domain: string;
  uri: string;
  chainId: string;
  statement: string;
  templateVersion: 1;
}

export interface CreateSessionRequest {
  wallet: Address;
  message: string;
  signatureBytes: Uint8Array;
  method: 'sign_in' | 'sign_message';
}

export interface Session {
  sessionKey: Uint8Array;
  wallet: Address;
  market: Address | null;
  expiresAtMs: number;
  quotas: { maxEnvelopesPerWalletPerEpoch: number; maxParkedPerWallet: number };
  usage?: { epoch: bigint; used: number; parked: number };
  evicted?: number;
}

export interface SubmitResult {
  status: 'accepted' | 'parked' | 'unknown';
  market: Address;
  epoch: bigint;
  commitment: Uint8Array;
  envelopeDigest: Uint8Array;
  receivedAtMs: number;
  promiseBytes: Uint8Array;
  duplicate: boolean;
}

/** RFC 9457 problem details. `code` is an  code, or 'unknown' for a code this SDK does not know. */
export interface Problem {
  type: string;
  title: string;
  status: number;
  code: ErrorCode | 'unknown';
  detail: string;
  retryable: boolean;
  retryAfterMs?: number;
  requestId: string;
  market?: Address;
  epoch?: bigint;
  details?: unknown;
}

export type SubmitItemResult =
  { ok: SubmitResult } | { error: Problem & { refusalBytes?: Uint8Array } };

export interface ParkedItem {
  epoch: bigint;
  commitment: Uint8Array;
}

export interface RetractResult {
  removedEpochs: bigint[];
  keptOpenEpoch: bigint | null;
}

// ---- Wire schemas ----
// Each schema parses the node's JSON and yields the decoded type above.
// Unknown fields are ignored. Unknown enum strings become 'unknown'. A
// missing or malformed field fails the parse.

const U64_RE = /^(0|[1-9][0-9]{0,19})$/;
const I64_RE = /^-?(0|[1-9][0-9]{0,18})$/;

/** A string field decoded by `f`. A throw becomes a schema issue. */
function decoded<T>(what: string, f: (s: string) => T) {
  return z.string().transform((s, ctx): T => {
    try {
      return f(s);
    } catch {
      ctx.issues.push({ code: 'custom', message: `invalid ${what}`, input: s });
      return z.NEVER;
    }
  });
}

export const U64 = decoded('u64', (s) => {
  if (!U64_RE.test(s)) throw new RangeError('u64');
  const v = BigInt(s);
  if (v > U64_MAX) throw new RangeError('u64');
  return v;
});
export const I64 = decoded('i64', (s) => {
  if (!I64_RE.test(s)) throw new RangeError('i64');
  const v = BigInt(s);
  if (v > I64_MAX || v < I64_MIN) throw new RangeError('i64');
  return v;
});
export const Num = z
  .number()
  .int()
  .min(0)
  .max(2 ** 31 - 1);
export const TimeMs = z.number().int().min(0).max(Number.MAX_SAFE_INTEGER);
const hexBytes = (n: number) =>
  decoded(`hex${n}`, (s) => {
    if (s.length !== 2 * n || !/^[0-9a-f]*$/.test(s)) throw new RangeError('hex');
    return hex.decode(s, n);
  });
export const Hex16 = hexBytes(16);
export const Hex32 = hexBytes(32);
export const Hex64 = hexBytes(64);
export const B58 = decoded('base58 address', (s) => {
  if (b58.encode(b58.decode(s, 32)) !== s) throw new RangeError('base58');
  return s as Address;
});
export const B58Signature = decoded('base58 signature', (s) => {
  if (b58.encode(b58.decode(s, 64)) !== s) throw new RangeError('base58');
  return s;
});
export const B64 = decoded('base64', (s) => b64.decode(s));

/** A string enum. Values this SDK does not know become 'unknown' (versioning). */
export function enumOf<const T extends readonly string[]>(values: T) {
  return z.string().pipe(z.enum([...values, 'unknown'] as [...T, 'unknown']).catch('unknown'));
}

const BOOK_IDS = { single: 0, maker_ask_taker_bid: 1, maker_bid_taker_ask: 2 } as const;

/** The book's id, or null for a book this SDK does not know. */
function knownBook(b: string): BookId | null {
  return Object.hasOwn(BOOK_IDS, b) ? BOOK_IDS[b as keyof typeof BOOK_IDS] : null;
}

/**
 * Entries of a list that name a book this SDK knows. BookId has no
 * 'unknown' (a new book is a protocol change, /v2), and these lists are for
 * display, so an entry for an unknown book is left out rather than failing
 * the whole response (versioning).
 */
function knownBooks<T extends { book: string }>(xs: T[]): (Omit<T, 'book'> & { book: BookId })[] {
  return xs.flatMap((x) => {
    const book = knownBook(x.book);
    return book === null ? [] : [{ ...x, book }];
  });
}

export const PHASES = [
  'scheduled',
  'open',
  'closed',
  'committed',
  'revealed',
  'executing',
  'posted',
  'settled',
  'aborting',
  'aborted',
] as const;
export const PAUSE_REASONS = [
  'pipeline_backlog',
  'epoch_key_unavailable',
  'halted',
  'operator',
  'low_relay_balance',
  'recovering',
  'fenced',
  'draining',
  'governance_due',
] as const;
export const ABORT_REASONS = [
  'admin',
  'relay',
  'beacon_expired',
  'exec_timeout',
  'settle_timeout',
  'quorum_timeout',
] as const;
const MARKET_STATES = ['running', 'paused', 'draining', 'fenced', 'recovering'] as const;
const ENCLAVES = ['simulated', 'intel_tdx'] as const;
const REFERENCE_PRICES = ['fixed', 'last_clearing', 'operator', 'modelled_tlsnotary'] as const;
const CHANGE_KINDS = [
  'set_relay',
  'set_executors',
  'set_committee_digest',
  'set_admin',
  'set_timings',
  'set_timelock',
] as const;
const TX_OPS = [
  'commit',
  'reveal',
  'post',
  'cosign',
  'verify',
  'finalize',
  'apply',
  'close',
  'abort',
  'reclaim',
] as const;

export const Phase = enumOf(PHASES);
export const PauseReasonSchema = enumOf(PAUSE_REASONS);
export const AbortReasonSchema = enumOf(ABORT_REASONS);
const MarketStateSchema = enumOf(MARKET_STATES);
const Enclave = enumOf(ENCLAVES);

export const ClearingListSchema = z
  .array(z.object({ book: z.string(), tick: U64, volume: U64 }))
  .transform((xs): Clearing[] =>
    knownBooks(xs).map((c) => ({ book: c.book, tick: c.tick, volume: c.volume })),
  );

export const BandSchema = z
  .object({ lo: U64, hi: U64, reference: U64 })
  .transform((b): PriceBand => ({ lo: b.lo, hi: b.hi, reference: b.reference }));

const TrustSchema = z
  .object({
    enclave: Enclave,
    quote_generation: enumOf(['simulated', 'configfs_tsm_untested_on_hardware']),
    quote_verification: enumOf(['simulated_vendor', 'intel_dcap']),
    key_generation: enumOf(['trusted_dealer_feldman']),
    dkg: z.literal(false),
    mpc: enumOf(['disabled']),
    reference_price: enumOf(REFERENCE_PRICES),
    receipt_quorum: Num,
    registered_executors: Num,
    notes: z.array(z.string()),
  })
  .transform((t): Trust => ({
    enclave: t.enclave,
    quoteGeneration: t.quote_generation,
    quoteVerification: t.quote_verification,
    keyGeneration: t.key_generation,
    dkg: false,
    mpc: t.mpc,
    referencePrice: t.reference_price,
    receiptQuorum: t.receipt_quorum,
    registeredExecutors: t.registered_executors,
    notes: t.notes,
  }));

/** `/v1/info` before its versions are checked (the client refuses other versions with `VERSION_UNSUPPORTED`). */
export const InfoSchema = z.object({
  api_version: z.string(),
  protocol_version: z.number(),
  header_version: z.number(),
  node_version: z.string(),
  git_sha: z.string(),
  profile: enumOf(['local', 'devnet', 'production']),
  cluster: enumOf(['localnet', 'devnet', 'mainnet-beta']),
  genesis_hash: B58,
  program_id: B58,
  server_time_ms: TimeMs,
  markets: z.array(B58),
  trust: TrustSchema,
  limits: z.object({ submit_max_body_bytes: Num, session_max_ttl_s: Num }),
});

export function toInfo(r: z.output<typeof InfoSchema>): Info {
  return {
    apiVersion: r.api_version,
    protocolVersion: 1,
    headerVersion: 2,
    nodeVersion: r.node_version,
    gitSha: r.git_sha,
    profile: r.profile,
    cluster: r.cluster,
    genesisHash: r.genesis_hash,
    programId: r.program_id,
    serverTimeMs: r.server_time_ms,
    markets: r.markets,
    trust: r.trust,
    limits: {
      submitMaxBodyBytes: r.limits.submit_max_body_bytes,
      sessionMaxTtlS: r.limits.session_max_ttl_s,
    },
  };
}

export const StatusSchema = z
  .object({
    status: enumOf(['ok', 'degraded', 'down', 'recovering']),
    server_time_ms: TimeMs,
    components: z.array(
      z.object({
        name: z.string(),
        status: enumOf(['ok', 'degraded', 'down']),
        detail: z.string().optional(),
        since_ms: TimeMs,
      }),
    ),
    markets: z.array(
      z.object({
        market: B58,
        state: MarketStateSchema,
        intake: enumOf(['open', 'paused']),
        pause_reason: PauseReasonSchema.optional(),
        current_epoch: U64.nullable(),
        last_committed: U64,
        last_settled: U64,
        settlement_lag: Num,
        keys_ready_ahead: Num,
      }),
    ),
    notice: z
      .object({
        level: enumOf(['info', 'warning', 'critical']),
        message: z.string(),
        since_ms: TimeMs,
      })
      .optional(),
  })
  .transform((s): Status => ({
    status: s.status,
    serverTimeMs: s.server_time_ms,
    components: s.components.map((c) => ({
      name: c.name,
      status: c.status,
      ...(c.detail !== undefined ? { detail: c.detail } : {}),
      sinceMs: c.since_ms,
    })),
    markets: s.markets.map((m) => ({
      market: m.market,
      state: m.state,
      intake: m.intake,
      ...(m.pause_reason !== undefined ? { pauseReason: m.pause_reason } : {}),
      currentEpoch: m.current_epoch,
      lastCommitted: m.last_committed,
      lastSettled: m.last_settled,
      settlementLag: m.settlement_lag,
      keysReadyAhead: m.keys_ready_ahead,
    })),
    ...(s.notice !== undefined
      ? {
          notice: { level: s.notice.level, message: s.notice.message, sinceMs: s.notice.since_ms },
        }
      : {}),
  }));

const summaryFields = {
  market: B58,
  name: z.string(),
  base_symbol: z.string(),
  quote_symbol: z.string(),
  state: MarketStateSchema,
  halted: z.boolean(),
  last_clearing: ClearingListSchema.nullable(),
};

type SummaryRaw = z.output<z.ZodObject<typeof summaryFields>>;

function toSummary(m: SummaryRaw): MarketSummary {
  return {
    market: m.market,
    name: m.name,
    baseSymbol: m.base_symbol,
    quoteSymbol: m.quote_symbol,
    state: m.state,
    halted: m.halted,
    lastClearing: m.last_clearing,
  };
}

export const MarketSummarySchema = z.object(summaryFields).transform(toSummary);

const Padding = z
  .union([
    z.object({ kind: z.literal('power_of_two'), min: Num }),
    z.object({ kind: z.literal('fixed'), n: Num }),
    z.object({ kind: z.literal('unknown') }),
  ])
  .catch({ kind: 'unknown' });

const Authorities = z.object({ mint: B58.nullable(), freeze: B58.nullable() });

/** `params_b64` is canonical. The JSON `params` view beside it is informational and not read. */
const MarketParamsBytes = B64.transform((b, ctx): { bytes: Uint8Array; params: MarketParams } => {
  try {
    return { bytes: b, params: decodeMarketParams(b) };
  } catch {
    ctx.issues.push({ code: 'custom', message: 'invalid params_b64', input: b });
    return z.NEVER;
  }
});

export const MarketDetailSchema = z
  .object({
    ...summaryFields,
    market_id: U64,
    creator: B58,
    admin: B58,
    params_b64: MarketParamsBytes,
    params_digest: Hex32,
    base_mint: B58,
    quote_mint: B58,
    base_vault: B58,
    quote_vault: B58,
    base_decimals: Num,
    quote_decimals: Num,
    relay: B58,
    executors: z.array(B58),
    receipt_quorum: Num,
    committee: z.object({
      digest: Hex32,
      description_b64: B64,
      threshold: Num,
      members: z.array(z.object({ index: Num, identity: Hex32, transport: Hex32 })),
      prev_digest: Hex32.nullable(),
      prev_description_b64: B64.nullable(),
      policies_b64: z.array(B64),
    }),
    timing: z.object({
      epoch_interval_ms: Num,
      beacon_delay_slots: Num,
      exec_timeout_slots: U64,
      settle_timeout_slots: U64,
      timelock_slots: U64,
      max_park_ahead_epochs: Num,
    }),
    relay_policy: z.object({
      padding: Padding,
      ack: enumOf(['immediate']),
      max_envelopes_per_wallet_per_epoch: Num,
      max_parked_per_wallet: Num,
      min_available_value_quote: U64,
      min_value_per_envelope_quote: U64,
      require_trader_account: z.boolean(),
      idle_policy: enumOf(['commit', 'extend']),
    }),
    market_id_salt: Hex32,
    session_domains: z.array(z.string()),
    mint_authorities: z.object({ base: Authorities, quote: Authorities }),
    books: z
      .array(z.object({ book: z.string(), label: z.string() }))
      .transform((xs) => knownBooks(xs).map((b) => ({ book: b.book, label: b.label }))),
    pending_change: z
      .object({ kind: enumOf(CHANGE_KINDS), eta_slot: U64, payload_b64: B64, due: z.boolean() })
      .nullable(),
    program: z.object({ upgrade_authority: B58.nullable(), last_deploy_slot: U64 }),
    chain: z.object({
      last_committed: U64,
      last_settled: U64,
      state_root: Hex32,
      prev_receipt: Hex32,
      context_slot: U64,
    }),
  })
  .transform((m): MarketDetail => ({
    ...toSummary(m),
    marketId: m.market_id,
    creator: m.creator,
    admin: m.admin,
    params: m.params_b64.params,
    paramsBytes: m.params_b64.bytes,
    paramsDigest: m.params_digest,
    baseMint: m.base_mint,
    quoteMint: m.quote_mint,
    baseVault: m.base_vault,
    quoteVault: m.quote_vault,
    baseDecimals: m.base_decimals,
    quoteDecimals: m.quote_decimals,
    relay: m.relay,
    executors: m.executors,
    receiptQuorum: m.receipt_quorum,
    committee: {
      digest: m.committee.digest,
      descriptionBytes: m.committee.description_b64,
      threshold: m.committee.threshold,
      members: m.committee.members,
      prevDigest: m.committee.prev_digest,
      prevDescriptionBytes: m.committee.prev_description_b64,
      policiesBytes: m.committee.policies_b64,
    },
    timing: {
      epochIntervalMs: m.timing.epoch_interval_ms,
      beaconDelaySlots: m.timing.beacon_delay_slots,
      execTimeoutSlots: m.timing.exec_timeout_slots,
      settleTimeoutSlots: m.timing.settle_timeout_slots,
      timelockSlots: m.timing.timelock_slots,
      maxParkAheadEpochs: m.timing.max_park_ahead_epochs,
    },
    relayPolicy: {
      padding: m.relay_policy.padding,
      ack: m.relay_policy.ack,
      maxEnvelopesPerWalletPerEpoch: m.relay_policy.max_envelopes_per_wallet_per_epoch,
      maxParkedPerWallet: m.relay_policy.max_parked_per_wallet,
      minAvailableValueQuote: m.relay_policy.min_available_value_quote,
      minValuePerEnvelopeQuote: m.relay_policy.min_value_per_envelope_quote,
      requireTraderAccount: m.relay_policy.require_trader_account,
      idlePolicy: m.relay_policy.idle_policy,
    },
    marketIdSalt: m.market_id_salt,
    sessionDomains: m.session_domains,
    mintAuthorities: m.mint_authorities,
    books: m.books,
    pendingChange:
      m.pending_change === null
        ? null
        : {
            kind: m.pending_change.kind,
            etaSlot: m.pending_change.eta_slot,
            payloadBytes: m.pending_change.payload_b64,
            due: m.pending_change.due,
          },
    program: {
      upgradeAuthority: m.program.upgrade_authority,
      lastDeploySlot: m.program.last_deploy_slot,
    },
    chain: {
      lastCommitted: m.chain.last_committed,
      lastSettled: m.chain.last_settled,
      stateRoot: m.chain.state_root,
      prevReceipt: m.chain.prev_receipt,
      contextSlot: m.chain.context_slot,
    },
  }));

export const EpochKeySchema = z
  .object({ epoch: U64, epoch_pk: Hex32, committee_digest: Hex32, bundle_b64: B64 })
  .transform((k): EpochKey => ({
    epoch: k.epoch,
    epochPk: k.epoch_pk,
    committeeDigest: k.committee_digest,
    bundleBytes: k.bundle_b64,
  }));

const EpochPhase = z.object({ epoch: U64, phase: Phase });

export const CurrentEpochSchema = z
  .object({
    market: B58,
    server_time_ms: TimeMs,
    intake: enumOf(['open', 'paused']),
    pause_reason: PauseReasonSchema.optional(),
    open: z
      .object({
        epoch: U64,
        opens_at_ms: TimeMs,
        cutoff_ms: TimeMs,
        band: BandSchema,
        binding: Hex32,
        terms_digest: Hex32,
        price_commitment: z.object({
          digest: Hex32,
          reference: U64,
          source: enumOf(REFERENCE_PRICES),
          observations: z.array(z.object({ source: Num, tick: U64, time: U64 })),
          commitment_b64: B64,
        }),
        announcement_b64: B64,
        key: EpochKeySchema,
        real_slots_left: enumOf(['available', 'low', 'full']),
      })
      .nullable(),
    park_window: z.array(EpochKeySchema),
    previous: EpochPhase.nullable(),
    inflight: EpochPhase.nullable(),
    context_slot: U64,
  })
  .transform((c): CurrentEpoch => ({
    market: c.market,
    serverTimeMs: c.server_time_ms,
    intake: c.intake,
    ...(c.pause_reason !== undefined ? { pauseReason: c.pause_reason } : {}),
    open:
      c.open === null
        ? null
        : {
            epoch: c.open.epoch,
            opensAtMs: c.open.opens_at_ms,
            cutoffMs: c.open.cutoff_ms,
            band: c.open.band,
            binding: c.open.binding,
            termsDigest: c.open.terms_digest,
            priceCommitment: {
              digest: c.open.price_commitment.digest,
              reference: c.open.price_commitment.reference,
              source: c.open.price_commitment.source,
              observations: c.open.price_commitment.observations,
              commitmentBytes: c.open.price_commitment.commitment_b64,
            },
            announcementBytes: c.open.announcement_b64,
            key: c.open.key,
            realSlotsLeft: c.open.real_slots_left,
          },
    parkWindow: c.park_window,
    previous: c.previous,
    inflight: c.inflight,
    contextSlot: c.context_slot,
  }));

const summaryEpochFields = {
  market: B58,
  epoch: U64,
  phase: Phase,
  opens_at_ms: TimeMs,
  cutoff_ms: TimeMs,
  envelope_count: Num.nullable(),
  clearing: ClearingListSchema.nullable(),
  fill_count: Num.nullable(),
  terminal_at_ms: TimeMs.nullable(),
  abort_reason: AbortReasonSchema.nullable(),
  tee_platform: Enclave.nullable(),
};

function toEpochSummary(e: z.output<z.ZodObject<typeof summaryEpochFields>>): EpochSummary {
  return {
    market: e.market,
    epoch: e.epoch,
    phase: e.phase,
    opensAtMs: e.opens_at_ms,
    cutoffMs: e.cutoff_ms,
    envelopeCount: e.envelope_count,
    clearing: e.clearing,
    fillCount: e.fill_count,
    terminalAtMs: e.terminal_at_ms,
    abortReason: e.abort_reason,
    teePlatform: e.tee_platform,
  };
}

export const EpochSummarySchema = z.object(summaryEpochFields).transform(toEpochSummary);

export const EpochDetailSchema = z
  .object({
    ...summaryEpochFields,
    band: BandSchema,
    terms_digest: Hex32,
    announcement_b64: B64,
    key: EpochKeySchema,
    batch: z
      .object({
        address: B58,
        status: z.string(),
        root: Hex32,
        count: Num,
        terms_digest: Hex32,
        commit_slot: U64,
        commit_signature: B58Signature,
        beacon: Hex32.nullable(),
        beacon_slots: z.tuple([U64, U64]).nullable(),
        reveal_slot: U64.nullable(),
        header_digest: Hex32.nullable(),
        receipt_digest: Hex32.nullable(),
        outcome_digest: Hex32.nullable(),
        cosigners: z.array(B58),
        quorum: z.object({ have: Num, need: Num }),
        settlement_count: Num.nullable(),
        fees: U64.nullable(),
        context_slot: U64,
      })
      .nullable(),
    artifacts_public: z.boolean(),
    header_b64: B64.nullable(),
    receipt_b64: B64.nullable(),
    receipt: z
      .object({
        version: Num,
        digest: Hex32,
        backend: enumOf(['tee']),
        executor: B58,
        attestation: Hex32,
        proof: Hex32,
        trace: Hex32,
        outcome: z.object({
          header_digest: Hex32,
          clearing: ClearingListSchema,
          fill_count: Num,
          fills_root: Hex32,
          cancelled_root: Hex32,
          next_state_root: Hex32,
          settlement_count: Num,
          settlement_root: Hex32,
          fees: U64,
        }),
      })
      .nullable(),
    settlement: z
      .object({
        status: enumOf(['posted', 'verifying', 'verified', 'applying', 'settled', 'aborted']),
        verified: Num,
        applied: Num,
        total: Num,
      })
      .nullable(),
    txs: z.array(z.object({ op: enumOf(TX_OPS), signature: B58Signature, slot: U64.nullable() })),
    abort: z.object({ reason: AbortReasonSchema, detail: z.string() }).nullable(),
  })
  .transform((e): EpochDetail => ({
    ...toEpochSummary(e),
    band: e.band,
    termsDigest: e.terms_digest,
    announcementBytes: e.announcement_b64,
    key: e.key,
    batch:
      e.batch === null
        ? null
        : {
            address: e.batch.address,
            status: e.batch.status,
            root: e.batch.root,
            count: e.batch.count,
            termsDigest: e.batch.terms_digest,
            commitSlot: e.batch.commit_slot,
            commitSignature: e.batch.commit_signature,
            beacon: e.batch.beacon,
            beaconSlots: e.batch.beacon_slots,
            revealSlot: e.batch.reveal_slot,
            headerDigest: e.batch.header_digest,
            receiptDigest: e.batch.receipt_digest,
            outcomeDigest: e.batch.outcome_digest,
            cosigners: e.batch.cosigners,
            quorum: e.batch.quorum,
            settlementCount: e.batch.settlement_count,
            fees: e.batch.fees,
            contextSlot: e.batch.context_slot,
          },
    artifactsPublic: e.artifacts_public,
    headerBytes: e.header_b64,
    receiptBytes: e.receipt_b64,
    receipt:
      e.receipt === null
        ? null
        : {
            version: e.receipt.version,
            digest: e.receipt.digest,
            backend: e.receipt.backend,
            executor: e.receipt.executor,
            attestation: e.receipt.attestation,
            proof: e.receipt.proof,
            trace: e.receipt.trace,
            outcome: {
              headerDigest: e.receipt.outcome.header_digest,
              clearing: e.receipt.outcome.clearing,
              fillCount: e.receipt.outcome.fill_count,
              fillsRoot: e.receipt.outcome.fills_root,
              cancelledRoot: e.receipt.outcome.cancelled_root,
              nextStateRoot: e.receipt.outcome.next_state_root,
              settlementCount: e.receipt.outcome.settlement_count,
              settlementRoot: e.receipt.outcome.settlement_root,
              fees: e.receipt.outcome.fees,
            },
          },
    settlement: e.settlement,
    txs: e.txs,
    abort: e.abort,
  }));

export const ArtifactsSchema = z
  .object({
    market: B58,
    epoch: U64,
    header_b64: B64,
    receipt_b64: B64,
    artifacts_b64: B64,
    attestation_b64: B64.nullable(),
    attestation_platform: Enclave,
    cosignatures: z.array(z.object({ executor: B58, signature: Hex64 })),
  })
  .transform((a): Artifacts => ({
    market: a.market,
    epoch: a.epoch,
    headerBytes: a.header_b64,
    receiptBytes: a.receipt_b64,
    artifactsBytes: a.artifacts_b64,
    attestationBytes: a.attestation_b64,
    attestationPlatform: a.attestation_platform,
    cosignatures: a.cosignatures,
  }));

export const TapeRowSchema = z
  .object({
    epoch: U64,
    cutoff_ms: TimeMs,
    phase: Phase,
    clearing: ClearingListSchema,
    matched_lots: U64,
    fill_count: Num,
    envelope_count: Num,
    terminal_at_ms: TimeMs.nullable(),
  })
  .transform((t): TapeRow => ({
    epoch: t.epoch,
    cutoffMs: t.cutoff_ms,
    phase: t.phase,
    clearing: t.clearing,
    matchedLots: t.matched_lots,
    fillCount: t.fill_count,
    envelopeCount: t.envelope_count,
    terminalAtMs: t.terminal_at_ms,
  }));

export const ExecutorRegistrationSchema = z
  .object({
    market: B58,
    executor: B58,
    seal_key: Hex32,
    platform: Enclave,
    measurement: Hex32,
    nonce: Hex32,
    evidence_b64: B64,
    registered: z.boolean(),
    label: z.string(),
  })
  .transform((x): ExecutorRegistration => ({
    market: x.market,
    executor: x.executor,
    sealKey: x.seal_key,
    platform: x.platform,
    measurement: x.measurement,
    nonce: x.nonce,
    evidenceBytes: x.evidence_b64,
    registered: x.registered,
    label: x.label,
  }));

export const SessionNonceSchema = z
  .object({
    nonce: Hex16,
    expires_at_ms: TimeMs,
    domain: z.string(),
    uri: z.string(),
    chain_id: z.string(),
    statement: z.string(),
    template_version: z.literal(1),
  })
  .transform((n): SessionNonce => ({
    nonce: n.nonce,
    expiresAtMs: n.expires_at_ms,
    domain: n.domain,
    uri: n.uri,
    chainId: n.chain_id,
    statement: n.statement,
    templateVersion: 1,
  }));

export const SessionSchema = z
  .object({
    session_key: Hex32,
    wallet: B58,
    market: B58.nullable(),
    expires_at_ms: TimeMs,
    quotas: z.object({ max_envelopes_per_wallet_per_epoch: Num, max_parked_per_wallet: Num }),
    usage: z.object({ epoch: U64, used: Num, parked: Num }).optional(),
    evicted: Num.optional(),
  })
  .transform((s): Session => ({
    sessionKey: s.session_key,
    wallet: s.wallet,
    market: s.market,
    expiresAtMs: s.expires_at_ms,
    quotas: {
      maxEnvelopesPerWalletPerEpoch: s.quotas.max_envelopes_per_wallet_per_epoch,
      maxParkedPerWallet: s.quotas.max_parked_per_wallet,
    },
    ...(s.usage !== undefined ? { usage: s.usage } : {}),
    ...(s.evicted !== undefined ? { evicted: s.evicted } : {}),
  }));

export const SubmitResultSchema = z
  .object({
    status: enumOf(['accepted', 'parked']),
    market: B58,
    epoch: U64,
    commitment: Hex32,
    envelope_digest: Hex32,
    received_at_ms: TimeMs,
    promise_b64: B64,
    duplicate: z.boolean(),
  })
  .transform((r): SubmitResult => ({
    status: r.status,
    market: r.market,
    epoch: r.epoch,
    commitment: r.commitment,
    envelopeDigest: r.envelope_digest,
    receivedAtMs: r.received_at_ms,
    promiseBytes: r.promise_b64,
    duplicate: r.duplicate,
  }));

export const ERROR_CODES = [
  'BAD_REQUEST',
  'DECODE_FAILED',
  'UNSUPPORTED_MEDIA_TYPE',
  'BODY_TOO_LARGE',
  'VERSION_UNSUPPORTED',
  'WRONG_MARKET',
  'MASKED_NOT_SUPPORTED',
  'BAD_SIGNATURE',
  'SKEW',
  'SESSION_UNKNOWN',
  'SESSION_EXPIRED',
  'SESSION_REVOKED',
  'SESSION_TEMPLATE_INVALID',
  'SESSION_DOMAIN_MISMATCH',
  'SESSION_NONCE_INVALID',
  'SESSION_METHOD_REFUSED',
  'WALLET_NOT_ELIGIBLE',
  'MARKET_HALTED',
  'MARKET_UNKNOWN',
  'NOT_FOUND',
  'NOT_YET_AVAILABLE',
  'PRUNED',
  'EPOCH_CLOSED',
  'EPOCH_TOO_FAR',
  'DUPLICATE_COMMITMENT',
  'BATCH_FULL',
  'QUOTA_EXCEEDED',
  'RATE_LIMITED',
  'EPOCH_KEY_UNAVAILABLE',
  'INTAKE_PAUSED',
  'MARKET_UNAVAILABLE',
  'OVERLOADED',
  'DRAINING',
  'INTERNAL',
] as const satisfies readonly ErrorCode[];

// Every ErrorCode is listed: the assignment fails to compile otherwise.
const _allCodes: readonly (typeof ERROR_CODES)[number][] = [] as ErrorCode[];
void _allCodes;

const problemFields = {
  type: z.string(),
  title: z.string(),
  status: z.number().int().min(100).max(599),
  code: enumOf(ERROR_CODES),
  detail: z.string(),
  retryable: z.boolean(),
  retry_after_ms: z.number().int().min(0).optional(),
  request_id: z.string(),
  market: B58.optional(),
  epoch: U64.optional(),
  details: z.unknown().optional(),
};

function toProblem(p: z.output<z.ZodObject<typeof problemFields>>): Problem {
  return {
    type: p.type,
    title: p.title,
    status: p.status,
    code: p.code,
    detail: p.detail,
    retryable: p.retryable,
    ...(p.retry_after_ms !== undefined ? { retryAfterMs: p.retry_after_ms } : {}),
    requestId: p.request_id,
    ...(p.market !== undefined ? { market: p.market } : {}),
    ...(p.epoch !== undefined ? { epoch: p.epoch } : {}),
    ...(p.details !== undefined ? { details: p.details } : {}),
  };
}

export const ProblemSchema = z.object(problemFields).transform(toProblem);

export const SubmitItemResultSchema = z.union([
  z.object({ ok: SubmitResultSchema }).transform((r): SubmitItemResult => ({ ok: r.ok })),
  z
    .object({
      error: z.object({ ...problemFields, refusal_b64: B64.optional() }),
    })
    .transform((r): SubmitItemResult => ({
      error: {
        ...toProblem(r.error),
        ...(r.error.refusal_b64 !== undefined ? { refusalBytes: r.error.refusal_b64 } : {}),
      },
    })),
]);

export const ParkedItemSchema = z
  .object({ epoch: U64, commitment: Hex32 })
  .transform((p): ParkedItem => ({ epoch: p.epoch, commitment: p.commitment }));

export const RetractResultSchema = z
  .object({ removed_epochs: z.array(U64), kept_open_epoch: U64.nullable() })
  .transform((r): RetractResult => ({
    removedEpochs: r.removed_epochs,
    keptOpenEpoch: r.kept_open_epoch,
  }));

export const TimeSchema = z
  .object({ server_time_ms: TimeMs, slot: U64 })
  .transform((t) => ({ serverTimeMs: t.server_time_ms, slot: t.slot }));

export const PolicyListSchema = z
  .object({ items: z.array(z.object({ member: Num, statement_b64: B64 })) })
  .transform((l) => l.items.map((i) => i.statement_b64));

export function itemsOf<T extends z.ZodType>(item: T) {
  return z.object({ items: z.array(item) }).transform((l) => l.items);
}

export function pageOf<T extends z.ZodType>(item: T) {
  return z
    .object({ items: z.array(item), next_before: U64.nullable() })
    .transform((p) => ({ items: p.items, nextBefore: p.next_before }));
}
