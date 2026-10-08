import type { Address } from '@solana/kit';
import { ed25519 } from '@noble/curves/ed25519.js';
import type { TimescalesApi } from '../api/client.js';
import { ERROR_TABLE } from '../api/errors.js';
import { b58 } from '../core/encoding/base58.js';
import { b64 } from '../core/encoding/base64.js';
import { bytesToBigIntLE, concat, equal, utf8 } from '../core/encoding/bytes.js';
import { Writer } from '../core/encoding/codec.js';
import { hex } from '../core/encoding/hex.js';
import { ed25519PublicKey, ed25519Sign } from '../core/crypto/ed25519.js';
import { edwardsU } from '../core/crypto/edwards.js';
import { verifyStrict, L } from '../core/crypto/verifyStrict.js';
import { x25519PublicKey } from '../core/crypto/x25519.js';
import {
  encodeAnnouncement,
  epochAnnouncementDigest,
  type EpochAnnouncement,
} from '../core/protocol/announcement.js';
import {
  cancelledRoot,
  encodeArtifacts,
  fillsRoot,
  type Fill,
} from '../core/protocol/artifacts.js';
import { band as bandOf, type PriceBand } from '../core/protocol/band.js';
import { epochBinding, termsDigest } from '../core/protocol/binding.js';
import {
  ackDigest,
  announcementDigest,
  encodeBundle,
  type EpochKeyAnnouncement,
} from '../core/protocol/bundle.js';
import {
  committeeDigest as committeeDigestOf,
  encodeCommittee,
} from '../core/protocol/committee.js';
import { decodeEnvelope, envelopeDigest } from '../core/protocol/envelope.js';
import { encodeHeader, headerDigest } from '../core/protocol/header.js';
import { batchRootV2, encodeLeaves, type BatchLeaf } from '../core/protocol/leaves.js';
import { deriveMarketId } from '../core/protocol/marketId.js';
import {
  bookFor,
  encodeMarketParams,
  paramsDigest,
  type BookId,
  type MarketParams,
  type Role,
  type Side,
} from '../core/protocol/params.js';
import { encodePolicyStatement, policyDigest } from '../core/protocol/policy.js';
import { encodePromiseV2, promiseV2Digest } from '../core/protocol/promise.js';
import {
  encodeReceipt,
  outcomeDigest,
  receiptDigest,
  type ExecutionOutcome,
} from '../core/protocol/receipt.js';
import { encodeRelayRefusal, relayRefusalDigest } from '../core/protocol/refusal.js';
import { SESSION_STATEMENT, parseSessionMessage } from '../core/protocol/sessionText.js';
import { settle, settlementRoot } from '../core/protocol/settlement.js';
import { encodeBalanceSheet } from '../core/protocol/state.js';
import { decodeSubmission, submissionDigest } from '../core/protocol/submission.js';
import { TimescalesError, type ErrorCode } from '../errors.js';
import {
  availableFor,
  type AbortReason,
  type BatchAccount,
  type MarketAccount,
  type TraderAccount,
} from '../solana/accounts.js';
import { batchSeeds, findProgramAddressSync, marketSeeds, traderSeeds } from '../solana/pdas.js';
import { SYSTEM_PROGRAM, programDataAddress } from '../solana/program.js';
import { programAccountAt, type AccountSnapshot, type TimescalesRpc } from '../solana/rpc.js';
import type { AppPins } from '../verify/market.js';
import { sessionRequestDigest } from '../wallet/session.js';
import { createFakeApi, type FakeApi, type FakeRequest } from './fakeApi.js';
import { devEpochKey, testMarketParams } from './fixtures.js';
import { createTestRng } from './rng.js';

// An in-memory node, relay, key committee, executors and chain for tests of
// the SDK and the app: everything a trader client talks to, built from the
// real encoders and signed with real keys, so the verifier checks run unmodified.
// Tests drive the epochs explicitly (close, commit, reveal, post, cosign,
// settle, abort). Nothing here models a node's timing or failure handling
// beyond what the tests ask for.

export interface FakeNodeOptions {
  seed?: Uint8Array;
  cluster?: 'localnet' | 'devnet' | 'mainnet-beta';
  profile?: 'local' | 'devnet' | 'production';
  scheme?: 'dev' | 'feldman';
  params?: Partial<MarketParams>;
  epochIntervalMs?: number;
  maxParkAheadEpochs?: number;
  receiptQuorum?: number;
  executors?: number;
  reference?: bigint;
  maxParkedPerWallet?: number;
  maxEnvelopesPerWalletPerEpoch?: number;
  /** Envelopes an epoch accepts before `BATCH_FULL`. */
  capacity?: number;
  /** The epoch open at creation (default 1), as on a market that has run for a while. */
  firstEpoch?: bigint;
  now?: () => number;
}

/** A fill the executor reports. The book is derived. */
export interface FakeFill {
  commitment: Uint8Array;
  trader: Uint8Array;
  side: Side;
  role: Role;
  quantity: bigint;
  tick: bigint;
}

export interface HeldSubmission {
  epoch: bigint;
  commitment: Uint8Array;
  envelopeDigest: Uint8Array;
  submission: Uint8Array;
  promise: Uint8Array;
  wallet: Address;
}

export interface FakeNode {
  readonly api: TimescalesApi;
  readonly fake: FakeApi;
  readonly rpc: TimescalesRpc;
  readonly WebSocket: typeof WebSocket;
  readonly streamUrl: string;
  readonly pins: AppPins;
  readonly market: Address;
  readonly marketId: bigint;
  readonly program: Address;
  readonly params: MarketParams;
  readonly band: PriceBand;
  readonly relay: Address;
  /** The open epoch. */
  readonly open: bigint;
  /** Submissions the relay holds for `epoch` (accepted or parked). */
  held(epoch: bigint): HeldSubmission[];
  /** Submission requests seen, in order: one entry per item. */
  readonly submitted: { epoch: bigint; commitment: Uint8Array; duplicate: boolean }[];
  closeEpoch(): void;
  commit(
    epoch: bigint,
    o?: { omit?: Uint8Array[]; substitute?: Uint8Array[]; cover?: number; terms?: Uint8Array },
  ): void;
  reveal(epoch: bigint): void;
  post(epoch: bigint, o: { fills: FakeFill[]; cancelled?: Uint8Array[] }): void;
  cosign(epoch: bigint): void;
  settle(epoch: bigint, o?: { stopAt?: 'verifying' | 'applying' }): void;
  abort(epoch: bigint, reason?: Exclude<AbortReason, 'unknown'>): void;
  invalidateParked(epochs: bigint[]): void;
  /** While `withheld`, the epoch's leaves are answered with `NOT_YET_AVAILABLE`, as a node that holds them back. */
  withholdLeaves(epoch: bigint, withheld: boolean): void;
  /** While `withheld`, the epoch's detail is answered with `NOT_YET_AVAILABLE`. */
  withholdDetail(epoch: bigint, withheld: boolean): void;
  /** Serves `sheet` as the epoch's balance sheet instead of the relay's snapshot. Null restores it. */
  overrideBalances(epoch: bigint, sheet: Uint8Array | null): void;
  /** Publishes `event` as given on the market's topic (events the fake does not raise itself). */
  emit(event: Record<string, unknown>): void;
  fund(owner: Address, base: bigint, quote: bigint): void;
  /**
   * Sends lamports to `address`, as anyone can: where the program has no
   * account yet this leaves a System-owned account without data, which the
   * program adopts when it creates its account there.
   */
  prefund(address: Address): void;
  /** The next `n` submission requests are processed and then answered with 503 `OVERLOADED`. */
  failSubmissions(n: number): void;
  /** Runs `f` when the next submission request arrives, before the relay looks at it. */
  onNextSubmission(f: () => void): void;
  setIntake(open: boolean): void;
  /** Closes every fake socket with `code`. */
  dropSockets(code?: number): void;
  /** Open sockets subscribed to `topic`. */
  subscribers(topic: string): number;
  /** Signing seeds, so tests can forge or tamper with what the node would sign. */
  readonly secrets: {
    relay: Uint8Array;
    executors: Uint8Array[];
    members: { index: number; seed: Uint8Array }[];
    upgradeAuthority: Address;
  };
}

interface Key {
  seed: Uint8Array;
  pub: Uint8Array;
  address: Address;
}

interface Dealt {
  epoch: bigint;
  epochPk: Uint8Array;
  bundle: Uint8Array;
  keyDigest: Uint8Array;
}

interface EpochState {
  epoch: bigint;
  key: Dealt;
  opensAtMs: number;
  cutoffMs: number;
  phase:
    'scheduled' | 'open' | 'closed' | 'committed' | 'revealed' | 'posted' | 'settled' | 'aborted';
  announcement: {
    raw: Uint8Array;
    binding: Uint8Array;
    terms: Uint8Array;
    priceCommitment: Uint8Array;
  } | null;
  subs: HeldSubmission[];
  leaves: Uint8Array | null;
  /** The relay's snapshot of available balances for the batch, published with the artifacts. */
  balances: Uint8Array | null;
  batch: BatchAccount | null;
  header: Uint8Array | null;
  receipt: Uint8Array | null;
  outcome: ExecutionOutcome | null;
  artifacts: Uint8Array | null;
}

interface SessionState {
  key: Uint8Array;
  wallet: Address;
  market: Address | null;
  expiresAtMs: number;
  lastTs: bigint;
  revoked: boolean;
  grant: string;
}

const MEMBERS = 3;
const THRESHOLD = 2;
const STREAM_URL = 'ws://node.timescales.test/v1/stream';

function json(v: unknown): string {
  return JSON.stringify(v, (_k, x: unknown) => (typeof x === 'bigint' ? x.toString() : x));
}

function problem(code: ErrorCode, detail: string, details?: Record<string, unknown>) {
  const { http, retryable } = ERROR_TABLE[code];
  return {
    status: http,
    body: {
      type: `urn:timescales:error:${code.toLowerCase()}`,
      title: code,
      status: http,
      code,
      detail,
      retryable,
      request_id: 'fake',
      ...(details !== undefined ? { details } : {}),
    },
  };
}

function respondProblem(p: ReturnType<typeof problem>): Response {
  return new Response(json(p.body), {
    status: p.status,
    headers: { 'content-type': 'application/problem+json' },
  });
}

const BOOK_NAMES = ['single', 'maker_ask_taker_bid', 'maker_bid_taker_ask'] as const;
/** The refusal numbering. */
const REFUSAL_CODES: Partial<Record<ErrorCode, number>> = {
  BATCH_FULL: 1,
  INTAKE_PAUSED: 2,
  QUOTA_EXCEEDED: 3,
  EPOCH_CLOSED: 4,
};

/** The in-memory node described at the top of this file. */
export function createFakeNode(o: FakeNodeOptions = {}): FakeNode {
  const rng = createTestRng(o.seed ?? crypto.getRandomValues(new Uint8Array(32)));
  const clock = o.now ?? (() => Date.now());
  const fake = createFakeApi({ now: clock });
  const key = (): Key => {
    const seed = rng.bytes(32);
    const pub = ed25519PublicKey(seed);
    return { seed, pub, address: b58.encode(pub) as Address };
  };
  const cluster = o.cluster ?? 'devnet';
  const profile = o.profile ?? 'devnet';
  const scheme = o.scheme ?? 'feldman';
  const interval = o.epochIntervalMs ?? 60_000;
  const parkAhead = o.maxParkAheadEpochs ?? 3;
  const quorumNeed = o.receiptQuorum ?? 1;
  const keySeed = rng.bytes(32);

  const program = key().address;
  const creator = key();
  const admin = key();
  const relay = key();
  const executors = Array.from({ length: o.executors ?? 2 }, key);
  const upgradeAuthority = key().address;
  const salt = rng.bytes(32);
  const marketId = deriveMarketId(program, creator.address, salt);
  const market = findProgramAddressSync(marketSeeds(marketId), program)[0];
  const marketBytes = b58.decode(market, 32);
  const params = testMarketParams({ market: marketId, ...o.params });
  const band = bandOf(params, o.reference ?? 10_000n);
  const genesisHash = b58.encode(rng.bytes(32));
  const baseMint = key().address;
  const quoteMint = key().address;
  const baseVault = key().address;
  const quoteVault = key().address;
  const mintAuthority = key().address;

  const mintBytes = (decimals: number): Uint8Array =>
    new Writer()
      .u32(1)
      .fixed(b58.decode(mintAuthority, 32), 32)
      .u64(1_000_000_000n)
      .u8(decimals)
      .bool(true)
      .u32(0)
      .fixed(new Uint8Array(32), 32)
      .finish();
  const programData = new Writer()
    .u32(3)
    .u64(1n)
    .u8(1)
    .fixed(b58.decode(upgradeAuthority, 32), 32)
    .finish();

  // Key-release committee and the members' release policies (V-2, V-14).
  const members = Array.from({ length: MEMBERS }, (_, i) => ({
    index: i + 1,
    key: key(),
    transport: x25519PublicKey(rng.bytes(32)),
  }));
  const description = encodeCommittee({
    version: 1,
    market: marketBytes,
    threshold: THRESHOLD,
    members: members.map((m) => ({ index: m.index, identity: m.key.pub, transport: m.transport })),
  });
  const committeeDigest = committeeDigestOf(description);
  const policies = members.map((m) => {
    const unsigned = {
      market: marketBytes,
      member: m.index,
      committeeDigest,
      platforms: { simulated: true, intelTdx: false },
      measurementSetDigest: new Uint8Array(32),
      allowDebug: false,
      minTcb: 0,
      mrConfigId: new Uint8Array(48),
      fromEpoch: 0n,
      signature: new Uint8Array(64),
    };
    const digest = policyDigest(encodePolicyStatement(unsigned));
    return encodePolicyStatement({ ...unsigned, signature: ed25519Sign(m.key.seed, digest) });
  });

  // Chain state.
  let slot = 100n;
  const marketAccount: MarketAccount = {
    address: market,
    marketId,
    salt,
    creator: creator.address,
    admin: admin.address,
    pendingAdmin: null,
    relay: relay.address,
    baseMint,
    quoteMint,
    baseVault,
    quoteVault,
    params,
    paramsDigest: paramsDigest(params),
    committeeDigest,
    prevCommitteeDigest: null,
    executors: Array.from({ length: 8 }, (_, i) => executors[i]?.address ?? null),
    receiptQuorum: quorumNeed,
    halted: false,
    beaconDelaySlots: 4,
    timelockSlots: 216_000n,
    execTimeoutSlots: 150n,
    settleTimeoutSlots: 1_500n,
    lastCommitted: 0n,
    lastSettled: 0n,
    lastProgressSlot: slot,
    feesAccrued: 0n,
    feesClaimed: 0n,
    prevReceipt: new Uint8Array(32),
    stateRoot: rng.bytes(32),
    pending: null,
  };
  const traders = new Map<Address, TraderAccount>();
  const batchAddress = (epoch: bigint): Address =>
    findProgramAddressSync(batchSeeds(market, epoch), program)[0];
  const traderAddress = (owner: Address): Address =>
    findProgramAddressSync(traderSeeds(market, owner), program)[0];
  /** Program addresses that hold only lamports someone sent, not yet the program's account. */
  const unclaimed = new Map<Address, AccountSnapshot>();

  // Epochs, keys and announcements.
  const epochs = new Map<bigint, EpochState>();
  let open = o.firstEpoch ?? 1n;

  const deal = (epoch: bigint): Dealt => {
    let epochPk: Uint8Array;
    let commitments: Uint8Array[] = [];
    if (scheme === 'dev') {
      epochPk = devEpochKey(keySeed, marketId, epoch).publicKey;
    } else {
      const s = (bytesToBigIntLE(rng.bytes(64)) % (L - 1n)) + 1n;
      const c0 = ed25519.Point.BASE.multiply(s).toBytes();
      epochPk = edwardsU(c0)!;
      commitments = [c0];
      for (let i = 1; i < THRESHOLD; i++) {
        commitments.push(
          ed25519.Point.BASE.multiply((bytesToBigIntLE(rng.bytes(64)) % (L - 1n)) + 1n).toBytes(),
        );
      }
    }
    const announcement: EpochKeyAnnouncement = {
      version: 1,
      market: marketBytes,
      epoch,
      committeeDigest,
      scheme,
      epochPk,
      commitments,
    };
    const keyDigest = announcementDigest(announcement);
    const acks = members.map((m, i) => {
      const pd = policyDigest(policies[i]!);
      return {
        member: m.index,
        policyDigest: pd,
        signature: ed25519Sign(m.key.seed, ackDigest(keyDigest, pd)),
      };
    });
    return { epoch, epochPk, bundle: encodeBundle({ announcement, acks }), keyDigest };
  };

  const ensureEpoch = (epoch: bigint): EpochState => {
    let e = epochs.get(epoch);
    if (e === undefined) {
      e = {
        epoch,
        key: deal(epoch),
        opensAtMs: 0,
        cutoffMs: 0,
        phase: 'scheduled',
        announcement: null,
        subs: [],
        leaves: null,
        balances: null,
        batch: null,
        header: null,
        receipt: null,
        outcome: null,
        artifacts: null,
      };
      epochs.set(epoch, e);
    }
    return e;
  };

  const announce = (e: EpochState): void => {
    const priceCommitment = rng.bytes(32);
    const unsigned: EpochAnnouncement = {
      market: marketBytes,
      epoch: e.epoch,
      opensAtMs: BigInt(e.opensAtMs),
      cutoffMs: BigInt(e.cutoffMs),
      band,
      priceCommitment,
      keyDigest: e.key.keyDigest,
      committeeDigest,
      relay: relay.pub,
      signature: new Uint8Array(64),
    };
    const signed = {
      ...unsigned,
      signature: ed25519Sign(relay.seed, epochAnnouncementDigest(unsigned)),
    };
    const binding = epochBinding(priceCommitment, e.key.keyDigest, committeeDigest);
    e.announcement = {
      raw: encodeAnnouncement(signed),
      binding,
      terms: termsDigest(band, binding),
      priceCommitment,
    };
  };

  const openEpoch = (epoch: bigint): EpochState => {
    const e = ensureEpoch(epoch);
    e.opensAtMs = Math.floor(clock());
    e.cutoffMs = e.opensAtMs + interval;
    e.phase = 'open';
    announce(e);
    for (let x = epoch + 1n; x <= epoch + BigInt(parkAhead); x++) ensureEpoch(x);
    return e;
  };
  openEpoch(open);

  // Stream: an event log per topic and fake sockets.
  let seq = 0n;
  const topicSeqs = new Map<string, bigint>();
  const streamId = hex.encode(rng.bytes(16));
  const sockets = new Set<FakeSocket>();

  const keyJson = (k: Dealt) => ({
    epoch: k.epoch,
    epoch_pk: hex.encode(k.epochPk),
    committee_digest: hex.encode(committeeDigest),
    bundle_b64: b64.encode(k.bundle),
  });
  const bandJson = (b: PriceBand) => ({ lo: b.lo, hi: b.hi, reference: b.reference });

  const publish = (event: Record<string, unknown>): void => {
    const topic = `market:${market}`;
    seq++;
    const ts = (topicSeqs.get(topic) ?? 0n) + 1n;
    topicSeqs.set(topic, ts);
    const frame = {
      v: 1,
      type: 'event',
      seq,
      topic,
      topic_seq: ts,
      at_ms: Math.floor(clock()),
      event,
    };
    for (const s of sockets) if (s.topics.has(topic)) s.deliver(frame);
  };

  const currentJson = () => {
    const e = epochs.get(open)!;
    return {
      market,
      server_time_ms: Math.floor(clock()),
      intake: intakeOpen ? 'open' : 'paused',
      ...(intakeOpen ? {} : { pause_reason: 'operator' }),
      open: {
        epoch: e.epoch,
        opens_at_ms: e.opensAtMs,
        cutoff_ms: e.cutoffMs,
        band: bandJson(band),
        binding: hex.encode(e.announcement!.binding),
        terms_digest: hex.encode(e.announcement!.terms),
        price_commitment: {
          digest: hex.encode(e.announcement!.priceCommitment),
          reference: band.reference,
          source: 'fixed',
          observations: [],
          commitment_b64: b64.encode(e.announcement!.priceCommitment),
        },
        announcement_b64: b64.encode(e.announcement!.raw),
        key: keyJson(e.key),
        real_slots_left: 'available',
      },
      park_window: [...epochs.values()]
        .filter((x) => x.epoch > open && x.epoch <= open + BigInt(parkAhead))
        .sort((a, b) => (a.epoch < b.epoch ? -1 : 1))
        .map((x) => keyJson(x.key)),
      previous: open > 1n ? { epoch: open - 1n, phase: phaseOf(epochs.get(open - 1n)) } : null,
      inflight: null,
      context_slot: slot,
    };
  };

  class FakeSocket extends EventTarget {
    static readonly CONNECTING = 0;
    static readonly OPEN = 1;
    static readonly CLOSING = 2;
    static readonly CLOSED = 3;
    readyState = 0;
    readonly url: string;
    readonly topics = new Set<string>();

    constructor(url: string | URL) {
      super();
      this.url = String(url);
      sockets.add(this);
      setTimeout(() => {
        if (this.readyState !== 0) return;
        this.readyState = 1;
        this.dispatchEvent(new Event('open'));
      }, 0);
    }

    send(data: string): void {
      let m: { op?: string; topics?: string[]; t?: number };
      try {
        m = JSON.parse(data) as typeof m;
      } catch {
        return;
      }
      if (m.op === 'subscribe') {
        for (const t of m.topics ?? []) this.topics.add(t);
        const seqs: Record<string, bigint> = {};
        for (const t of m.topics ?? []) seqs[t] = topicSeqs.get(t) ?? 0n;
        this.deliver({
          v: 1,
          type: 'subscribed',
          topics: m.topics ?? [],
          head_seq: seq,
          stream_id: streamId,
          topic_seqs: seqs,
        });
        for (const t of m.topics ?? []) {
          if (t === `market:${market}`) {
            this.deliver({
              v: 1,
              type: 'snapshot',
              topic: t,
              seq,
              topic_seq: topicSeqs.get(t) ?? 0n,
              current: currentJson(),
            });
          }
        }
      } else if (m.op === 'unsubscribe') {
        for (const t of m.topics ?? []) this.topics.delete(t);
      } else if (m.op === 'ping') {
        this.deliver({ v: 1, type: 'pong', t: m.t ?? 0, server_time_ms: Math.floor(clock()) });
      }
    }

    deliver(frame: unknown): void {
      const data = json(frame);
      setTimeout(() => {
        if (this.readyState === 1) this.dispatchEvent(new MessageEvent('message', { data }));
      }, 0);
    }

    close(code = 1000): void {
      if (this.readyState === 3) return;
      this.readyState = 3;
      sockets.delete(this);
      this.dispatchEvent(new CloseEvent('close', { code }));
    }
  }

  function phaseOf(e: EpochState | undefined): string {
    if (e === undefined) return 'scheduled';
    return e.phase;
  }

  // Sessions.
  const nonces = new Map<string, { expiresAtMs: number; used: boolean }>();
  const sessions = new Map<string, SessionState>();
  const domain = 'app.timescales.test';
  const uri = 'https://app.timescales.test';
  const chainId = cluster === 'mainnet-beta' ? 'mainnet' : cluster;

  const sessionJson = (s: SessionState) => ({
    session_key: hex.encode(s.key),
    wallet: s.wallet,
    market: s.market,
    expires_at_ms: s.expiresAtMs,
    quotas: {
      max_envelopes_per_wallet_per_epoch: o.maxEnvelopesPerWalletPerEpoch ?? 16,
      max_parked_per_wallet: o.maxParkedPerWallet ?? 64,
    },
  });

  const authorize = (r: FakeRequest): SessionState | Response => {
    const m = /^TimescalesSession ([0-9a-f]{64})\.(\d+)\.([0-9a-f]{128})$/.exec(
      r.headers.get('authorization') ?? '',
    );
    if (m === null) return respondProblem(problem('SESSION_UNKNOWN', 'no session'));
    const s = sessions.get(m[1]!);
    if (s === undefined) return respondProblem(problem('SESSION_UNKNOWN', 'unknown session'));
    if (s.revoked) return respondProblem(problem('SESSION_REVOKED', 'revoked'));
    if (s.expiresAtMs <= clock()) return respondProblem(problem('SESSION_EXPIRED', 'expired'));
    const ts = BigInt(m[2]!);
    if (ts > BigInt(Math.floor(clock())) + 30_000n || ts < BigInt(Math.floor(clock())) - 30_000n) {
      return respondProblem(problem('SKEW', 'timestamp outside ±30 s'));
    }
    const search = r.query.toString();
    const digest = sessionRequestDigest(
      r.method,
      r.path + (search.length > 0 ? `?${search}` : ''),
      ts,
      r.body ?? new Uint8Array(0),
    );
    if (!verifyStrict(s.key, digest, hex.decode(m[3]!, 64)) || ts <= s.lastTs) {
      return respondProblem(problem('BAD_SIGNATURE', 'bad session signature or replay'));
    }
    s.lastTs = ts;
    return s;
  };

  // Intake.
  let intakeOpen = true;
  let failing = 0;
  let beforeNext: (() => void) | null = null;
  const submitted: { epoch: bigint; commitment: Uint8Array; duplicate: boolean }[] = [];
  const capacity = o.capacity ?? params.maxBatchEnvelopes;

  const refusal = (code: ErrorCode, epoch: bigint, digest: Uint8Array) => {
    const unsigned = {
      market: marketBytes,
      epoch,
      envelopeDigest: digest,
      code: REFUSAL_CODES[code] ?? 0,
      atMs: BigInt(Math.floor(clock())),
      relay: relay.pub,
      signature: new Uint8Array(64),
    };
    return encodeRelayRefusal({
      ...unsigned,
      signature: ed25519Sign(relay.seed, relayRefusalDigest(unsigned)),
    });
  };

  const resultJson = (h: HeldSubmission, duplicate: boolean) => ({
    status: h.epoch > open ? 'parked' : 'accepted',
    market,
    epoch: h.epoch,
    commitment: hex.encode(h.commitment),
    envelope_digest: hex.encode(h.envelopeDigest),
    received_at_ms: Math.floor(clock()),
    promise_b64: b64.encode(h.promise),
    duplicate,
  });

  type Outcome = { ok: unknown } | { error: Record<string, unknown>; status: number };

  const intake = (bytes: Uint8Array, s: SessionState): Outcome => {
    const refuse = (
      code: ErrorCode,
      detail: string,
      extra?: Record<string, unknown>,
      refusalBytes?: Uint8Array,
    ): Outcome => {
      const p = problem(code, detail, {
        ...(extra ?? {}),
        ...(refusalBytes !== undefined ? { refusal_b64: b64.encode(refusalBytes) } : {}),
      });
      return {
        status: p.status,
        error: {
          ...p.body,
          ...(refusalBytes !== undefined ? { refusal_b64: b64.encode(refusalBytes) } : {}),
        },
      };
    };
    let sub;
    try {
      sub = decodeSubmission(bytes);
    } catch {
      return refuse('DECODE_FAILED', 'not a submission');
    }
    if (
      !equal(sub.trader, s.key) ||
      !verifyStrict(sub.trader, submissionDigest(sub.envelope, sub.trader), sub.signature)
    ) {
      return refuse('BAD_SIGNATURE', 'submission signature');
    }
    const env = decodeEnvelope(sub.envelope);
    if (env.market !== marketId) return refuse('WRONG_MARKET', 'another market');
    const digest = envelopeDigest(sub.envelope);
    const epoch = env.epoch;
    const known = epochs
      .get(epoch)
      ?.subs.find((h) => equal(h.commitment, env.commitment) && h.wallet === s.wallet);
    if (known !== undefined) {
      if (equal(known.submission, bytes) || equal(known.envelopeDigest, digest)) {
        submitted.push({ epoch, commitment: env.commitment, duplicate: true });
        return { ok: resultJson(known, true) };
      }
      return refuse('DUPLICATE_COMMITMENT', 'same commitment, other bytes', {
        promise_b64: b64.encode(known.promise),
      });
    }
    if (epoch < open || (epoch === open && clock() >= epochs.get(open)!.cutoffMs)) {
      return refuse(
        'EPOCH_CLOSED',
        'cutoff passed',
        { next_epoch: (open + 1n).toString() },
        refusal('EPOCH_CLOSED', epoch, digest),
      );
    }
    if (epoch > open + BigInt(parkAhead)) return refuse('EPOCH_TOO_FAR', 'beyond the park window');
    const e = epochs.get(epoch);
    if (e === undefined) return refuse('EPOCH_KEY_UNAVAILABLE', 'no key yet');
    if (!intakeOpen)
      return refuse(
        'INTAKE_PAUSED',
        'paused',
        { reason: 'operator' },
        refusal('INTAKE_PAUSED', epoch, digest),
      );
    if (e.subs.length >= capacity)
      return refuse('BATCH_FULL', 'full', undefined, refusal('BATCH_FULL', epoch, digest));
    const perEpoch = e.subs.filter((h) => h.wallet === s.wallet).length;
    const parked = [...epochs.values()]
      .filter((x) => x.epoch > open)
      .flatMap((x) => x.subs)
      .filter((h) => h.wallet === s.wallet).length;
    if (
      perEpoch >= (o.maxEnvelopesPerWalletPerEpoch ?? 16) ||
      (epoch > open && parked >= (o.maxParkedPerWallet ?? 64))
    ) {
      return refuse('QUOTA_EXCEEDED', 'quota', undefined, refusal('QUOTA_EXCEEDED', epoch, digest));
    }
    const unsigned = {
      market: marketBytes,
      epoch,
      commitment: env.commitment,
      envelopeDigest: digest,
      relay: relay.pub,
      signature: new Uint8Array(64),
    };
    const promise = encodePromiseV2({
      ...unsigned,
      signature: ed25519Sign(relay.seed, promiseV2Digest(unsigned)),
    });
    const h: HeldSubmission = {
      epoch,
      commitment: env.commitment,
      envelopeDigest: digest,
      submission: bytes,
      promise,
      wallet: s.wallet,
    };
    e.subs.push(h);
    submitted.push({ epoch, commitment: env.commitment, duplicate: false });
    return { ok: resultJson(h, false) };
  };

  // REST routes.
  const marketParam = (r: FakeRequest): Response | null =>
    r.params.market === market ? null : respondProblem(problem('MARKET_UNKNOWN', 'unknown market'));

  const summaryJson = () => ({
    market,
    name: 'TEST/USD',
    base_symbol: 'TEST',
    quote_symbol: 'USD',
    state: 'running',
    halted: marketAccount.halted,
    last_clearing: null,
  });

  const detailJson = () => ({
    ...summaryJson(),
    market_id: marketId,
    creator: creator.address,
    admin: admin.address,
    params: {
      market: params.market,
      base_lot_size: params.baseLotSize,
      tick_size: params.tickSize,
      band_half_width: params.bandHalfWidth,
      max_order_lots_log2: params.maxOrderLotsLog2,
      max_orders_per_trader: params.maxOrdersPerTrader,
      max_batch_envelopes: params.maxBatchEnvelopes,
      max_order_lifetime: params.maxOrderLifetime,
      maker_fee_bps: params.makerFeeBps,
      taker_fee_bps: params.takerFeeBps,
      flow: params.flow === 0 ? 'single_book' : 'dual_flow',
      rationing: params.rationing === 0 ? 'lottery' : 'pro_rata',
      commitment_scheme: 'sha256',
    },
    params_b64: b64.encode(encodeMarketParams(params)),
    params_digest: hex.encode(marketAccount.paramsDigest),
    base_mint: baseMint,
    quote_mint: quoteMint,
    base_vault: baseVault,
    quote_vault: quoteVault,
    base_decimals: 6,
    quote_decimals: 6,
    relay: marketAccount.relay,
    executors: marketAccount.executors.filter((x) => x !== null),
    receipt_quorum: marketAccount.receiptQuorum,
    committee: {
      digest: hex.encode(committeeDigest),
      description_b64: b64.encode(description),
      threshold: THRESHOLD,
      members: members.map((m) => ({
        index: m.index,
        identity: hex.encode(m.key.pub),
        transport: hex.encode(m.transport),
      })),
      prev_digest: null,
      prev_description_b64: null,
      policies_b64: policies.map((p) => b64.encode(p)),
    },
    timing: {
      epoch_interval_ms: interval,
      beacon_delay_slots: marketAccount.beaconDelaySlots,
      exec_timeout_slots: marketAccount.execTimeoutSlots,
      settle_timeout_slots: marketAccount.settleTimeoutSlots,
      timelock_slots: marketAccount.timelockSlots,
      max_park_ahead_epochs: parkAhead,
    },
    relay_policy: {
      padding: { kind: 'power_of_two', min: 8 },
      ack: 'immediate',
      max_envelopes_per_wallet_per_epoch: o.maxEnvelopesPerWalletPerEpoch ?? 16,
      max_parked_per_wallet: o.maxParkedPerWallet ?? 64,
      min_available_value_quote: 0n,
      min_value_per_envelope_quote: 0n,
      require_trader_account: false,
      idle_policy: 'commit',
    },
    market_id_salt: hex.encode(salt),
    session_domains: [domain],
    mint_authorities: {
      base: { mint: mintAuthority, freeze: null },
      quote: { mint: mintAuthority, freeze: null },
    },
    books:
      params.flow === 0
        ? [{ book: 'single', label: 'Single book' }]
        : [
            { book: 'maker_ask_taker_bid', label: 'Maker asks, taker bids' },
            { book: 'maker_bid_taker_ask', label: 'Maker bids, taker asks' },
          ],
    pending_change: null,
    program: { upgrade_authority: upgradeAuthority, last_deploy_slot: 1n },
    chain: {
      last_committed: marketAccount.lastCommitted,
      last_settled: marketAccount.lastSettled,
      state_root: hex.encode(marketAccount.stateRoot),
      prev_receipt: hex.encode(marketAccount.prevReceipt),
      context_slot: slot,
    },
  });

  const publicPhase = (e: EpochState): string => (e.phase === 'posted' ? 'posted' : e.phase);

  const epochDetailJson = (e: EpochState) => {
    const b = e.batch;
    const quorum = b === null ? 0 : popcount(b.cosignBitmap);
    const artifactsPublic = b !== null && b.receipt !== null && quorum >= quorumNeed;
    return {
      market,
      epoch: e.epoch,
      phase: publicPhase(e),
      opens_at_ms: e.opensAtMs,
      cutoff_ms: e.cutoffMs,
      envelope_count: b?.count ?? null,
      clearing: null,
      fill_count: e.outcome?.fillCount ?? null,
      terminal_at_ms: null,
      abort_reason: b?.abortReason ?? null,
      tee_platform: 'simulated',
      band: bandJson(band),
      terms_digest: hex.encode(e.announcement?.terms ?? new Uint8Array(32)),
      announcement_b64: b64.encode(e.announcement?.raw ?? new Uint8Array(0)),
      key: keyJson(e.key),
      batch:
        b === null
          ? null
          : {
              address: b.address,
              status: b.status,
              root: hex.encode(b.root),
              count: b.count,
              terms_digest: hex.encode(b.termsDigest),
              commit_slot: b.commitSlot,
              commit_signature: b58.encode(new Uint8Array(64).fill(1)),
              beacon: b.beacon === null ? null : hex.encode(b.beacon),
              beacon_slots: b.beaconSlots,
              reveal_slot: b.revealSlot,
              header_digest: b.headerDigest === null ? null : hex.encode(b.headerDigest),
              receipt_digest: b.receipt === null ? null : hex.encode(b.receipt),
              outcome_digest: b.outcomeDigest === null ? null : hex.encode(b.outcomeDigest),
              cosigners: [],
              quorum: { have: quorum, need: quorumNeed },
              settlement_count: b.receipt === null ? null : b.settlementCount,
              fees: b.receipt === null ? null : b.fees,
              context_slot: slot,
            },
      artifacts_public: artifactsPublic,
      header_b64: e.header === null ? null : b64.encode(e.header),
      receipt_b64: e.receipt === null ? null : b64.encode(e.receipt),
      receipt: null,
      settlement: null,
      txs: [],
      abort: b?.abortReason == null ? null : { reason: b.abortReason, detail: 'aborted' },
    };
  };

  fake.respond('GET', '/v1/info', 200, () => ({
    api_version: '1.0',
    protocol_version: 1,
    header_version: 2,
    node_version: 'fake',
    git_sha: '0000000',
    profile,
    cluster,
    genesis_hash: genesisHash,
    program_id: program,
    server_time_ms: Math.floor(clock()),
    markets: [market],
    trust: {
      enclave: 'simulated',
      quote_generation: 'simulated',
      quote_verification: 'simulated_vendor',
      key_generation: 'trusted_dealer_feldman',
      dkg: false,
      mpc: 'disabled',
      reference_price: 'fixed',
      receipt_quorum: quorumNeed,
      registered_executors: executors.length,
      notes: ['Simulated enclave: the operator can read sealed orders.'],
    },
    limits: { submit_max_body_bytes: 65536, session_max_ttl_s: 86400 },
  }));
  fake.respond('GET', '/v1/markets', 200, () => ({ items: [summaryJson()] }));
  fake.respond(
    'GET',
    '/v1/markets/{market}',
    200,
    (r: FakeRequest) => marketParam(r) ?? detailJson(),
  );
  fake.respond(
    'GET',
    '/v1/markets/{market}/epochs/current',
    200,
    (r: FakeRequest) => marketParam(r) ?? currentJson(),
  );
  fake.respond(
    'GET',
    '/v1/markets/{market}/committee/policies',
    200,
    (r: FakeRequest) =>
      marketParam(r) ?? {
        items: policies.map((p, i) => ({ member: i + 1, statement_b64: b64.encode(p) })),
      },
  );
  const epochOf = (r: FakeRequest): EpochState | Response => {
    const bad = marketParam(r);
    if (bad !== null) return bad;
    const e = epochs.get(BigInt(r.params.epoch ?? '0'));
    return e ?? respondProblem(problem('NOT_FOUND', 'no such epoch'));
  };
  const withheldDetails = new Set<bigint>();
  fake.respond('GET', '/v1/markets/{market}/epochs/{epoch}', 200, (r: FakeRequest) => {
    const e = epochOf(r);
    if (e instanceof Response) return e;
    return withheldDetails.has(e.epoch)
      ? respondProblem(problem('NOT_YET_AVAILABLE', 'withheld'))
      : epochDetailJson(e);
  });
  fake.respond('GET', '/v1/markets/{market}/epochs/{epoch}/key', 200, (r: FakeRequest) => {
    const e = epochOf(r);
    return e instanceof Response ? e : keyJson(e.key);
  });
  const withheldLeaves = new Set<bigint>();
  fake.respond('GET', '/v1/markets/{market}/epochs/{epoch}/leaves.bin', 200, (r: FakeRequest) => {
    const e = epochOf(r);
    if (e instanceof Response) return e;
    const leaves = withheldLeaves.has(e.epoch) ? null : e.leaves;
    return (
      leaves ??
      respondProblem(
        problem('NOT_YET_AVAILABLE', 'not committed', { available_after: 'committed' }),
      )
    );
  });
  fake.respond('GET', '/v1/markets/{market}/epochs/{epoch}/artifacts', 200, (r: FakeRequest) => {
    const e = epochOf(r);
    if (e instanceof Response) return e;
    const b = e.batch;
    if (b === null || e.artifacts === null || popcount(b.cosignBitmap) < quorumNeed) {
      return respondProblem(
        problem('NOT_YET_AVAILABLE', 'quorum not on chain', { available_after: 'quorum' }),
      );
    }
    return {
      market,
      epoch: e.epoch,
      header_b64: b64.encode(e.header!),
      receipt_b64: b64.encode(e.receipt!),
      artifacts_b64: b64.encode(e.artifacts),
      attestation_b64: null,
      attestation_platform: 'simulated',
      cosignatures: [],
    };
  });
  const balanceOverrides = new Map<bigint, Uint8Array>();
  fake.respond('GET', '/v1/markets/{market}/epochs/{epoch}/balances', 200, (r: FakeRequest) => {
    const e = epochOf(r);
    if (e instanceof Response) return e;
    const b = e.batch;
    if (
      b === null ||
      e.balances === null ||
      b.receipt === null ||
      popcount(b.cosignBitmap) < quorumNeed
    ) {
      return respondProblem(
        problem('NOT_YET_AVAILABLE', 'artifacts are not public', { available_after: 'quorum' }),
      );
    }
    return balanceOverrides.get(e.epoch) ?? e.balances;
  });
  fake.respond('GET', '/v1/sessions/nonce', 200, () => {
    const nonce = rng.bytes(16);
    nonces.set(hex.encode(nonce), { expiresAtMs: clock() + 300_000, used: false });
    return {
      nonce: hex.encode(nonce),
      expires_at_ms: Math.floor(clock()) + 300_000,
      domain,
      uri,
      chain_id: chainId,
      statement: SESSION_STATEMENT,
      template_version: 1,
    };
  });
  fake.respond('POST', '/v1/sessions', 201, (r: FakeRequest) => {
    const req = JSON.parse(new TextDecoder().decode(r.body ?? new Uint8Array(0))) as {
      wallet: string;
      message: string;
      signature_b64: string;
      method: 'sign_in' | 'sign_message';
    };
    for (const s of sessions.values()) {
      if (s.grant === req.message && !s.revoked) {
        return new Response(json(sessionJson(s)), {
          status: 200,
          headers: { 'content-type': 'application/json' },
        });
      }
    }
    if (req.method === 'sign_message' && profile === 'production') {
      return respondProblem(problem('SESSION_METHOD_REFUSED', 'sign-in only'));
    }
    let grant;
    try {
      grant = parseSessionMessage(req.message);
    } catch {
      return respondProblem(problem('SESSION_TEMPLATE_INVALID', 'not a session grant'));
    }
    if (grant.domain !== domain)
      return respondProblem(problem('SESSION_DOMAIN_MISMATCH', 'domain'));
    const n = nonces.get(hex.encode(grant.nonce));
    if (n === undefined || n.used || n.expiresAtMs < clock()) {
      return respondProblem(problem('SESSION_NONCE_INVALID', 'nonce'));
    }
    if (
      grant.wallet !== req.wallet ||
      !verifyStrict(b58.decode(req.wallet, 32), utf8(req.message), b64.decode(req.signature_b64))
    ) {
      return respondProblem(problem('BAD_SIGNATURE', 'grant signature'));
    }
    n.used = true;
    const s: SessionState = {
      key: grant.sessionKey,
      wallet: grant.wallet,
      market: grant.market,
      expiresAtMs: grant.expiresAtMs,
      lastTs: 0n,
      revoked: false,
      grant: req.message,
    };
    sessions.set(hex.encode(s.key), s);
    return sessionJson(s);
  });
  fake.respond('GET', '/v1/sessions/current', 200, (r: FakeRequest) => {
    const s = authorize(r);
    return s instanceof Response ? s : sessionJson(s);
  });
  fake.respond('DELETE', '/v1/sessions/current', 204, (r: FakeRequest) => {
    const s = authorize(r);
    if (s instanceof Response) return s;
    s.revoked = true;
    return null;
  });
  const submissionRoute = (single: boolean) => (r: FakeRequest) => {
    const bad = marketParam(r);
    if (bad !== null) return bad;
    const s = authorize(r);
    if (s instanceof Response) return s;
    const hook = beforeNext;
    beforeNext = null;
    hook?.();
    const body = JSON.parse(new TextDecoder().decode(r.body ?? new Uint8Array(0))) as {
      submission_b64?: string;
      submissions_b64?: string[];
    };
    const items = (single ? [body.submission_b64 ?? ''] : (body.submissions_b64 ?? [])).map((x) =>
      intake(b64.decode(x), s),
    );
    if (failing > 0) {
      failing--;
      return respondProblem(problem('OVERLOADED', 'shed after processing'));
    }
    if (single) {
      const item = items[0]!;
      return 'ok' in item
        ? new Response(json(item.ok), {
            status: 202,
            headers: { 'content-type': 'application/json' },
          })
        : new Response(json(item.error), {
            status: item.status,
            headers: { 'content-type': 'application/problem+json' },
          });
    }
    return new Response(
      json({ items: items.map((i) => ('ok' in i ? { ok: i.ok } : { error: i.error })) }),
      { status: 207, headers: { 'content-type': 'application/json' } },
    );
  };
  fake.respond('POST', '/v1/markets/{market}/submissions', 202, submissionRoute(true));
  fake.respond('POST', '/v1/markets/{market}/submissions/batch', 207, submissionRoute(false));
  fake.respond('GET', '/v1/markets/{market}/parked', 200, (r: FakeRequest) => {
    const s = authorize(r);
    if (s instanceof Response) return s;
    const items = [...epochs.values()]
      .filter((e) => e.epoch > open)
      .flatMap((e) => e.subs.filter((h) => h.wallet === s.wallet))
      .map((h) => ({ epoch: h.epoch, commitment: hex.encode(h.commitment) }));
    return { items };
  });
  fake.respond('POST', '/v1/markets/{market}/parked/retract', 200, (r: FakeRequest) => {
    const s = authorize(r);
    if (s instanceof Response) return s;
    const { commitment } = JSON.parse(new TextDecoder().decode(r.body ?? new Uint8Array(0))) as {
      commitment: string;
    };
    const c = hex.decode(commitment, 32);
    const removed: bigint[] = [];
    let keptOpen: bigint | null = null;
    for (const e of epochs.values()) {
      const mine = (h: HeldSubmission) => h.wallet === s.wallet && equal(h.commitment, c);
      if (e.epoch > open && e.subs.some(mine)) {
        e.subs = e.subs.filter((h) => !mine(h));
        removed.push(e.epoch);
      } else if (e.epoch === open && e.subs.some(mine)) {
        keptOpen = open;
      }
    }
    removed.sort((a, b) => (a < b ? -1 : 1));
    return { removed_epochs: removed, kept_open_epoch: keptOpen };
  });

  // The RPC.
  const observed = <T>(value: T) => ({
    value,
    contextSlot: slot,
    commitment: 'confirmed' as const,
  });
  const rpc: TimescalesRpc = {
    async market(a, minContextSlot) {
      if (a !== market) {
        throw new TimescalesError({
          kind: 'verify',
          code: 'account_missing',
          message: `no market at ${a}`,
        });
      }
      if (minContextSlot !== undefined && minContextSlot > slot) {
        throw new TimescalesError({
          kind: 'network',
          code: 'min_context_slot_not_reached',
          message: 'behind',
          retryable: true,
        });
      }
      return observed(structuredClone(marketAccount));
    },
    async trader(a) {
      const raw = unclaimed.get(a);
      if (raw !== undefined) return programAccountAt('trader', a, observed(raw));
      for (const t of traders.values()) if (t.address === a) return observed(structuredClone(t));
      return null;
    },
    async batch(a) {
      const raw = unclaimed.get(a);
      if (raw !== undefined) return programAccountAt('batch', a, observed(raw));
      for (const e of epochs.values()) {
        if (e.batch !== null && e.batch.address === a) return observed(structuredClone(e.batch));
      }
      return null;
    },
    async account(a) {
      if (a === baseMint || a === quoteMint) return observed(mintBytes(6));
      if (a === programDataAddress(program)) return observed(programData);
      return null;
    },
    async tokenBalance() {
      return 0n;
    },
    async slot() {
      return slot;
    },
    async genesisHash() {
      return genesisHash;
    },
    async blockTime() {
      return Math.floor(clock());
    },
  };

  const tick = (): bigint => {
    slot += 1n;
    return slot;
  };

  const node: FakeNode = {
    api: fake.api,
    fake,
    rpc,
    WebSocket: FakeSocket as unknown as typeof WebSocket,
    streamUrl: STREAM_URL,
    pins: { programId: program, genesisHash, cluster, market, upgradeAuthority },
    market,
    marketId,
    program,
    params,
    band,
    relay: relay.address,
    get open() {
      return open;
    },
    held(epoch) {
      return [...(epochs.get(epoch)?.subs ?? [])];
    },
    submitted,
    closeEpoch() {
      const closing = epochs.get(open)!;
      closing.phase = 'closed';
      publish({ kind: 'epoch.closed', market, epoch: closing.epoch });
      open += 1n;
      const e = openEpoch(open);
      const dealt = open + BigInt(parkAhead);
      publish({ kind: 'key.published', market, epoch: dealt });
      publish({
        kind: 'epoch.opened',
        market,
        epoch: e.epoch,
        opens_at_ms: e.opensAtMs,
        cutoff_ms: e.cutoffMs,
        band: bandJson(band),
        terms_digest: hex.encode(e.announcement!.terms),
        announcement_b64: b64.encode(e.announcement!.raw),
        key: keyJson(e.key),
      });
    },
    commit(epoch, c) {
      const e = epochs.get(epoch)!;
      const omit = c?.omit ?? [];
      const substitute = c?.substitute ?? [];
      const leaves: BatchLeaf[] = e.subs
        .filter((h) => !omit.some((x) => equal(x, h.commitment)))
        .map((h) => ({
          commitment: h.commitment,
          envelopeDigest: substitute.some((x) => equal(x, h.commitment))
            ? rng.bytes(32)
            : h.envelopeDigest,
        }));
      for (let i = 0; i < (c?.cover ?? 1); i++)
        leaves.push({ commitment: rng.bytes(32), envelopeDigest: rng.bytes(32) });
      e.leaves = encodeLeaves(leaves);
      e.balances = encodeBalanceSheet(
        [...traders.values()].map((t) => {
          const a = availableFor(t, epoch);
          return { trader: b58.decode(t.owner, 32), base: a.base, quote: a.quote };
        }),
      );
      e.phase = 'committed';
      unclaimed.delete(batchAddress(epoch));
      e.batch = {
        address: batchAddress(epoch),
        status: 'committed',
        abortReason: null,
        cosignBitmap: 0,
        cosignCount: 0,
        market,
        epoch,
        root: batchRootV2(leaves),
        count: leaves.length,
        termsDigest: c?.terms ?? e.announcement!.terms,
        commitSlot: tick(),
        beaconSlots: null,
        beacon: null,
        revealSlot: null,
        receiptSlot: null,
        headerDigest: null,
        receipt: null,
        outcomeDigest: null,
        nextStateRoot: null,
        settlementRoot: null,
        settlementCount: 0,
        fees: 0n,
        verifiedCount: 0,
        appliedCount: 0,
      };
      marketAccount.lastCommitted = epoch;
      marketAccount.lastProgressSlot = slot;
      publish({
        kind: 'epoch.committed',
        market,
        epoch,
        root: hex.encode(e.batch.root),
        count: e.batch.count,
        slot,
        signature: b58.encode(new Uint8Array(64).fill(1)),
      });
    },
    reveal(epoch) {
      const e = epochs.get(epoch)!;
      const b = e.batch!;
      const s = tick();
      b.status = 'beacon_revealed';
      b.beacon = rng.bytes(32);
      b.beaconSlots = [b.commitSlot + 4n, b.commitSlot + 8n];
      b.revealSlot = s;
      e.phase = 'revealed';
      publish({
        kind: 'epoch.revealed',
        market,
        epoch,
        beacon: hex.encode(b.beacon),
        beacon_slots: b.beaconSlots,
        finalized: true,
      });
    },
    post(epoch, p) {
      const e = epochs.get(epoch)!;
      if (e.batch?.status === 'committed') node.reveal(epoch);
      const b = e.batch!;
      const header = encodeHeader({
        version: 2,
        market: marketId,
        epoch,
        params,
        band,
        priceCommitmentOrBinding: e.announcement!.binding,
        envelopeCount: b.count,
        batchRoot: b.root,
        beacon: b.beacon!,
        priorStateRoot: marketAccount.stateRoot,
        balancesRoot: new Uint8Array(32),
        prevReceipt: marketAccount.prevReceipt,
      });
      const fills: Fill[] = p.fills.map((f) => ({
        commitment: f.commitment,
        trader: f.trader,
        book: bookFor(params.flow, f.side, f.role),
        side: f.side,
        role: f.role,
        quantity: f.quantity,
        tick: f.tick,
      }));
      const cancelled = p.cancelled ?? [];
      const settlement = settle(params, epoch, fills);
      const books = new Map<BookId, { tick: bigint; volume: bigint }>();
      for (const f of fills) {
        const c = books.get(f.book) ?? { tick: f.tick, volume: 0n };
        if (f.side === 0) c.volume += f.quantity;
        books.set(f.book, c);
      }
      const outcome: ExecutionOutcome = {
        market: marketId,
        epoch,
        headerDigest: headerDigest(header),
        clearing: [...books.entries()]
          .sort(([a], [b2]) => a - b2)
          .map(([book, c]) => ({ book, tick: c.tick, volume: c.volume })),
        fillCount: fills.length,
        fillsRoot: fillsRoot(fills),
        cancelledRoot: cancelledRoot(cancelled),
        nextStateRoot: rng.bytes(32),
        settlementCount: settlement.deltas.length,
        settlementRoot: settlementRoot(settlement.deltas),
        fees: settlement.fees,
      };
      const poster = executors[0]!;
      const unsigned = encodeReceipt({
        version: 1,
        outcome,
        backend: 'tee',
        executor: poster.pub,
        attestation: rng.bytes(32),
        proof: rng.bytes(32),
        trace: rng.bytes(32),
        signature: new Uint8Array(64),
      });
      const digest = receiptDigest(unsigned);
      const receipt = concat(
        unsigned.subarray(0, unsigned.length - 64),
        ed25519Sign(poster.seed, digest),
      );
      e.header = header;
      e.receipt = receipt;
      e.outcome = outcome;
      e.artifacts = encodeArtifacts({ fills, cancelled, settlement });
      e.phase = 'posted';
      b.status = 'receipt_posted';
      b.headerDigest = headerDigest(header);
      b.receipt = digest;
      b.outcomeDigest = outcomeDigest(outcome);
      b.nextStateRoot = outcome.nextStateRoot;
      b.settlementRoot = outcome.settlementRoot;
      b.settlementCount = outcome.settlementCount;
      b.fees = outcome.fees;
      b.receiptSlot = tick();
      b.cosignBitmap = 1;
      b.cosignCount = 1;
      publish({
        kind: 'epoch.posted',
        market,
        epoch,
        receipt_digest: hex.encode(digest),
        clearing: outcome.clearing.map((c) => ({
          book: BOOK_NAMES[c.book],
          tick: c.tick,
          volume: c.volume,
        })),
        fill_count: outcome.fillCount,
        settlement_count: outcome.settlementCount,
      });
      publish({ kind: 'epoch.quorum', market, epoch, have: 1, need: quorumNeed });
    },
    cosign(epoch) {
      const b = epochs.get(epoch)!.batch!;
      const next = executors.findIndex((_, i) => (b.cosignBitmap & (1 << i)) === 0);
      if (next < 0) return;
      b.cosignBitmap |= 1 << next;
      b.cosignCount += 1;
      tick();
      publish({ kind: 'epoch.cosigned', market, epoch, executor: executors[next]!.address });
      publish({
        kind: 'epoch.quorum',
        market,
        epoch,
        have: popcount(b.cosignBitmap),
        need: quorumNeed,
      });
    },
    settle(epoch, s) {
      const e = epochs.get(epoch)!;
      const b = e.batch!;
      b.verifiedCount = b.settlementCount;
      b.status = 'verified';
      tick();
      publish({
        kind: 'epoch.settlement',
        market,
        epoch,
        stage: 'verifying',
        done: b.verifiedCount,
        total: b.settlementCount,
      });
      if (s?.stopAt === 'verifying') return;
      b.appliedCount = b.settlementCount;
      publish({
        kind: 'epoch.settlement',
        market,
        epoch,
        stage: 'applying',
        done: b.appliedCount,
        total: b.settlementCount,
      });
      if (s?.stopAt === 'applying') return;
      b.status = 'settled';
      e.phase = 'settled';
      marketAccount.lastSettled = epoch;
      marketAccount.prevReceipt = b.receipt!;
      marketAccount.stateRoot = b.nextStateRoot!;
      marketAccount.lastProgressSlot = tick();
      publish({ kind: 'epoch.settled', market, epoch, slot });
    },
    abort(epoch, reason = 'exec_timeout') {
      const e = epochs.get(epoch)!;
      const b = e.batch!;
      b.status = 'aborted';
      b.abortReason = reason;
      e.phase = 'aborted';
      marketAccount.lastSettled = epoch;
      marketAccount.lastProgressSlot = tick();
      publish({ kind: 'epoch.aborted', market, epoch, reason });
    },
    invalidateParked(list) {
      for (const epoch of list) {
        const e = epochs.get(epoch);
        if (e === undefined || epoch <= open) continue;
        e.key = deal(epoch);
        e.subs = [];
      }
      publish({ kind: 'parked.invalidated', market, epochs: list });
    },
    withholdLeaves(epoch, withheld) {
      if (withheld) withheldLeaves.add(epoch);
      else withheldLeaves.delete(epoch);
    },
    withholdDetail(epoch, withheld) {
      if (withheld) withheldDetails.add(epoch);
      else withheldDetails.delete(epoch);
    },
    overrideBalances(epoch, sheet) {
      if (sheet === null) balanceOverrides.delete(epoch);
      else balanceOverrides.set(epoch, sheet);
    },
    emit(event) {
      publish(event);
    },
    fund(owner, base, quote) {
      const address = traderAddress(owner);
      unclaimed.delete(address);
      traders.set(owner, {
        address,
        market,
        owner,
        base,
        quote,
        requestedBase: 0n,
        requestedQuote: 0n,
        requestEpoch: 0n,
        lastLeafEpoch: 0n,
        lastChangeSlot: tick(),
        floorEpoch: 0n,
        floorBase: 0n,
        floorQuote: 0n,
      });
    },
    prefund(address) {
      const created =
        [...traders.values()].some((t) => t.address === address) ||
        [...epochs.values()].some((e) => e.batch?.address === address);
      if (created || unclaimed.has(address)) return;
      unclaimed.set(address, {
        owner: SYSTEM_PROGRAM,
        lamports: 890_880n,
        executable: false,
        data: new Uint8Array(0),
      });
    },
    failSubmissions(n) {
      failing = n;
    },
    onNextSubmission(f) {
      beforeNext = f;
    },
    setIntake(isOpen) {
      intakeOpen = isOpen;
      publish({ kind: isOpen ? 'intake.resumed' : 'intake.paused', market });
    },
    dropSockets(code = 1006) {
      for (const s of [...sockets]) s.close(code);
    },
    subscribers(topic) {
      return [...sockets].filter((s) => s.readyState === 1 && s.topics.has(topic)).length;
    },
    secrets: {
      relay: relay.seed,
      executors: executors.map((x) => x.seed),
      members: members.map((m) => ({ index: m.index, seed: m.key.seed })),
      upgradeAuthority,
    },
  };
  return node;
}

function popcount(x: number): number {
  let n = 0;
  for (let v = x >>> 0; v !== 0; v &= v - 1) n++;
  return n;
}
