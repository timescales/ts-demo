import type { Address } from '@solana/kit';
import { b58 } from '../encoding/base58.js';
import { hex } from '../encoding/hex.js';
import { utf8 } from '../encoding/bytes.js';

/**
 * A session grant: the wallet authorises `sessionKey` to submit
 * envelopes for `program` (and `market`, or every market when null).
 */
export interface SessionGrant {
  domain: string;
  wallet: Address;
  statement: string;
  uri: string;
  chainId: 'localnet' | 'devnet' | 'mainnet';
  nonce: Uint8Array;
  issuedAtMs: number;
  expiresAtMs: number;
  sessionKey: Uint8Array;
  program: Address;
  market: Address | null;
}

/** The statement the SDK asks wallets to show. */
export const SESSION_STATEMENT =
  'Authorize a Timescales trading session. This key can submit encrypted orders for this wallet. ' +
  'Timescales executes only orders this wallet signs. It cannot sign orders or move funds.';

/** Largest grant text the node accepts. */
export const MAX_SESSION_TEXT_BYTES = 1024;

export class SessionTextError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'SessionTextError';
  }
}

const HEADER_SUFFIX = ' wants you to sign in with your Solana account:';
const DOMAIN_RE =
  /^(?:[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?)*|\[[0-9A-Fa-f:.]+\])(?::\d{1,5})?$/;
const URI_RE = /^[A-Za-z][A-Za-z0-9+.-]*:[\x21-\x7e]+$/;
const NONCE_RE = /^[0-9a-f]{32}$/;
const KEY_RE = /^[0-9a-f]{64}$/;
const TIME_RE =
  /^(\d{4})-(\d{2})-(\d{2})[Tt](\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,9}))?(?:([Zz])|([+-])(\d{2}):(\d{2}))$/;
const MAX_TIME_MS = Date.UTC(9999, 11, 31, 23, 59, 59, 999);

/** Fields after the statement, in the order the SIWS ABNF fixes. */
const FIELDS = [
  'URI',
  'Version',
  'Chain ID',
  'Nonce',
  'Issued At',
  'Expiration Time',
  'Not Before',
  'Request ID',
] as const;
type FieldName = (typeof FIELDS)[number];

function fail(message: string): never {
  throw new SessionTextError(message);
}

function rfc3339(ms: number): string {
  if (!Number.isSafeInteger(ms) || ms < 0 || ms > MAX_TIME_MS) fail(`time out of range: ${ms}`);
  return new Date(ms).toISOString();
}

/** RFC 3339 `date-time` to milliseconds. Sub-millisecond digits must be zero so the value is exact. */
function parseTime(s: string): number {
  const m = TIME_RE.exec(s);
  if (m === null) fail(`not an RFC 3339 timestamp: ${s}`);
  const [, y, mo, d, h, mi, sec, frac = '', z, sign, oh, om] = m;
  const year = Number(y);
  const month = Number(mo);
  const day = Number(d);
  const hour = Number(h);
  const minute = Number(mi);
  const second = Number(sec);
  if (frac.length > 3 && !/^0+$/.test(frac.slice(3))) fail('sub-millisecond precision');
  const ms = Number(frac.slice(0, 3).padEnd(3, '0'));
  const local = Date.UTC(year, month - 1, day, hour, minute, second, ms);
  const check = new Date(local);
  if (
    check.getUTCFullYear() !== year ||
    check.getUTCMonth() !== month - 1 ||
    check.getUTCDate() !== day ||
    check.getUTCHours() !== hour ||
    check.getUTCMinutes() !== minute ||
    check.getUTCSeconds() !== second
  ) {
    fail(`invalid date or time: ${s}`);
  }
  let offset = 0;
  if (z === undefined) {
    const offH = Number(oh);
    const offM = Number(om);
    if (offH > 23 || offM > 59) fail(`invalid offset: ${s}`);
    offset = (sign === '-' ? -1 : 1) * (offH * 60 + offM) * 60_000;
  }
  const t = local - offset;
  if (t < 0 || t > MAX_TIME_MS) fail(`time out of range: ${s}`);
  return t;
}

function parseAddress(s: string, what: string): Address {
  let raw: Uint8Array;
  try {
    raw = b58.decode(s, 32);
  } catch {
    fail(`${what} is not a base58 public key`);
  }
  if (b58.encode(raw) !== s) fail(`${what} is not canonical base58`);
  return s as Address;
}

function parseChainId(s: string): SessionGrant['chainId'] {
  const bare = s.startsWith('solana:') ? s.slice('solana:'.length) : s;
  if (bare === 'localnet' || bare === 'devnet' || bare === 'mainnet') return bare;
  return fail(`unsupported chain id: ${s}`);
}

/**
 * The canonical grant text, byte-identical to the Rust
 * `render_session_message`. No trailing newline.
 */
export function renderSessionMessage(g: SessionGrant): string {
  if (g.domain.length === 0 || !DOMAIN_RE.test(g.domain)) fail('invalid domain');
  if (g.statement.includes('\n') || g.statement.includes('\r')) fail('statement must be one line');
  if (!URI_RE.test(g.uri)) fail('invalid URI');
  if (g.nonce.length !== 16) fail('nonce must be 16 bytes');
  if (g.sessionKey.length !== 32) fail('session key must be 32 bytes');
  if (g.expiresAtMs <= g.issuedAtMs) fail('expiration must follow issuance');
  parseAddress(g.wallet, 'wallet');
  parseAddress(g.program, 'program');
  if (g.market !== null) parseAddress(g.market, 'market');
  const lines = [
    `${g.domain}${HEADER_SUFFIX}`,
    g.wallet,
    '',
    ...(g.statement.length > 0 ? [g.statement, ''] : []),
    `URI: ${g.uri}`,
    'Version: 1',
    // Wallets refuse a Chain ID they cannot match and none knows a local
    // validator, so a localnet grant leaves the optional field out.
    ...(g.chainId === 'localnet' ? [] : [`Chain ID: ${g.chainId}`]),
    `Nonce: ${hex.encode(g.nonce)}`,
    `Issued At: ${rfc3339(g.issuedAtMs)}`,
    `Expiration Time: ${rfc3339(g.expiresAtMs)}`,
    'Resources:',
    `- timescales:session:${hex.encode(g.sessionKey)}`,
    `- timescales:program:${g.program}`,
    ...(g.market !== null ? [`- timescales:market:${g.market}`] : []),
  ];
  const text = lines.join('\n');
  if (utf8(text).length > MAX_SESSION_TEXT_BYTES) fail('grant text exceeds 1024 bytes');
  return text;
}

/**
 * Parses a SIWS message (the EIP-4361-derived ABNF of Sign In With Solana)
 * into a grant. Accepted variations, which wallets produce when they build
 * the text from `SiwsInput` themselves: no statement (with or without the
 * extra blank line), RFC 3339 times with any offset, lowercase `t`/`z` or up
 * to nine fractional digits (sub-millisecond digits must be zero), a
 * `solana:`-prefixed chain id, an informational `Request ID`, and resources in
 * any order. Rejected: CR characters, a trailing newline, out-of-order or
 * repeated fields, `Not Before` (a grant cannot represent it), a version other
 * than 1, unknown resources, and texts over 1024 bytes.
 */
export function parseSessionMessage(text: string): SessionGrant {
  if (utf8(text).length > MAX_SESSION_TEXT_BYTES) fail('grant text exceeds 1024 bytes');
  if (text.includes('\r')) fail('CR is not allowed');
  const lines = text.split('\n');
  let i = 0;
  const next = (): string | undefined => lines[i];

  const header = next() ?? '';
  if (!header.endsWith(HEADER_SUFFIX)) fail('missing SIWS header line');
  const domain = header.slice(0, header.length - HEADER_SUFFIX.length);
  if (!DOMAIN_RE.test(domain)) fail('invalid domain');
  i++;
  const walletLine = next();
  if (walletLine === undefined) fail('missing address');
  const wallet = parseAddress(walletLine, 'address');
  i++;

  const isFieldLine = (l: string): boolean =>
    FIELDS.some((f) => l.startsWith(`${f}: `)) || l === 'Resources:';

  let statement = '';
  if (i < lines.length) {
    if (next() !== '') fail('expected a blank line after the address');
    i++;
    const l = next();
    if (l === undefined) fail('unexpected end of message');
    if (l === '') {
      i++;
    } else if (!isFieldLine(l)) {
      statement = l;
      i++;
      if (next() !== '') fail('expected a blank line after the statement');
      i++;
    }
  }

  const values = new Map<FieldName, string>();
  let fieldIndex = 0;
  while (i < lines.length && next() !== 'Resources:') {
    const l = next()!;
    let matched = false;
    for (let f = fieldIndex; f < FIELDS.length; f++) {
      const name = FIELDS[f]!;
      if (l.startsWith(`${name}: `)) {
        const value = l.slice(name.length + 2);
        if (value.length === 0) fail(`empty ${name}`);
        values.set(name, value);
        fieldIndex = f + 1;
        matched = true;
        break;
      }
    }
    if (!matched) fail(`unexpected line: ${JSON.stringify(l)}`);
    i++;
  }

  const resources: string[] = [];
  if (next() === 'Resources:') {
    i++;
    while (i < lines.length) {
      const l = next()!;
      if (!l.startsWith('- ') || l.length === 2) fail(`unexpected line: ${JSON.stringify(l)}`);
      resources.push(l.slice(2));
      i++;
    }
  }

  const required = (f: FieldName): string => values.get(f) ?? fail(`missing ${f}`);
  if (values.has('Not Before')) fail('Not Before is not supported in a session grant');
  const uri = required('URI');
  if (!URI_RE.test(uri)) fail('invalid URI');
  if (required('Version') !== '1') fail('unsupported SIWS version');
  const chainField = values.get('Chain ID');
  const chainId = chainField === undefined ? 'localnet' : parseChainId(chainField);
  if (chainField !== undefined && chainId === 'localnet') fail('a localnet grant has no Chain ID');
  const nonceHex = required('Nonce');
  if (!NONCE_RE.test(nonceHex)) fail('nonce must be 32 lowercase hex digits');
  const issuedAtMs = parseTime(required('Issued At'));
  const expiresAtMs = parseTime(required('Expiration Time'));
  if (expiresAtMs <= issuedAtMs) fail('expiration must follow issuance');

  let sessionKey: Uint8Array | null = null;
  let program: Address | null = null;
  let market: Address | null = null;
  let sawMarket = false;
  for (const r of resources) {
    if (r.startsWith('timescales:session:')) {
      if (sessionKey !== null) fail('repeated session resource');
      const k = r.slice('timescales:session:'.length);
      if (!KEY_RE.test(k)) fail('session key must be 64 lowercase hex digits');
      sessionKey = hex.decode(k, 32);
    } else if (r.startsWith('timescales:program:')) {
      if (program !== null) fail('repeated program resource');
      program = parseAddress(r.slice('timescales:program:'.length), 'program');
    } else if (r.startsWith('timescales:market:')) {
      if (sawMarket) fail('repeated market resource');
      sawMarket = true;
      market = parseAddress(r.slice('timescales:market:'.length), 'market');
    } else {
      fail(`unknown resource: ${r}`);
    }
  }
  if (sessionKey === null) fail('missing session resource');
  if (program === null) fail('missing program resource');

  return {
    domain,
    wallet,
    statement,
    uri,
    chainId,
    nonce: hex.decode(nonceHex, 16),
    issuedAtMs,
    expiresAtMs,
    sessionKey,
    program,
    market,
  };
}
