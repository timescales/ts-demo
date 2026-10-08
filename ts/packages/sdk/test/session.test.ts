// Wallet port and trading sessions: the Wallet Standard
// adapter and its mutex, intent signing, the SIWS grant flow, request
// authorization, resume, and WebCrypto against noble.
import 'fake-indexeddb/auto';
import type { Address } from '@solana/kit';
import type { Wallet, WalletAccount } from '@wallet-standard/base';
import { sha256 } from '@noble/hashes/sha2.js';
import { describe, expect, it, vi } from 'vitest';
import { ServerClock } from '../src/api/index.js';
import {
  b58,
  concat,
  ed25519PublicKey,
  ed25519Sign,
  fromUtf8,
  hex,
  intentMessage,
  parseSessionMessage,
  u64le,
  utf8,
  verifyStrict,
} from '../src/core/index.js';
import { openJournal } from '../src/journal/index.js';
import { createTestRng, createTestWallet, type TestWallet } from '../src/testing/index.js';
import { createFakeNode, type FakeNode } from '../src/testing/node.js';
import {
  TradingSession,
  WalletError,
  signIntent,
  walletFromStandard,
  type SiwsInput,
  type TraderWallet,
} from '../src/wallet/index.js';
import { toWalletError } from '../src/wallet/port.js';
import { rememberSession, sessionRequestDigest } from '../src/wallet/session.js';

let counter = 0;

async function node(profile: 'devnet' | 'production' = 'devnet') {
  counter++;
  const rng = createTestRng(new Uint8Array([counter, 0x55]));
  const n = createFakeNode({ seed: rng.bytes(32), profile });
  const clock = new ServerClock();
  await clock.sync(n.api);
  return { n, rng, clock, info: await n.api.info() };
}

function posts(n: FakeNode): number {
  return n.fake.requests.filter((r) => r.method === 'POST' && r.path === '/v1/sessions').length;
}

/** A wallet whose `signIn` changes what it is asked to sign. */
function rewriting(w: TestWallet, f: (i: SiwsInput) => SiwsInput): TraderWallet {
  return {
    address: w.address,
    name: w.name,
    features: w.features,
    signMessage: (m, s) => w.signMessage(m, s),
    signIn: (i, s) => w.signIn!(f(i), s),
    onChange: (l) => w.onChange(l),
  };
}

describe('TimescalesSession request authorization', () => {
  it('signs H(SESSION, "request" || method || 0 || path || 0 || ts || SHA-256(body))', () => {
    const body = utf8('{"submission_b64":"AA=="}');
    const tag = utf8('timescales/v1/session');
    const expected = sha256(
      concat(
        Uint8Array.of(tag.length),
        tag,
        utf8('request'),
        utf8('POST'),
        Uint8Array.of(0),
        utf8('/v1/markets/m/submissions?x=1'),
        Uint8Array.of(0),
        u64le(1_791_000_000_123n),
        sha256(body),
      ),
    );
    expect(
      hex.encode(
        sessionRequestDigest('POST', '/v1/markets/m/submissions?x=1', 1_791_000_000_123n, body),
      ),
    ).toBe(hex.encode(expected));
    // Every input is bound: another method, path, time or body gives another digest.
    const base = sessionRequestDigest('GET', '/v1/sessions/current', 1n, new Uint8Array(0));
    for (const other of [
      sessionRequestDigest('DELETE', '/v1/sessions/current', 1n, new Uint8Array(0)),
      sessionRequestDigest('GET', '/v1/sessions/current?', 1n, new Uint8Array(0)),
      sessionRequestDigest('GET', '/v1/sessions/current', 2n, new Uint8Array(0)),
      sessionRequestDigest('GET', '/v1/sessions/current', 1n, new Uint8Array(1)),
    ]) {
      expect(hex.encode(other)).not.toBe(hex.encode(base));
    }
  });
});

describe('TradingSession', () => {
  it('opens with one Sign-In prompt, posting the exact text the wallet signed', async () => {
    const { n, rng, clock, info } = await node('production');
    const w = createTestWallet({ seed: rng.bytes(32) });
    const s = await TradingSession.open({ api: n.api, wallet: w, info, clock, market: n.market });
    expect(w.calls.map((c) => c.method)).toEqual(['signIn']);
    expect(s.wallet).toBe(w.address);
    expect(s.nonExtractable).toBe(true);
    const body = JSON.parse(
      fromUtf8(n.fake.requests.find((r) => r.path === '/v1/sessions')!.body!),
    ) as {
      message: string;
      method: string;
      signature_b64: string;
    };
    expect(body.method).toBe('sign_in');
    const grant = parseSessionMessage(body.message);
    expect(grant.wallet).toBe(w.address);
    expect(grant.market).toBe(n.market);
    expect(grant.program).toBe(info.programId);
    expect(hex.encode(grant.sessionKey)).toBe(hex.encode(s.sessionKey));
    expect(grant.expiresAtMs - grant.issuedAtMs).toBe(12 * 3_600_000);
    expect(s.expiresAtMs).toBe(grant.expiresAtMs);

    // Requests carry a fresh, strictly increasing timestamp on server time.
    const h1 = await s.authorization('GET', '/v1/sessions/current', new Uint8Array(0));
    const h2 = await s.authorization('GET', '/v1/sessions/current', new Uint8Array(0));
    const parse = (h: string) => {
      const m = /^TimescalesSession ([0-9a-f]{64})\.(\d+)\.([0-9a-f]{128})$/.exec(h)!;
      return { key: m[1]!, ts: BigInt(m[2]!), sig: hex.decode(m[3]!) };
    };
    const a = parse(h1);
    const b = parse(h2);
    expect(a.key).toBe(hex.encode(s.sessionKey));
    expect(b.ts).toBeGreaterThan(a.ts);
    expect(
      verifyStrict(
        s.sessionKey,
        sessionRequestDigest('GET', '/v1/sessions/current', b.ts, new Uint8Array(0)),
        b.sig,
      ),
    ).toBe(true);
    expect((await n.api.currentSession(s)).wallet).toBe(w.address);
  });

  it('parses the wallet’s text before posting it and refuses another semantic field', async () => {
    const { n, rng, clock, info } = await node('production');
    const w = createTestWallet({ seed: rng.bytes(32) });
    for (const change of [
      (i: SiwsInput) => ({ ...i, domain: 'evil.example' }),
      (i: SiwsInput) => ({ ...i, resources: i.resources.slice(1) }),
      (i: SiwsInput) => ({ ...i, nonce: '00'.repeat(16) }),
    ]) {
      await expect(
        TradingSession.open({
          api: n.api,
          wallet: rewriting(w, change),
          info,
          clock,
          market: null,
        }),
      ).rejects.toMatchObject({ code: 'SESSION_TEMPLATE_INVALID' });
    }
    const prefixing = createTestWallet({ seed: rng.bytes(32), behaviour: 'prefixing' });
    await expect(
      TradingSession.open({ api: n.api, wallet: prefixing, info, clock, market: null }),
    ).rejects.toMatchObject({ code: 'SESSION_TEMPLATE_INVALID' });
    expect(posts(n)).toBe(0);
  });

  it('signs the canonical text instead only where allowed and only after the user agrees', async () => {
    const { n, rng, clock, info } = await node('devnet');
    const w = createTestWallet({ seed: rng.bytes(32) });
    const odd = rewriting(w, (i) => ({ ...i, statement: 'Sign in' }));
    await expect(
      TradingSession.open({
        api: n.api,
        wallet: odd,
        info,
        clock,
        market: null,
        onSecondPrompt: () => Promise.resolve(false),
      }),
    ).rejects.toMatchObject({ code: 'SESSION_TEMPLATE_INVALID' });
    expect(posts(n)).toBe(0);
    const before = w.calls.length;
    const s = await TradingSession.open({
      api: n.api,
      wallet: odd,
      info,
      clock,
      market: null,
      onSecondPrompt: () => Promise.resolve(true),
    });
    expect(w.calls.slice(before).map((c) => c.method)).toEqual(['signIn', 'signMessage']);
    const body = JSON.parse(fromUtf8(n.fake.requests.at(-1)!.body!)) as { method: string };
    expect(body.method).toBe('sign_message');
    expect(s.wallet).toBe(w.address);

    // A wallet without Sign-In: allowed on devnet, refused in production.
    const plain = createTestWallet({ seed: rng.bytes(32), features: ['solana:signMessage'] });
    expect(plain.signIn).toBeUndefined();
    await TradingSession.open({ api: n.api, wallet: plain, info, clock, market: null });
    const prod = await node('production');
    await expect(
      TradingSession.open({
        api: prod.n.api,
        wallet: plain,
        info: prod.info,
        clock: prod.clock,
        market: null,
      }),
    ).rejects.toMatchObject({ code: 'SESSION_METHOD_REFUSED' });
    expect(posts(prod.n)).toBe(0);
  });

  it('signs the canonical text when the wallet cannot sign in, but not when the user refused', async () => {
    const { n, rng, clock, info } = await node('devnet');
    const w = createTestWallet({ seed: rng.bytes(32) });
    const failing = (err: unknown): TraderWallet => ({
      ...rewriting(w, (i) => i),
      signIn: () => Promise.reject(err),
    });
    // A wallet that rejects the request itself (an unknown cluster, say).
    const s = await TradingSession.open({
      api: n.api,
      wallet: failing({ code: -32603, message: 'Unsupported chain' }),
      info,
      clock,
      market: null,
    });
    expect(s.wallet).toBe(w.address);
    const body = JSON.parse(fromUtf8(n.fake.requests.at(-1)!.body!)) as { method: string };
    expect(body.method).toBe('sign_message');
    // The user's refusal ends the attempt.
    const before = posts(n);
    await expect(
      TradingSession.open({
        api: n.api,
        wallet: failing({ code: 4001, message: 'User rejected the request.' }),
        info,
        clock,
        market: null,
      }),
    ).rejects.toMatchObject({ code: 'rejected' });
    expect(posts(n)).toBe(before);
    // Production never falls back.
    const prod = await node('production');
    await expect(
      TradingSession.open({
        api: prod.n.api,
        wallet: failing({ code: -32603, message: 'Unsupported chain' }),
        info: prod.info,
        clock: prod.clock,
        market: null,
      }),
    ).rejects.toMatchObject({ code: 'unknown' });
    expect(posts(prod.n)).toBe(0);
  });

  it('signs the session text directly on localnet, never asking for a Sign-In', async () => {
    counter++;
    const rng = createTestRng(new Uint8Array([counter, 0x56]));
    const n = createFakeNode({ seed: rng.bytes(32), profile: 'devnet', cluster: 'localnet' });
    const clock = new ServerClock();
    await clock.sync(n.api);
    const info = await n.api.info();
    const w = createTestWallet({ seed: rng.bytes(32) });
    const s = await TradingSession.open({ api: n.api, wallet: w, info, clock, market: null });
    expect(s.wallet).toBe(w.address);
    expect(w.calls.map((c) => c.method)).toEqual(['signMessage']);
    const body = JSON.parse(fromUtf8(n.fake.requests.at(-1)!.body!)) as {
      method: string;
      message: string;
    };
    expect(body.method).toBe('sign_message');
    expect(body.message).not.toContain('Chain ID');
  });

  it('refuses a Sign-In by another account', async () => {
    const { n, rng, clock, info } = await node();
    const w = createTestWallet({ seed: rng.bytes(32) });
    const other = b58.encode(ed25519PublicKey(rng.bytes(32))) as Address;
    const liar: TraderWallet = {
      ...rewriting(w, (i) => i),
      signIn: async (i, s) => ({ ...(await w.signIn!(i, s)), account: other }),
    };
    await expect(
      TradingSession.open({ api: n.api, wallet: liar, info, clock, market: null }),
    ).rejects.toMatchObject({ kind: 'wallet', code: 'account_changed' });
    expect(posts(n)).toBe(0);
  });

  it('resumes from the journal and forgets a session the node revoked', async () => {
    const { n, rng, clock, info } = await node();
    const w = createTestWallet({ seed: rng.bytes(32) });
    const journal = await openJournal({
      cluster: 'devnet',
      program: info.programId,
      wallet: w.address,
    });
    const s = await TradingSession.open({ api: n.api, wallet: w, info, clock, market: n.market });
    expect(await rememberSession(s, journal)).toBe(true);
    const back = await TradingSession.resume({ api: n.api, wallet: w.address, journal, clock });
    expect(back).not.toBeNull();
    expect(hex.encode(back!.sessionKey)).toBe(hex.encode(s.sessionKey));
    expect(back!.nonExtractable).toBe(true);
    expect((await n.api.currentSession(back!)).wallet).toBe(w.address);
    expect(
      await TradingSession.resume({
        api: n.api,
        wallet: b58.encode(new Uint8Array(32).fill(1)) as Address,
        journal,
        clock,
      }),
    ).toBeNull();
    await back!.revoke();
    await expect(
      back!.authorization('GET', '/v1/sessions/current', new Uint8Array(0)),
    ).rejects.toMatchObject({
      code: 'SESSION_REVOKED',
    });
    expect(
      await TradingSession.resume({ api: n.api, wallet: w.address, journal, clock }),
    ).toBeNull();
  });

  it('falls back to an in-memory noble key where WebCrypto has no Ed25519', async () => {
    const { n, rng, clock, info } = await node();
    const w = createTestWallet({ seed: rng.bytes(32) });
    const generate = crypto.subtle.generateKey.bind(crypto.subtle);
    const spy = vi
      .spyOn(crypto.subtle, 'generateKey')
      .mockImplementation(((alg: AlgorithmIdentifier, ...rest: unknown[]) =>
        (alg as { name?: string }).name === 'Ed25519'
          ? Promise.reject(new DOMException('unsupported', 'NotSupportedError'))
          : (generate as (...a: unknown[]) => Promise<unknown>)(
              alg,
              ...rest,
            )) as typeof crypto.subtle.generateKey);
    try {
      const s = await TradingSession.open({ api: n.api, wallet: w, info, clock, market: null });
      expect(s.nonExtractable).toBe(false);
      expect((await n.api.currentSession(s)).wallet).toBe(w.address);
      const journal = await openJournal({
        cluster: 'devnet',
        program: info.programId,
        wallet: w.address,
      });
      // Only a non-extractable key may be kept. A reload needs a new session.
      expect(await rememberSession(s, journal)).toBe(false);
    } finally {
      spy.mockRestore();
    }
  });

  it('signs with WebCrypto Ed25519 exactly as noble does for the same key', async () => {
    const seed = hex.decode('9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60');
    const pkcs8 = concat(hex.decode('302e020100300506032b657004220420'), seed);
    const key = await crypto.subtle.importKey(
      'pkcs8',
      pkcs8 as Uint8Array<ArrayBuffer>,
      { name: 'Ed25519' },
      false,
      ['sign'],
    );
    for (const msg of [new Uint8Array(0), utf8('timescales'), new Uint8Array(32).fill(7)]) {
      const data = msg as Uint8Array<ArrayBuffer>;
      const web = new Uint8Array(await crypto.subtle.sign({ name: 'Ed25519' }, key, data));
      expect(hex.encode(web)).toBe(hex.encode(ed25519Sign(seed, msg)));
    }
    // RFC 8032 test 1.
    expect(hex.encode(ed25519PublicKey(seed))).toBe(
      'd75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a',
    );
  });
});

describe('signIntent (V-11)', () => {
  const c = new Uint8Array(32).fill(3);

  it('returns a signature over the intent text after verifying it', async () => {
    const w = createTestWallet({ seed: new Uint8Array(32).fill(1) });
    const sig = await signIntent(w, c);
    expect(verifyStrict(b58.decode(w.address, 32), intentMessage(c), sig)).toBe(true);
    const r = createTestWallet({ seed: new Uint8Array(32).fill(1), behaviour: 'randomized' });
    const sig2 = await signIntent(r, c);
    expect(hex.encode(sig2)).not.toBe(hex.encode(sig));
    expect(verifyStrict(b58.decode(r.address, 32), intentMessage(c), sig2)).toBe(true);
  });

  it('refuses modified messages and maps wallet errors', async () => {
    const prefixing = createTestWallet({
      seed: new Uint8Array(32).fill(2),
      behaviour: 'prefixing',
    });
    await expect(signIntent(prefixing, c)).rejects.toMatchObject({ code: 'modified_message' });
    for (const behaviour of ['phantom_errors', 'solflare_errors', 'backpack_errors'] as const) {
      const w = createTestWallet({ seed: new Uint8Array(32).fill(2), behaviour });
      await expect(signIntent(w, c)).rejects.toMatchObject({ kind: 'wallet', code: 'rejected' });
    }
    const gone = createTestWallet({ seed: new Uint8Array(32).fill(2) });
    gone.disconnect();
    await expect(signIntent(gone, c)).rejects.toMatchObject({ code: 'disconnected' });
  });

  it('drops a signature that resolves after the signal aborted', async () => {
    const w = createTestWallet({
      seed: new Uint8Array(32).fill(4),
      behaviour: 'late_resolving',
      lateMs: 30,
    });
    const ac = new AbortController();
    const pending = signIntent(w, c, ac.signal);
    ac.abort();
    await expect(pending).rejects.toMatchObject({ code: 'abandoned' });
    const never = createTestWallet({
      seed: new Uint8Array(32).fill(4),
      behaviour: 'never_resolving',
    });
    const ac2 = new AbortController();
    const p2 = signIntent(never, c, ac2.signal);
    setTimeout(() => ac2.abort(), 5);
    await expect(p2).rejects.toMatchObject({ code: 'abandoned' });
  });

  it('normalises what wallets throw', () => {
    const cases: [unknown, string][] = [
      [Object.assign(new Error('User rejected the request.'), { code: 4001 }), 'rejected'],
      [Object.assign(new Error('x'), { name: 'WalletWindowClosedError' }), 'rejected'],
      [new Error('Approval Denied'), 'rejected'],
      [new Error('Wallet is locked'), 'locked'],
      [Object.assign(new Error('pending'), { code: -32002 }), 'busy'],
      [Object.assign(new Error('x'), { code: 4900 }), 'disconnected'],
      [new Error('Method not supported'), 'unsupported_feature'],
      ['plain string', 'unknown'],
      [undefined, 'unknown'],
    ];
    for (const [thrown, code] of cases) {
      const e = toWalletError(thrown);
      expect(e).toBeInstanceOf(WalletError);
      expect(e.code).toBe(code);
    }
  });
});

describe('walletFromStandard', () => {
  function standard(o: { chains?: `${string}:${string}`[]; delay?: () => Promise<void> } = {}) {
    const seed = new Uint8Array(32).fill(9);
    const pub = ed25519PublicKey(seed);
    const listeners = new Set<
      (p: { accounts?: readonly WalletAccount[]; chains?: readonly string[] }) => void
    >();
    const log: string[] = [];
    const account: WalletAccount = {
      address: b58.encode(pub),
      publicKey: pub,
      chains: o.chains ?? ['solana:devnet'],
      features: ['solana:signMessage', 'solana:signAndSendTransaction'],
    };
    const wallet = {
      version: '1.0.0',
      name: 'Standard test wallet',
      icon: 'data:image/svg+xml;base64,AA==',
      chains: account.chains,
      accounts: [account],
      features: {
        'solana:signMessage': {
          version: '1.0.0',
          signMessage: async (...inputs: { message: Uint8Array }[]) => {
            log.push('start');
            await o.delay?.();
            log.push('end');
            return inputs.map((i) => ({
              signedMessage: i.message,
              signature: ed25519Sign(seed, i.message),
            }));
          },
        },
        'solana:signAndSendTransaction': {
          version: '1.0.0',
          supportedTransactionVersions: ['legacy'],
          signAndSendTransaction: async (...inputs: { chain: string }[]) => {
            log.push(`send ${inputs[0]!.chain}`);
            return [{ signature: new Uint8Array(64).fill(5) }];
          },
        },
        'standard:events': {
          version: '1.0.0',
          on: (_e: 'change', l: (p: { accounts?: readonly WalletAccount[] }) => void) => {
            listeners.add(l);
            return () => listeners.delete(l);
          },
        },
      },
    } as unknown as Wallet;
    return { wallet, account, listeners, log };
  }

  it('serialises requests per wallet and lets a queued caller leave without a prompt', async () => {
    let release!: () => void;
    const gate = new Promise<void>((r) => (release = r));
    let first = true;
    const s = standard({
      delay: () => {
        if (!first) return Promise.resolve();
        first = false;
        return gate;
      },
    });
    const w = walletFromStandard(s.wallet, s.account);
    expect(w.features.has('solana:signMessage')).toBe(true);
    expect(w.signIn).toBeUndefined();
    const a = w.signMessage(utf8('a'));
    const ac = new AbortController();
    const b = w.signMessage(utf8('b'), ac.signal);
    const c = w.signMessage(utf8('c'));
    await new Promise((r) => setTimeout(r, 5));
    expect(s.log).toEqual(['start']);
    ac.abort();
    await expect(b).rejects.toMatchObject({ code: 'abandoned' });
    release();
    expect(fromUtf8((await a).signedMessage)).toBe('a');
    expect(fromUtf8((await c).signedMessage)).toBe('c');
    expect(s.log).toEqual(['start', 'end', 'start', 'end']);
  });

  it('reports standard:events changes that concern its account', () => {
    const s = standard();
    const w = walletFromStandard(s.wallet, s.account);
    const seen: string[] = [];
    const off = w.onChange((e) => seen.push(e.kind));
    for (const l of s.listeners) {
      l({ accounts: [s.account] });
      l({ accounts: [{ ...s.account, address: b58.encode(new Uint8Array(32).fill(1)) }] });
      l({ chains: ['solana:mainnet'] });
      l({ accounts: [] });
    }
    off();
    for (const l of s.listeners) l({ accounts: [] });
    expect(seen).toEqual(['accounts', 'chains', 'disconnected']);
  });

  it('sends only when the account names exactly one Solana cluster', async () => {
    const one = standard();
    const w1 = walletFromStandard(one.wallet, one.account);
    expect(await w1.signAndSendTransaction!(new Uint8Array(10))).toEqual({
      signature: b58.encode(new Uint8Array(64).fill(5)),
    });
    expect(one.log).toEqual(['send solana:devnet']);
    const two = standard({ chains: ['solana:devnet', 'solana:mainnet'] });
    const w2 = walletFromStandard(two.wallet, two.account);
    await expect(w2.signAndSendTransaction!(new Uint8Array(10))).rejects.toMatchObject({
      code: 'unsupported_feature',
    });
  });
});
