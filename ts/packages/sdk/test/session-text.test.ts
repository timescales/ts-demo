import type { Address } from '@solana/kit';
import fc from 'fast-check';
import { describe, expect, it } from 'vitest';
import {
  SESSION_STATEMENT,
  SessionTextError,
  b58,
  hex,
  parseSessionMessage,
  renderSessionMessage,
  type SessionGrant,
} from '../src/core/index.js';

const addr = (fill: number): Address => b58.encode(new Uint8Array(32).fill(fill)) as Address;

const grant: SessionGrant = {
  domain: 'app.timescales.example',
  wallet: addr(1),
  statement: SESSION_STATEMENT,
  uri: 'https://app.timescales.example',
  chainId: 'devnet',
  nonce: hex.decode('00112233445566778899aabbccddeeff'),
  issuedAtMs: Date.UTC(2026, 9, 7, 12, 0, 0, 123),
  expiresAtMs: Date.UTC(2026, 9, 8, 0, 0, 0, 123),
  sessionKey: new Uint8Array(32).fill(0xab),
  program: addr(2),
  market: addr(3),
};

const canonical = [
  'app.timescales.example wants you to sign in with your Solana account:',
  addr(1),
  '',
  SESSION_STATEMENT,
  '',
  'URI: https://app.timescales.example',
  'Version: 1',
  'Chain ID: devnet',
  'Nonce: 00112233445566778899aabbccddeeff',
  'Issued At: 2026-10-07T12:00:00.123Z',
  'Expiration Time: 2026-10-08T00:00:00.123Z',
  'Resources:',
  `- timescales:session:${'ab'.repeat(32)}`,
  `- timescales:program:${addr(2)}`,
  `- timescales:market:${addr(3)}`,
].join('\n');

/** Replaces one whole line of the canonical text. */
function withLine(from: string, to: string | null): string {
  const lines = canonical.split('\n');
  const i = lines.indexOf(from);
  if (i < 0) throw new Error(`no line ${from}`);
  if (to === null) lines.splice(i, 1);
  else lines[i] = to;
  return lines.join('\n');
}

describe('renderSessionMessage', () => {
  it('renders the canonical text', () => {
    expect(renderSessionMessage(grant)).toBe(canonical);
  });

  it('omits the market line for an all-markets grant', () => {
    const text = renderSessionMessage({ ...grant, market: null });
    expect(text).toBe(canonical.split('\n').slice(0, -1).join('\n'));
    expect(parseSessionMessage(text).market).toBeNull();
  });

  it('refuses grants it cannot render faithfully', () => {
    expect(() => renderSessionMessage({ ...grant, statement: 'two\nlines' })).toThrow(
      SessionTextError,
    );
    expect(() => renderSessionMessage({ ...grant, nonce: new Uint8Array(8) })).toThrow(
      SessionTextError,
    );
    expect(() => renderSessionMessage({ ...grant, expiresAtMs: grant.issuedAtMs })).toThrow(
      SessionTextError,
    );
    expect(() => renderSessionMessage({ ...grant, wallet: 'not-base58!' as Address })).toThrow(
      SessionTextError,
    );
    expect(() => renderSessionMessage({ ...grant, domain: 'bad domain' })).toThrow(
      SessionTextError,
    );
  });
});

describe('parseSessionMessage', () => {
  it('round-trips the canonical text', () => {
    expect(parseSessionMessage(canonical)).toEqual(grant);
    expect(renderSessionMessage(parseSessionMessage(canonical))).toBe(canonical);
  });

  it('round-trips random grants (property)', () => {
    const arb = fc.record({
      wallet: fc.uint8Array({ minLength: 32, maxLength: 32 }),
      program: fc.uint8Array({ minLength: 32, maxLength: 32 }),
      market: fc.option(fc.uint8Array({ minLength: 32, maxLength: 32 }), { nil: null }),
      nonce: fc.uint8Array({ minLength: 16, maxLength: 16 }),
      sessionKey: fc.uint8Array({ minLength: 32, maxLength: 32 }),
      issuedAtMs: fc.integer({ min: Date.UTC(2000, 0, 1), max: Date.UTC(2200, 0, 1) }),
      ttl: fc.integer({ min: 1, max: 24 * 3600 * 1000 }),
      chainId: fc.constantFrom('localnet' as const, 'devnet' as const, 'mainnet' as const),
      port: fc.option(fc.integer({ min: 1, max: 65535 }), { nil: null }),
    });
    fc.assert(
      fc.property(arb, (a) => {
        const g: SessionGrant = {
          domain: a.port === null ? 'localhost' : `localhost:${a.port}`,
          wallet: b58.encode(a.wallet) as Address,
          statement: SESSION_STATEMENT,
          uri: 'http://localhost:5173',
          chainId: a.chainId,
          nonce: a.nonce,
          issuedAtMs: a.issuedAtMs,
          expiresAtMs: a.issuedAtMs + a.ttl,
          sessionKey: a.sessionKey,
          program: b58.encode(a.program) as Address,
          market: a.market === null ? null : (b58.encode(a.market) as Address),
        };
        expect(parseSessionMessage(renderSessionMessage(g))).toEqual(g);
      }),
    );
  });

  describe('accepts wallet-formatted variants with the same semantic fields', () => {
    const variants: [string, string][] = [
      [
        'EIP-4361 blank lines without a statement',
        canonical.replace(`\n${SESSION_STATEMENT}\n`, '\n'),
      ],
      ['no statement at all', canonical.replace(`${SESSION_STATEMENT}\n\n`, '')],
      [
        'a +00:00 offset',
        withLine('Issued At: 2026-10-07T12:00:00.123Z', 'Issued At: 2026-10-07T12:00:00.123+00:00'),
      ],
      [
        'another offset',
        withLine('Issued At: 2026-10-07T12:00:00.123Z', 'Issued At: 2026-10-07T14:30:00.123+02:30'),
      ],
      [
        'microsecond digits',
        withLine('Issued At: 2026-10-07T12:00:00.123Z', 'Issued At: 2026-10-07T12:00:00.123000Z'),
      ],
      [
        'lowercase t and z',
        withLine('Issued At: 2026-10-07T12:00:00.123Z', 'Issued At: 2026-10-07t12:00:00.123z'),
      ],
      ['a solana:-prefixed chain id', withLine('Chain ID: devnet', 'Chain ID: solana:devnet')],
      [
        'a Request ID',
        withLine(
          'Expiration Time: 2026-10-08T00:00:00.123Z',
          'Expiration Time: 2026-10-08T00:00:00.123Z\nRequest ID: abc-123',
        ),
      ],
      [
        'reordered resources',
        canonical.replace(
          `- timescales:session:${'ab'.repeat(32)}\n- timescales:program:${addr(2)}`,
          `- timescales:program:${addr(2)}\n- timescales:session:${'ab'.repeat(32)}`,
        ),
      ],
    ];

    it.each(variants)('%s', (_name, text) => {
      const parsed = parseSessionMessage(text);
      const { statement, ...rest } = parsed;
      const { statement: expectedStatement, ...expected } = grant;
      expect(rest).toEqual(expected);
      expect([expectedStatement, '']).toContain(statement);
    });

    it('reads whole-second times', () => {
      const text = withLine(
        'Issued At: 2026-10-07T12:00:00.123Z',
        'Issued At: 2026-10-07T12:00:00Z',
      );
      expect(parseSessionMessage(text).issuedAtMs).toBe(Date.UTC(2026, 9, 7, 12, 0, 0, 0));
    });
  });

  describe('rejects', () => {
    const negatives: [string, string][] = [
      ['CRLF line endings', canonical.replace(/\n/g, '\r\n')],
      ['a trailing newline', `${canonical}\n`],
      [
        'Not Before',
        withLine(
          'Expiration Time: 2026-10-08T00:00:00.123Z',
          'Expiration Time: 2026-10-08T00:00:00.123Z\nNot Before: 2026-10-07T12:00:00Z',
        ),
      ],
      ['version 2', withLine('Version: 1', 'Version: 2')],
      ['an unknown resource', `${canonical}\n- https://evil.example/`],
      ['a repeated resource', `${canonical}\n- timescales:program:${addr(2)}`],
      ['a missing session resource', withLine(`- timescales:session:${'ab'.repeat(32)}`, null)],
      ['a missing program resource', withLine(`- timescales:program:${addr(2)}`, null)],
      [
        'an uppercase session key',
        withLine(
          `- timescales:session:${'ab'.repeat(32)}`,
          `- timescales:session:${'AB'.repeat(32)}`,
        ),
      ],
      [
        'out-of-order fields',
        canonical.replace(
          'URI: https://app.timescales.example\nVersion: 1',
          'Version: 1\nURI: https://app.timescales.example',
        ),
      ],
      ['a repeated field', withLine('Version: 1', 'Version: 1\nVersion: 1')],
      ['a missing nonce', withLine('Nonce: 00112233445566778899aabbccddeeff', null)],
      [
        'a short nonce',
        withLine('Nonce: 00112233445566778899aabbccddeeff', 'Nonce: 0011223344556677'),
      ],
      ['an unknown chain', withLine('Chain ID: devnet', 'Chain ID: testnet')],
      ['an invalid address', canonical.replace(addr(1), '0OIl')],
      ['a non-canonical address', canonical.replace(addr(1), `1${addr(1)}`)],
      [
        'sub-millisecond precision',
        withLine('Issued At: 2026-10-07T12:00:00.123Z', 'Issued At: 2026-10-07T12:00:00.1234Z'),
      ],
      [
        'an impossible date',
        withLine('Issued At: 2026-10-07T12:00:00.123Z', 'Issued At: 2026-02-30T12:00:00.123Z'),
      ],
      [
        'a leap second',
        withLine('Issued At: 2026-10-07T12:00:00.123Z', 'Issued At: 2026-12-31T23:59:60Z'),
      ],
      [
        'expiry before issuance',
        withLine(
          'Expiration Time: 2026-10-08T00:00:00.123Z',
          'Expiration Time: 2026-10-07T00:00:00Z',
        ),
      ],
      [
        'a wrong header',
        canonical.replace(
          'wants you to sign in with your Solana account:',
          'wants you to sign in with your Ethereum account:',
        ),
      ],
      [
        'a domain with a path',
        canonical.replace('app.timescales.example wants', 'app.timescales.example/x wants'),
      ],
      ['an unknown line', withLine('Version: 1', 'Version: 1\nColor: blue')],
      ['text over 1024 bytes', canonical.replace(SESSION_STATEMENT, 'x'.repeat(1024))],
      ['an empty message', ''],
    ];
    it.each(negatives)('%s', (_name, text) => {
      expect(() => parseSessionMessage(text)).toThrow(SessionTextError);
    });
  });
});
