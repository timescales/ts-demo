import { hex } from '../core/encoding/hex.js';
import type { SessionGrant } from '../core/protocol/sessionText.js';
import type { SiwsInput } from './port.js';

/** The `solana:signIn` input for a grant, with every field set. */
export function siwsInputFor(g: SessionGrant): SiwsInput {
  return {
    domain: g.domain,
    address: g.wallet,
    statement: g.statement,
    uri: g.uri,
    version: '1',
    chainId: g.chainId,
    nonce: hex.encode(g.nonce),
    issuedAt: new Date(g.issuedAtMs).toISOString(),
    expirationTime: new Date(g.expiresAtMs).toISOString(),
    resources: [
      `timescales:session:${hex.encode(g.sessionKey)}`,
      `timescales:program:${g.program}`,
      ...(g.market !== null ? [`timescales:market:${g.market}`] : []),
    ],
  };
}

/**
 * Whether a wallet-formatted grant text carries exactly the semantic fields
 * the SDK asked for. The node accepts any ABNF-conformant text whose
 * fields match and checks the statement too.
 */
export function sameGrant(a: SessionGrant, b: SessionGrant): boolean {
  return (
    a.domain === b.domain &&
    a.wallet === b.wallet &&
    a.statement === b.statement &&
    a.uri === b.uri &&
    a.chainId === b.chainId &&
    hex.encode(a.nonce) === hex.encode(b.nonce) &&
    a.issuedAtMs === b.issuedAtMs &&
    a.expiresAtMs === b.expiresAtMs &&
    hex.encode(a.sessionKey) === hex.encode(b.sessionKey) &&
    a.program === b.program &&
    a.market === b.market
  );
}
