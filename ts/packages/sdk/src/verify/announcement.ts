import { b58 } from '../core/encoding/base58.js';
import { equal } from '../core/encoding/bytes.js';
import { verifyStrict } from '../core/crypto/verifyStrict.js';
import { decodeAnnouncement, epochAnnouncementDigest } from '../core/protocol/announcement.js';
import { band } from '../core/protocol/band.js';
import { epochBinding, termsDigest } from '../core/protocol/binding.js';
import { announcementDigest, type EpochKeyBundle } from '../core/protocol/bundle.js';
import type { MarketParams } from '../core/protocol/params.js';
import type { BatchAccount, MarketAccount, Observed } from '../solana/accounts.js';
import { termsEvidence } from './evidence.js';
import { CheckFailed, check, must, mustBeReady, type Verdict } from './verdict.js';

/**
 * V-4: the relay-signed announcement verifies under `Market.relay`, names
 * this market, the bundle's epoch, the bundle's announcement digest and
 * committee. Its band is `band(params, reference)` exactly. Returns the
 * epoch binding and the terms digest the batch will commit to.
 */
export function verifyAnnouncement(
  raw: Uint8Array,
  chain: MarketAccount,
  params: MarketParams,
  bundle: EpochKeyBundle,
): Verdict<{ binding: Uint8Array; terms: Uint8Array }> {
  return check('V-4 announcement', () => {
    const a = decodeAnnouncement(raw);
    const relay = b58.decode(chain.relay, 32);
    must(equal(a.market, b58.decode(chain.address, 32)), 'the announcement is for another market');
    must(a.epoch === bundle.announcement.epoch, 'the announcement is for another epoch');
    must(equal(a.relay, relay), 'the announcement names another relay');
    must(
      verifyStrict(relay, epochAnnouncementDigest(a), a.signature),
      "the announcement is not signed by the market's relay",
    );
    must(
      equal(a.keyDigest, announcementDigest(bundle.announcement)),
      'the announcement names another epoch key',
    );
    must(
      equal(a.committeeDigest, bundle.announcement.committeeDigest),
      'the announcement names another committee',
    );
    let expected;
    try {
      expected = band(params, a.band.reference);
    } catch (e) {
      throw new CheckFailed(`the announced reference has no valid band: ${(e as Error).message}`);
    }
    must(
      expected.lo === a.band.lo && expected.hi === a.band.hi,
      'the announced band is not the band of its reference',
    );
    const binding = epochBinding(a.priceCommitment, a.keyDigest, a.committeeDigest);
    return { binding, terms: termsDigest(a.band, binding) };
  });
}

/**
 * The V-4 check after commit: `Batch.terms_digest` must equal the terms of
 * the announcement the client sealed under. A mismatch fails with portable
 * terms evidence.
 */
export function checkCommittedTerms(
  announcementRaw: Uint8Array,
  terms: Uint8Array,
  batch: Observed<BatchAccount> | null,
): Verdict {
  return check('V-4 committed terms', () => {
    mustBeReady(batch !== null, 'the batch is not visible on the RPC yet');
    if (!equal(batch.value.termsDigest, terms)) {
      throw new CheckFailed(
        'the relay committed other terms than it announced',
        termsEvidence({ announcement: announcementRaw, expectedTerms: terms, batch }),
      );
    }
  });
}
