import type { EpochKey } from '../api/schemas.js';
import { b58 } from '../core/encoding/base58.js';
import { equal } from '../core/encoding/bytes.js';
import { decompress, edwardsU, isPrimeOrder } from '../core/crypto/edwards.js';
import { verifyStrict } from '../core/crypto/verifyStrict.js';
import {
  ackDigest,
  announcementDigest,
  decodeBundle,
  type EpochKeyBundle,
} from '../core/protocol/bundle.js';
import {
  committeeDigest,
  encodeCommittee,
  type CommitteeDescription,
} from '../core/protocol/committee.js';
import type { MarketAccount } from '../solana/accounts.js';
import { committeeKnown } from './committee.js';
import type { AppPins } from './market.js';
import { check, must, type Verdict } from './verdict.js';

/** Members whose ack over `H(EPOCH_KEY_ACK, announcement digest || policy digest)` verifies, keyed by member index. */
export function validAcks(
  bundle: EpochKeyBundle,
  committee: CommitteeDescription,
): Map<number, Uint8Array> {
  const digest = announcementDigest(bundle.announcement);
  const out = new Map<number, Uint8Array>();
  for (const ack of bundle.acks) {
    const member = committee.members.find((m) => m.index === ack.member);
    if (member === undefined || out.has(ack.member)) continue;
    if (verifyStrict(member.identity, ackDigest(digest, ack.policyDigest), ack.signature)) {
      out.set(ack.member, ack.policyDigest);
    }
  }
  return out;
}

/**
 * V-3: the bundle names this market and epoch and a committee digest the
 * market knows (current or previous, V-2), which is the `committee` given.
 * The scheme is Feldman (`dev` only when the app is pinned to localnet.
 * The caller checks the RPC's genesis hash against the pin). `t`
 * commitments, each canonical, torsion-free and not the identity, with
 * `u(C_0) == epoch_pk`. And at least `t` distinct members' acks verify.
 * Without this check the client never seals.
 */
export function verifyEpochKey(
  k: EpochKey,
  committee: CommitteeDescription,
  chain: MarketAccount,
  epoch: bigint,
  pins: AppPins,
): Verdict<{ epochPk: Uint8Array; bundle: EpochKeyBundle }> {
  return check('V-3 epoch key', () => {
    const bundle = decodeBundle(k.bundleBytes);
    const a = bundle.announcement;
    must(equal(a.market, b58.decode(chain.address, 32)), 'the epoch key is for another market');
    must(a.epoch === epoch && k.epoch === epoch, 'the epoch key is for another epoch');
    must(equal(a.epochPk, k.epochPk), 'the bundle and the API disagree about the epoch key');
    must(
      equal(a.committeeDigest, k.committeeDigest),
      'the bundle and the API disagree about the committee',
    );
    must(
      committeeKnown(chain, a.committeeDigest),
      'the epoch key was dealt for an unknown committee',
    );
    must(
      equal(committeeDigest(encodeCommittee(committee)), a.committeeDigest),
      'the epoch key was dealt for another committee',
    );
    if (a.scheme === 'dev') {
      must(pins.cluster === 'localnet', 'a development epoch key outside localnet');
      must(a.commitments.length === 0, 'a development epoch key with commitments');
    } else {
      must(
        a.commitments.length === committee.threshold,
        'the key needs one commitment per threshold',
      );
      must(
        a.commitments.every((c) => {
          const p = decompress(c);
          return p !== null && isPrimeOrder(p);
        }),
        'a key commitment is not a canonical prime-order point',
      );
      const u = edwardsU(a.commitments[0]!);
      must(u !== null, 'the key commitment C_0 is not a prime-order point');
      must(equal(u, a.epochPk), 'the epoch key is not u(C_0)');
    }
    must(
      validAcks(bundle, committee).size >= committee.threshold,
      'fewer than t committee members vouched for the epoch key',
    );
    return { epochPk: a.epochPk, bundle };
  });
}
