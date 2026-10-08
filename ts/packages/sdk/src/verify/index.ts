// @timescales/sdk/verify: the client checks. Each returns a Verdict and never throws on adversarial input.
import { z } from 'zod';

z.config({ jitless: true });

export type { Verdict } from './verdict.js';
export { type AppPins, type VerifiedMarketContext, verifyMarket } from './market.js';
export { verifyCommittee } from './committee.js';
export { verifyEpochKey } from './epochKey.js';
export { verifyAnnouncement } from './announcement.js';
export { verifyPromise } from './promise.js';
export { type Inclusion, checkInclusion } from './inclusion.js';
export { verifyReceipt } from './receipt.js';
export { verifyArtifacts } from './artifacts.js';
export { type OwnFill, ownFills } from './fills.js';
export { verifyPolicies } from './policy.js';
export { verifyOwnBalance } from './balance.js';
export { verifyProgram } from './program.js';
export { decodePendingChange } from './governance.js';
export type { EvidenceRecord } from './evidence.js';
