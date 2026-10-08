// The verifier checks behind one participation (VerificationChecklist). The
// SDK moves a participation only on verified objects, so its state
// says which checks have passed. The next one is being checked.
import type { OrderRecord, Participation, ParticipationState } from '@timescales/sdk/orders';

export type CheckId =
  'key' | 'binding' | 'promise' | 'root' | 'executor' | 'quorum' | 'fills' | 'balance' | 'settled';

export const CHECKS: readonly CheckId[] = [
  'key',
  'binding',
  'promise',
  'root',
  'executor',
  'quorum',
  'fills',
  'balance',
  'settled',
];

export type CheckStatus = 'passed' | 'failed' | 'checking' | 'pending' | 'not_reached';

export interface CheckRow {
  id: CheckId;
  status: CheckStatus;
  /** Quorum progress, when known. */
  quorum?: { have: number; need: number };
}

const IN_FLIGHT = new Set<ParticipationState['kind']>([
  'locked',
  'included',
  'clearing',
  'provisional',
  'verified',
  'settling',
]);

/** How many checks (in CHECKS order) a participation state implies have passed. */
const PASSED: Record<ParticipationState['kind'], number> = {
  not_submitted: 0,
  sealed: 3,
  parked: 3,
  locked: 3,
  included: 4,
  excluded: 3,
  clearing: 4,
  provisional: 5,
  verified: 8,
  settling: 8,
  settled: 9,
  voided: 0,
};

/** The  check id a failed `check` string names (`V-3`... `V-10`). */
export function checkOfFailure(check: string): CheckId | null {
  const m = /V-(\d+)/.exec(check);
  switch (m?.[1]) {
    case '3':
      return 'key';
    case '4':
      return 'binding';
    case '5':
      return 'promise';
    case '6':
      return 'root';
    case '7':
      return 'executor';
    case '8':
      return 'fills';
    case '9':
      return 'balance';
    case '10':
      return 'settled';
    default:
      return null;
  }
}

/** Index of the last check a voided participation had passed, from the events before the abort. */
function passedBeforeVoid(r: OrderRecord, epoch: bigint): number {
  let passed = 0;
  for (const e of r.history) {
    if (!('epoch' in e) || e.epoch !== epoch) continue;
    if (e.kind === 'promise_verified') passed = Math.max(passed, 3);
    else if (e.kind === 'inclusion' && e.inclusion === 'included') passed = Math.max(passed, 4);
    else if (e.kind === 'receipt') passed = Math.max(passed, e.quorumMet ? 6 : 5);
    else if (e.kind === 'fills') passed = Math.max(passed, 8);
  }
  return passed;
}

export function checklist(r: OrderRecord, p: Participation): CheckRow[] {
  const s = p.state;
  const failedCheck = r.state.kind === 'verification_failed' ? checkOfFailure(r.state.check) : null;
  let passed = PASSED[s.kind];
  if ((s.kind === 'sealed' || s.kind === 'parked') && p.promise === null) passed = 2;
  if (s.kind === 'voided') passed = passedBeforeVoid(r, p.epoch);
  // A sealed or parked envelope waits for its epoch to close. Nothing is being checked yet.
  const active = IN_FLIGHT.has(s.kind) || (passed === 2 && p.promise === null);
  return CHECKS.map((id, i): CheckRow => {
    const row: CheckRow = { id, status: 'pending' };
    if (id === 'quorum' && s.kind === 'provisional') row.quorum = { have: s.have, need: s.need };
    if (i < passed) row.status = 'passed';
    else if (s.kind === 'excluded' && id === 'root') row.status = 'failed';
    else if (failedCheck === id) row.status = 'failed';
    else if (s.kind === 'voided' || s.kind === 'excluded' || s.kind === 'not_submitted') {
      row.status = 'not_reached';
    } else if (i === passed && active && r.state.kind !== 'verification_failed') {
      row.status = 'checking';
    }
    return row;
  });
}
