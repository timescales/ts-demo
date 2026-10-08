// Order and participation states -> glyph, tone and text. Both tables
// are keyed by every state the SDK's ORDER_LIFECYCLE and
// PARTICIPATION_LIFECYCLE can produce. The Record types make a missing
// state a type error and the tests render every row.
import type { UnitContext } from '@timescales/sdk/core';
import type {
  OrderRecord,
  OrderState,
  Participation,
  ParticipationState,
} from '@timescales/sdk/orders';
import { badge } from '@timescales/sdk/orders';
import type { LucideIcon } from 'lucide-react';
import {
  Ban,
  CircleAlert,
  CircleCheck,
  CircleDashed,
  CircleDot,
  CircleSlash,
  Clock,
  Cpu,
  FileWarning,
  Hourglass,
  Layers,
  Link,
  Lock,
  OctagonAlert,
  PauseCircle,
  PenLine,
  RotateCcw,
  Send,
  ShieldCheck,
  Wallet,
  X,
} from 'lucide-react';

import type { Tone } from '../../components/types';
import { failedCodeMessage } from '../trade/errors';
import type { NumberFormat } from '../trade/services';
import { localize, priceOf } from '../trade/units';
import { ordersCopy } from './copy';
import { fillTick } from './fills';

export interface BadgeContext {
  record: OrderRecord;
  epoch: bigint | undefined;
  participation: Participation | undefined;
  units: UnitContext | null;
  numberFormat: NumberFormat;
}

export interface BadgeSpec {
  icon: LucideIcon;
  tone: Tone;
  text: (c: BadgeContext) => string;
  /** "Filled" with the slat animation appears only once the epoch is settled. */
  slats?: 'open' | 'closed';
}

const b = ordersCopy.badge;
const e = (c: BadgeContext) => (c.epoch ?? c.participation?.epoch ?? 0n).toString();

function percentOf(part: bigint, whole: bigint): string {
  if (whole <= 0n) return '0';
  const hundredths = (part * 10_000n) / whole;
  const int = hundredths / 100n;
  const frac = (hundredths % 100n).toString().padStart(2, '0').replace(/0+$/, '');
  return frac ? `${int}.${frac}` : int.toString();
}

function placed(c: BadgeContext) {
  return c.record.body.kind === 'place' ? c.record.body.order : null;
}

function parkedRange(c: BadgeContext): [string, string] {
  const epochs = [...c.record.epochs.values()]
    .filter((p) => p.state.kind === 'parked' || p.state.kind === 'sealed')
    .map((p) => p.epoch)
    .sort((x, y) => (x < y ? -1 : x > y ? 1 : 0));
  const from = c.epoch ?? epochs[0] ?? 0n;
  const to = epochs[epochs.length - 1] ?? from;
  return [from.toString(), (to < from ? from : to).toString()];
}

function verifiedText(c: BadgeContext, filled: bigint): string {
  const order = placed(c);
  if (filled === 0n || order === null) return b.verifiedNone(e(c));
  const epoch = c.participation?.epoch ?? c.epoch ?? 0n;
  const tick = fillTick(c.record, epoch);
  const price =
    tick === null || c.units === null ? '-' : localize(priceOf(c.units, tick), c.numberFormat);
  let text = b.verifiedFilled(percentOf(filled, order.quantity), price);
  // Market orders never show a price improvement.
  if (order.kind === 0 && tick !== null && order.limit > 0n) {
    const better = order.side === 0 ? order.limit - tick : tick - order.limit;
    if (better > 0n) text += ` (${b.betterThanLimit(percentOf(better, order.limit))})`;
  }
  return text;
}

export const ORDER_BADGES: Record<OrderState['kind'], BadgeSpec> = {
  draft: { icon: PenLine, tone: 'neutral', text: () => b.draft },
  awaiting_wallet: { icon: Wallet, tone: 'accent', text: () => b.awaiting_wallet },
  wallet_rejected: { icon: X, tone: 'neutral', text: () => b.wallet_rejected },
  unsupported_wallet: { icon: CircleAlert, tone: 'danger', text: () => b.unsupported_wallet },
  abandoned: { icon: CircleSlash, tone: 'neutral', text: () => b.abandoned },
  signed_too_late: { icon: Clock, tone: 'warning', text: () => b.signed_too_late },
  submitting: { icon: Send, tone: 'accent', text: () => b.submitting },
  submit_failed: {
    icon: CircleAlert,
    tone: 'danger',
    text: (c) =>
      b.submit_failed(
        c.record.state.kind === 'submit_failed'
          ? failedCodeMessage(c.record.state.code, c.epoch ?? null)
          : '',
      ),
  },
  working: { icon: CircleDot, tone: 'accent', text: () => b.working },
  paused_needs_app: { icon: PauseCircle, tone: 'warning', text: () => b.paused_needs_app },
  reseal_needs_consent: {
    icon: RotateCcw,
    tone: 'warning',
    text: (c) => b.reseal_needs_consent(e(c)),
  },
  filled: { icon: CircleCheck, tone: 'buy', text: () => b.filled, slats: 'open' },
  expired: { icon: Hourglass, tone: 'neutral', text: () => b.expired },
  cancel_pending: { icon: Hourglass, tone: 'neutral', text: (c) => b.cancel_pending(e(c)) },
  cancelled: { icon: Ban, tone: 'neutral', text: () => b.cancelled },
  cancel_too_late: { icon: Ban, tone: 'warning', text: () => b.cancel_too_late },
  verification_failed: {
    icon: OctagonAlert,
    tone: 'danger',
    text: (c) =>
      b.verification_failed(
        c.record.state.kind === 'verification_failed' ? c.record.state.check : '',
      ),
  },
};

export const PARTICIPATION_BADGES: Record<ParticipationState['kind'], BadgeSpec> = {
  sealed: { icon: ShieldCheck, tone: 'accent', text: (c) => b.sealed(e(c)), slats: 'closed' },
  parked: {
    icon: Layers,
    tone: 'accent',
    text: (c) => {
      const [from, to] = parkedRange(c);
      return b.parked(from, to);
    },
  },
  not_submitted: {
    icon: CircleDashed,
    tone: 'warning',
    text: (c) => {
      const s = c.participation?.state;
      const epoch = c.participation?.epoch ?? c.epoch ?? 0n;
      if (s?.kind === 'not_submitted' && s.reason !== 'quota') {
        return b.not_submitted_reason[s.reason](epoch.toString());
      }
      return b.not_submitted((epoch - 1n).toString());
    },
  },
  locked: { icon: Lock, tone: 'neutral', text: () => b.locked },
  included: { icon: Link, tone: 'info', text: (c) => b.included(e(c)) },
  excluded: { icon: FileWarning, tone: 'danger', text: (c) => b.excluded(e(c)) },
  clearing: {
    icon: Cpu,
    tone: 'info',
    text: (c) =>
      c.participation?.state.kind === 'clearing' && c.participation.state.delayed
        ? b.clearingDelayed
        : b.clearing,
  },
  provisional: {
    icon: Hourglass,
    tone: 'info',
    text: (c) => {
      const s = c.participation?.state;
      return s?.kind === 'provisional' ? b.provisional(s.have, s.need) : b.provisional(0, 0);
    },
  },
  verified: {
    icon: CircleCheck,
    tone: 'buy',
    text: (c) => {
      const s = c.participation?.state;
      return verifiedText(c, s?.kind === 'verified' ? s.filled : 0n);
    },
  },
  settling: {
    icon: Hourglass,
    tone: 'info',
    text: (c) => {
      const s = c.participation?.state;
      return s?.kind === 'settling' ? b.settling(s.done, s.total) : b.settling(0, 0);
    },
  },
  settled: {
    icon: CircleCheck,
    tone: 'buy',
    text: (c) => {
      const s = c.participation?.state;
      return s?.kind === 'settled' && s.filled > 0n ? b.settledFilled : b.settled;
    },
    slats: 'open',
  },
  voided: {
    icon: Ban,
    tone: 'warning',
    text: (c) => {
      const epoch = c.participation?.epoch ?? c.epoch ?? 0n;
      const continues =
        c.record.state.kind === 'working' && [...c.record.epochs.keys()].some((x) => x > epoch);
      return continues
        ? b.voidedContinues(epoch.toString(), (epoch + 1n).toString())
        : b.voidedEnded(epoch.toString());
    },
  },
};

export interface ResolvedBadge {
  kind: OrderState['kind'] | ParticipationState['kind'];
  spec: BadgeSpec;
  text: string;
  epoch: bigint | undefined;
  /** Verified with nothing filled: the badge offers "Why?". */
  notFilled: boolean;
}

function isParticipationKind(k: string): k is ParticipationState['kind'] {
  return Object.hasOwn(PARTICIPATION_BADGES, k);
}

/** The order's badge by the SDK's precedence rule (`badge`). */
export function resolveBadge(
  record: OrderRecord,
  units: UnitContext | null,
  numberFormat: NumberFormat,
): ResolvedBadge {
  const { state, epoch } = badge(record);
  return describe(record, state, epoch, units, numberFormat);
}

/** The badge of one epoch participation (a lane of the drawer's timeline). */
export function participationBadge(
  record: OrderRecord,
  p: Participation,
  units: UnitContext | null,
  numberFormat: NumberFormat,
): ResolvedBadge {
  return describe(record, p.state.kind, p.epoch, units, numberFormat);
}

function describe(
  record: OrderRecord,
  kind: OrderState['kind'] | ParticipationState['kind'],
  epoch: bigint | undefined,
  units: UnitContext | null,
  numberFormat: NumberFormat,
): ResolvedBadge {
  const participation = epoch === undefined ? undefined : record.epochs.get(epoch);
  const spec = isParticipationKind(kind)
    ? PARTICIPATION_BADGES[kind]
    : ORDER_BADGES[kind as OrderState['kind']];
  const ctx: BadgeContext = { record, epoch, participation, units, numberFormat };
  const notFilled = participation?.state.kind === 'verified' && participation.state.filled === 0n;
  return { kind, spec, text: spec.text(ctx), epoch, notFilled: kind === 'verified' && notFilled };
}
