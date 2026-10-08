import type { LucideIcon } from 'lucide-react';
import {
  Ban,
  CircleCheck,
  CircleDot,
  Clock,
  Cpu,
  Dices,
  FileCheck,
  CircleHelp,
  Lock,
  Hourglass,
  Link,
} from 'lucide-react';

import { componentsCopy } from '../copy';
import type { PublicPhase, Tone } from '../types';
import { Badge } from './Badge';

const PHASES: Record<PublicPhase, { icon: LucideIcon; tone: Tone }> = {
  scheduled: { icon: Clock, tone: 'neutral' },
  open: { icon: CircleDot, tone: 'info' },
  closed: { icon: Lock, tone: 'neutral' },
  committed: { icon: Link, tone: 'neutral' },
  revealed: { icon: Dices, tone: 'neutral' },
  executing: { icon: Cpu, tone: 'info' },
  posted: { icon: FileCheck, tone: 'info' },
  settled: { icon: CircleCheck, tone: 'buy' },
  aborting: { icon: Hourglass, tone: 'warning' },
  aborted: { icon: Ban, tone: 'warning' },
  unknown: { icon: CircleHelp, tone: 'neutral' },
};

export interface PhaseBadgeProps {
  phase: PublicPhase;
}

/** An epoch's public phase as glyph + word. */
export function PhaseBadge({ phase }: PhaseBadgeProps) {
  const { icon: Icon, tone } = PHASES[phase];
  return (
    <Badge tone={tone} icon={<Icon aria-hidden="true" />}>
      {componentsCopy.phase[phase]}
    </Badge>
  );
}
