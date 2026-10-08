// Duration presets come from the SDK's lifetimePresets: never above
// max_order_lifetime + 1, and "This epoch" only for intervals of 30 s or more.
import type { MarketParams } from '@timescales/sdk/core';
import { lifetimePresets } from '@timescales/sdk/orders';

import { formatDuration } from './clock';
import { tradeCopy } from './copy';

/** The SDK's default signing budget before any signature was timed: p95 15 s + 2 s + p95 submit 1 s. */
export const DEFAULT_SIGN_BUDGET_MS = 18_000;

export interface DurationPreset {
  epochs: number;
  label: string;
}

export function durationPresets(
  params: MarketParams,
  intervalMs: number,
  signBudgetMs: number,
): DurationPreset[] {
  const copy = tradeCopy.ticket;
  const presets = lifetimePresets(params, intervalMs, signBudgetMs);
  return presets.map((p, i) => {
    const isMax = i === presets.length - 1 && p.label.startsWith('Max');
    const label = isMax
      ? copy.presetMax(p.epochs)
      : p.epochs === 1
        ? copy.presetThisEpoch
        : p.epochs === 2
          ? copy.presetNext(p.epochs)
          : copy.presetEpochs(p.epochs);
    return {
      epochs: p.epochs,
      label: copy.presetAbout(label, formatDuration(p.epochs * intervalMs)),
    };
  });
}
