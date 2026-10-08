import type { MarketParams } from '../core/protocol/params.js';

/** Below this interval an order cannot be signed and sealed reliably within one epoch. */
const SINGLE_EPOCH_MIN_INTERVAL_MS = 30_000;

/**
 * Lifetime presets. `epochs` is `expiresAt - validFrom + 1`, because
 * the executor accepts `expiresAt - validFrom <= maxOrderLifetime`, so no
 * preset exceeds `maxOrderLifetime + 1`. "This epoch" is offered only when
 * the interval is at least 30 s and the signing budget fits inside it. The
 * shortest preset otherwise is "Next clearing" (2 epochs), which reaches
 * the next clearing even when the open epoch closes while the wallet signs.
 */
export function lifetimePresets(
  params: MarketParams,
  epochIntervalMs: number,
  signBudgetMs: number,
): { epochs: number; label: string }[] {
  const max = params.maxOrderLifetime + 1;
  const candidates: { epochs: number; label: string }[] = [];
  if (epochIntervalMs >= SINGLE_EPOCH_MIN_INTERVAL_MS && signBudgetMs < epochIntervalMs) {
    candidates.push({ epochs: 1, label: 'This epoch' });
  }
  candidates.push({ epochs: 2, label: 'Next clearing (2)' }, { epochs: 4, label: '4 epochs' });
  const out = candidates.filter((p) => p.epochs < max);
  if (max >= 2 || out.length === 0) {
    out.push({ epochs: max, label: max === 1 ? 'Max: 1 epoch' : `Max: ${max} epochs` });
  }
  return out;
}
