// Token amounts typed in the declared number format, as atoms.
import type { NumberFormat } from '../trade/services';
import { canonical, decimalToAtoms } from '../trade/units';

/**  `MAX_BALANCE` (`i64::MAX`): a deposit that would pass it fails with `BalanceCap`. */
export const MAX_BALANCE = 2n ** 63n - 1n;

export type AmountError = 'empty' | 'syntax' | 'ambiguous' | 'zero' | 'too_large' | 'precision';

export type AmountParse = { ok: true; atoms: bigint } | { ok: false; error: AmountError };

/** `max` bounds the amount (a balance). An empty field is allowed only with `optional`. */
export function parseAmount(
  text: string,
  format: NumberFormat,
  decimals: number,
  o: { max?: bigint | null; optional?: boolean } = {},
): AmountParse {
  if (text.trim() === '' && o.optional) return { ok: true, atoms: 0n };
  const c = canonical(text, format);
  if (!c.ok) return { ok: false, error: c.error === 'zero' ? 'zero' : c.error };
  const atoms = decimalToAtoms(c.value, decimals);
  if (atoms === null) return { ok: false, error: 'precision' };
  if (atoms === 0n && !o.optional) return { ok: false, error: 'zero' };
  if (o.max !== undefined && o.max !== null && atoms > o.max) {
    return { ok: false, error: 'too_large' };
  }
  return { ok: true, atoms };
}
