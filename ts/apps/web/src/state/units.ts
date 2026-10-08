import { parseDecimal } from '@timescales/sdk/core';

import type { NumberFormat } from './settings';
import { NUMBER_LOCALES } from './settings';

/**
 * A token amount typed in the user's declared number format as integer atoms
 * (`decimals` places). Throws on ambiguous separators, on more decimals than
 * the token has, and on zero.
 */
export function amountToAtoms(input: string, decimals: number, format: NumberFormat): bigint {
  const canonical = parseDecimal(input, NUMBER_LOCALES[format]);
  const [whole, frac = ''] = canonical.split('.');
  if (frac.length > decimals) throw new RangeError(`at most ${decimals} decimal places`);
  const atoms = BigInt(whole! + frac.padEnd(decimals, '0'));
  if (atoms <= 0n) throw new RangeError('the amount must be positive');
  return atoms;
}

/** Integer atoms as a decimal string with `decimals` places, trailing zeros trimmed. */
export function atomsToAmount(atoms: bigint, decimals: number): string {
  if (decimals === 0) return atoms.toString();
  const s = atoms.toString().padStart(decimals + 1, '0');
  const frac = s.slice(-decimals).replace(/0+$/, '');
  return frac.length > 0 ? `${s.slice(0, -decimals)}.${frac}` : s.slice(0, -decimals);
}
