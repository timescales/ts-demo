// Types the app shares across state modules. The kit `Address` brand is
// taken from the SDK's own declarations, so the app needs no direct
// dependency on @solana/kit.
import { b58 } from '@timescales/sdk/core';
import type { AppPins } from '@timescales/sdk/verify';

export type Address = AppPins['programId'];
export type Cluster = AppPins['cluster'];

/** A base58 Solana address of 32 bytes, or null. */
export function parseAddress(text: string | null | undefined): Address | null {
  if (text === null || text === undefined || text.length < 32 || text.length > 44) return null;
  try {
    b58.decode(text, 32);
  } catch {
    return null;
  }
  return text as Address;
}

/** A decimal u64, or null. */
export function parseU64(text: string | null | undefined): bigint | null {
  if (text === null || text === undefined || !/^(0|[1-9][0-9]{0,19})$/.test(text)) return null;
  const v = BigInt(text);
  return v <= 0xffff_ffff_ffff_ffffn ? v : null;
}
