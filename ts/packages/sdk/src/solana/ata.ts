import type { Address, Instruction } from '@solana/kit';
import { b58 } from '../core/encoding/base58.js';
import { findProgramAddressSync } from './pdas.js';
import {
  ASSOCIATED_TOKEN_PROGRAM,
  READONLY,
  SYSTEM_PROGRAM,
  TOKEN_PROGRAM,
  WRITABLE,
  WRITABLE_SIGNER,
  meta,
} from './program.js';

/** Associated-token-account instruction tag `CreateIdempotent`. */
const CREATE_IDEMPOTENT = 1;

export function associatedTokenAddressSync(owner: Address, mint: Address): Address {
  return findProgramAddressSync(
    [b58.decode(owner, 32), b58.decode(TOKEN_PROGRAM, 32), b58.decode(mint, 32)],
    ASSOCIATED_TOKEN_PROGRAM,
  )[0];
}

/** The classic SPL Token associated token account of `owner` for `mint`. */
export function associatedTokenAddress(owner: Address, mint: Address): Promise<Address> {
  return Promise.resolve().then(() => associatedTokenAddressSync(owner, mint));
}

/** Creates the associated token account unless it exists (used before a withdrawal). */
export function createAtaIdempotentIx(a: {
  payer: Address;
  owner: Address;
  mint: Address;
}): Promise<Instruction> {
  return Promise.resolve().then(() => ({
    programAddress: ASSOCIATED_TOKEN_PROGRAM,
    accounts: [
      meta(a.payer, WRITABLE_SIGNER),
      meta(associatedTokenAddressSync(a.owner, a.mint), WRITABLE),
      meta(a.owner, READONLY),
      meta(a.mint, READONLY),
      meta(SYSTEM_PROGRAM, READONLY),
      meta(TOKEN_PROGRAM, READONLY),
    ],
    data: Uint8Array.of(CREATE_IDEMPOTENT),
  }));
}
