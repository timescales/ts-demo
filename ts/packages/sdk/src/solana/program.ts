import type { AccountMeta, AccountRole, Address } from '@solana/kit';
import { b58 } from '../core/encoding/base58.js';
import { DecodeError, Reader } from '../core/encoding/codec.js';
import { findProgramAddressSync } from './pdas.js';

// kit's `AccountRole` values. The enum itself is runtime code this file may not import.
export const READONLY = 0 as AccountRole.READONLY;
export const WRITABLE = 1 as AccountRole.WRITABLE;
export const READONLY_SIGNER = 2 as AccountRole.READONLY_SIGNER;
export const WRITABLE_SIGNER = 3 as AccountRole.WRITABLE_SIGNER;

export function meta(address: Address, role: AccountRole): AccountMeta {
  return { address, role };
}

export const SYSTEM_PROGRAM = '11111111111111111111111111111111' as Address;
export const TOKEN_PROGRAM = 'TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA' as Address;
export const ASSOCIATED_TOKEN_PROGRAM = 'ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL' as Address;
export const COMPUTE_BUDGET_PROGRAM = 'ComputeBudget111111111111111111111111111111' as Address;
export const BPF_LOADER_UPGRADEABLE = 'BPFLoaderUpgradeab1e11111111111111111111111' as Address;
export const SLOT_HASHES_SYSVAR = 'SysvarS1otHashes111111111111111111111111111' as Address;

/** `UpgradeableLoaderState::ProgramData` metadata: `u32 tag (3) || slot u64 || Option<Pubkey>`, 45 bytes. */
const PROGRAM_DATA_TAG = 3;
const PROGRAM_DATA_METADATA_LEN = 45;

/** Decodes an upgradeable-loader ProgramData account (V-16). */
export function decodeProgramData(d: Uint8Array): {
  upgradeAuthority: Address | null;
  lastDeploySlot: bigint;
} {
  if (d.length < PROGRAM_DATA_METADATA_LEN) {
    throw new DecodeError('eof', `ProgramData shorter than ${PROGRAM_DATA_METADATA_LEN} bytes`);
  }
  const r = new Reader(d.subarray(0, PROGRAM_DATA_METADATA_LEN));
  const tag = r.u32();
  if (tag !== PROGRAM_DATA_TAG) throw new DecodeError('tag', `loader state ${tag}`);
  const lastDeploySlot = r.u64();
  const some = r.u8();
  const key = r.fixed(32);
  if (some > 1) throw new DecodeError('tag', `Option tag ${some}`);
  return { upgradeAuthority: some === 1 ? (b58.encode(key) as Address) : null, lastDeploySlot };
}

/** The ProgramData account of an upgradeable program: the loader's PDA of `[program]`. */
export function programDataAddress(program: Address): Address {
  return findProgramAddressSync([b58.decode(program, 32)], BPF_LOADER_UPGRADEABLE)[0];
}
