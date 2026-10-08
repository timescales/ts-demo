import type { Instruction } from '@solana/kit';
import { Writer } from '../core/encoding/codec.js';
import { COMPUTE_BUDGET_PROGRAM } from './program.js';

// ComputeBudget instruction tags (solana-compute-budget-interface).
const SET_COMPUTE_UNIT_LIMIT = 2;
const SET_COMPUTE_UNIT_PRICE = 3;

/** `SetComputeUnitLimit`: `2 || units u32`. */
export function computeUnitLimitIx(units: number): Instruction {
  return {
    programAddress: COMPUTE_BUDGET_PROGRAM,
    data: new Writer().u8(SET_COMPUTE_UNIT_LIMIT).u32(units).finish(),
  };
}

/** `SetComputeUnitPrice`: `3 || micro-lamports per CU u64`. */
export function computeUnitPriceIx(microLamports: bigint): Instruction {
  return {
    programAddress: COMPUTE_BUDGET_PROGRAM,
    data: new Writer().u8(SET_COMPUTE_UNIT_PRICE).u64(microLamports).finish(),
  };
}
