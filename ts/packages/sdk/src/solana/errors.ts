import type { Address } from '@solana/kit';
import { SYSTEM_PROGRAM, TOKEN_PROGRAM } from './program.js';

export type ProgramFailure = {
  program: 'settlement' | 'token' | 'system' | 'other';
  code: number;
  name: string | null;
  instructionIndex: number;
};

/** Settlement program error names by code (6016 is reserved). */
export const SETTLEMENT_ERRORS: Readonly<Record<number, string>> = Object.freeze({
  6001: 'InvalidInstruction',
  6002: 'InvalidAccount',
  6003: 'Unauthorised',
  6004: 'OutOfOrder',
  6005: 'HeaderMismatch',
  6006: 'ReceiptMismatch',
  6007: 'BadSignature',
  6008: 'UnknownExecutor',
  6009: 'BadProof',
  6010: 'DuplicateLeaf',
  6011: 'Insolvent',
  6012: 'NotConserved',
  6013: 'Incomplete',
  6014: 'WrongStatus',
  6015: 'TooManyDeltas',
  6017: 'WithdrawLocked',
  6018: 'Overflow',
  6019: 'Halted',
  6020: 'BeaconNotReady',
  6021: 'BeaconExpired',
  6022: 'InFlight',
  6023: 'NotExpired',
  6024: 'DuplicateTrader',
  6025: 'ParamsMismatch',
  6026: 'StateRootMismatch',
  6027: 'UnsupportedVersion',
  6028: 'TermsMismatch',
  6029: 'InvalidParams',
  6030: 'InvalidConfig',
  6031: 'WithdrawPending',
  6032: 'NothingToWithdraw',
  6033: 'Timelocked',
  6034: 'ChangePending',
  6035: 'NoPendingChange',
  6036: 'NotPendingAdmin',
  6037: 'RetentionNotReached',
  6038: 'BalanceCap',
  6039: 'QuorumNotMet',
  6040: 'AlreadyCosigned',
  6041: 'BackendNotAllowed',
  6042: 'InvalidBatchCount',
  6043: 'AccountNotEmpty',
  6044: 'InvalidTokenAccount',
  6045: 'InvalidAbortReason',
  6046: 'ChangeDue',
  6047: 'InvalidMarketId',
});

/** `spl_token::error::TokenError`. */
const TOKEN_ERRORS: readonly string[] = [
  'NotRentExempt',
  'InsufficientFunds',
  'InvalidMint',
  'MintMismatch',
  'OwnerMismatch',
  'FixedSupply',
  'AlreadyInUse',
  'InvalidNumberOfProvidedSigners',
  'InvalidNumberOfRequiredSigners',
  'UninitializedState',
  'NativeNotSupported',
  'NonNativeHasBalance',
  'InvalidInstruction',
  'InvalidState',
  'Overflow',
  'AuthorityTypeNotSupported',
  'MintCannotFreeze',
  'AccountFrozen',
  'MintDecimalsMismatch',
  'NonNativeNotSupported',
];

/** `solana_system_interface::error::SystemError`. */
const SYSTEM_ERRORS: readonly string[] = [
  'AccountAlreadyInUse',
  'ResultWithNegativeLamports',
  'InvalidProgramId',
  'InvalidAccountDataLength',
  'MaxSeedLengthExceeded',
  'AddressWithSeedMismatch',
  'NonceNoRecentBlockhashes',
  'NonceBlockhashNotExpired',
  'NonceUnexpectedBlockhashValue',
];

const INVOKE = /^Program (\w+) invoke \[(\d+)\]$/;
const FAILED = /^Program (\w+) failed: (.*)$/;
const CUSTOM = /^custom program error: 0x([0-9a-fA-F]+)$/;

function classify(id: string, settlement: (id: string) => boolean): ProgramFailure['program'] {
  if (settlement(id)) return 'settlement';
  if (id === TOKEN_PROGRAM) return 'token';
  if (id === SYSTEM_PROGRAM) return 'system';
  return 'other';
}

function errorName(kind: ProgramFailure['program'], code: number): string | null {
  switch (kind) {
    case 'settlement':
      return SETTLEMENT_ERRORS[code] ?? null;
    case 'token':
      return TOKEN_ERRORS[code] ?? null;
    case 'system':
      return SYSTEM_ERRORS[code] ?? null;
    case 'other':
      return null;
  }
}

/**
 * Maps transaction logs to the failing program and its error. The first
 * `failed` line is the innermost failure, so a Token or System error raised
 * through a CPI is attributed to that program, not to the settlement program
 * that invoked it. `instructionIndex` counts top-level instructions,
 * compute-budget ones included. A failure that is not a custom error (for
 * example "invalid account data") has code -1 and the runtime's message as
 * its name. Null when the logs show no failure.
 */
export function decodeProgramFailure(
  logs: readonly string[],
  program: Address,
): ProgramFailure | null {
  return decodeFailure(logs, (id) => id === program);
}

/** {@link decodeProgramFailure} with the settlement program given as a test: none, one or several ids. */
export function decodeFailure(
  logs: readonly string[],
  settlement: (id: string) => boolean,
): ProgramFailure | null {
  let instructionIndex = -1;
  for (const line of logs) {
    const invoke = INVOKE.exec(line);
    if (invoke !== null) {
      if (invoke[2] === '1') instructionIndex++;
      continue;
    }
    const failed = FAILED.exec(line);
    if (failed === null) continue;
    const kind = classify(failed[1]!, settlement);
    const custom = CUSTOM.exec(failed[2]!);
    if (custom === null) {
      return { program: kind, code: -1, name: failed[2]!, instructionIndex };
    }
    const code = Number.parseInt(custom[1]!, 16);
    return { program: kind, code, name: errorName(kind, code), instructionIndex };
  }
  return null;
}
