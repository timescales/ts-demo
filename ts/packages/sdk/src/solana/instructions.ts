import type { Address, Instruction } from '@solana/kit';
import { Writer } from '../core/encoding/codec.js';
import { batchSeeds, findProgramAddressSync, traderSeeds } from './pdas.js';
import {
  READONLY,
  READONLY_SIGNER,
  SLOT_HASHES_SYSVAR,
  SYSTEM_PROGRAM,
  TOKEN_PROGRAM,
  WRITABLE,
  WRITABLE_SIGNER,
  meta,
} from './program.js';

// Trader instructions of settlement program v2: one tag byte, then
// fixed-width little-endian fields. Account order and roles follow the
// program's processor.
const OPEN_TRADER = 1;
const DEPOSIT = 2;
const REQUEST_WITHDRAW = 3;
const WITHDRAW = 4;
const REVEAL_BEACON = 12;
const CANCEL_WITHDRAW_REQUEST = 14;
const CLOSE_TRADER = 23;

function sideByte(side: 'base' | 'quote'): number {
  if (side !== 'base' && side !== 'quote') throw new RangeError(`side ${String(side)}`);
  return side === 'quote' ? 1 : 0;
}

function trader(program: Address, market: Address, owner: Address): Address {
  return findProgramAddressSync(traderSeeds(market, owner), program)[0];
}

/** `OpenTrader`: `[owner (w, s), market, trader PDA (w), System]`. */
export function openTraderIx(a: {
  program: Address;
  owner: Address;
  market: Address;
}): Promise<Instruction> {
  return Promise.resolve().then(() => ({
    programAddress: a.program,
    accounts: [
      meta(a.owner, WRITABLE_SIGNER),
      meta(a.market, READONLY),
      meta(trader(a.program, a.market, a.owner), WRITABLE),
      meta(SYSTEM_PROGRAM, READONLY),
    ],
    data: Uint8Array.of(OPEN_TRADER),
  }));
}

/** `Deposit`: `2 || side u8 || amount u64`. `[owner (s), market, trader (w), source (w), vault (w), Token]`. */
export function depositIx(a: {
  program: Address;
  owner: Address;
  market: Address;
  source: Address;
  vault: Address;
  side: 'base' | 'quote';
  amount: bigint;
}): Promise<Instruction> {
  return Promise.resolve().then(() => {
    if (a.amount <= 0n) throw new RangeError('deposit amount must be positive');
    return {
      programAddress: a.program,
      accounts: [
        meta(a.owner, READONLY_SIGNER),
        meta(a.market, READONLY),
        meta(trader(a.program, a.market, a.owner), WRITABLE),
        meta(a.source, WRITABLE),
        meta(a.vault, WRITABLE),
        meta(TOKEN_PROGRAM, READONLY),
      ],
      data: new Writer().u8(DEPOSIT).u8(sideByte(a.side)).u64(a.amount).finish(),
    };
  });
}

/** `RequestWithdraw`: `3 || base u64 || quote u64`. Reserves, never debits. */
export function requestWithdrawIx(a: {
  program: Address;
  owner: Address;
  market: Address;
  base: bigint;
  quote: bigint;
}): Promise<Instruction> {
  return Promise.resolve().then(() => {
    if (a.base === 0n && a.quote === 0n) throw new RangeError('nothing to withdraw');
    return {
      programAddress: a.program,
      accounts: [
        meta(a.owner, READONLY_SIGNER),
        meta(a.market, READONLY),
        meta(trader(a.program, a.market, a.owner), WRITABLE),
      ],
      data: new Writer().u8(REQUEST_WITHDRAW).u64(a.base).u64(a.quote).finish(),
    };
  });
}

/** `CancelWithdrawRequest`: `14`. */
export function cancelWithdrawRequestIx(a: {
  program: Address;
  owner: Address;
  market: Address;
}): Promise<Instruction> {
  return Promise.resolve().then(() => ({
    programAddress: a.program,
    accounts: [
      meta(a.owner, READONLY_SIGNER),
      meta(a.market, READONLY),
      meta(trader(a.program, a.market, a.owner), WRITABLE),
    ],
    data: Uint8Array.of(CANCEL_WITHDRAW_REQUEST),
  }));
}

/** `Withdraw`: `4 || side u8`. `[owner (s), market, trader (w), vault (w), dest (w), Token]`. */
export function withdrawIx(a: {
  program: Address;
  owner: Address;
  market: Address;
  vault: Address;
  dest: Address;
  side: 'base' | 'quote';
}): Promise<Instruction> {
  return Promise.resolve().then(() => ({
    programAddress: a.program,
    accounts: [
      meta(a.owner, READONLY_SIGNER),
      meta(a.market, READONLY),
      meta(trader(a.program, a.market, a.owner), WRITABLE),
      meta(a.vault, WRITABLE),
      meta(a.dest, WRITABLE),
      meta(TOKEN_PROGRAM, READONLY),
    ],
    data: new Writer().u8(WITHDRAW).u8(sideByte(a.side)).finish(),
  }));
}

/** `CloseTrader`: `23`. `[owner (w, s), market, trader (w)]`. Rent goes to the owner. */
export function closeTraderIx(a: {
  program: Address;
  owner: Address;
  market: Address;
}): Promise<Instruction> {
  return Promise.resolve().then(() => ({
    programAddress: a.program,
    accounts: [
      meta(a.owner, WRITABLE_SIGNER),
      meta(a.market, READONLY),
      meta(trader(a.program, a.market, a.owner), WRITABLE),
    ],
    data: Uint8Array.of(CLOSE_TRADER),
  }));
}

/** Manual, user-paid reveal: `12`. `[cranker (s), market, batch (w), SlotHashes]`. */
export function revealBeaconIx(a: {
  program: Address;
  cranker: Address;
  market: Address;
  epoch: bigint;
}): Promise<Instruction> {
  return Promise.resolve().then(() => ({
    programAddress: a.program,
    accounts: [
      meta(a.cranker, READONLY_SIGNER),
      meta(a.market, READONLY),
      meta(findProgramAddressSync(batchSeeds(a.market, a.epoch), a.program)[0], WRITABLE),
      meta(SLOT_HASHES_SYSVAR, READONLY),
    ],
    data: Uint8Array.of(REVEAL_BEACON),
  }));
}
