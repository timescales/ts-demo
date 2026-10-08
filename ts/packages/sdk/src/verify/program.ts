import type { MarketAccount } from '../solana/accounts.js';
import { decodeProgramData } from '../solana/program.js';
import type { AppPins } from './market.js';
import { check, must, type Verdict } from './verdict.js';

/**
 * V-16: the program's ProgramData names the upgrade authority the app pins
 * (null for a frozen program). A deploy within the market's timelock window
 * of `nowSlot` is reported as a recent upgrade (a warning, not a failure).
 */
export function verifyProgram(
  programData: Uint8Array,
  pins: AppPins,
  market: MarketAccount,
  nowSlot: bigint,
): Verdict<{ recentUpgrade: boolean }> {
  return check('V-16 program', () => {
    const pd = decodeProgramData(programData);
    must(
      pd.upgradeAuthority === pins.upgradeAuthority,
      "the program's upgrade authority is not the expected one",
    );
    return { recentUpgrade: nowSlot < pd.lastDeploySlot + market.timelockSlots };
  });
}
