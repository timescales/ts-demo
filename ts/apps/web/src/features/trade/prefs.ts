// Remembered ticket choices (WCAG 3.3.7 Redundant Entry). Browser storage can
// be missing or throw (private windows, blocked site data). The ticket then
// starts from its defaults.

const ROLE_KEY = 'ts.trade.role';
const LIFETIME_KEY = 'ts.trade.lifetime';

function read(key: string): string | null {
  try {
    return globalThis.localStorage?.getItem(key) ?? null;
  } catch {
    return null;
  }
}

function write(key: string, value: string): void {
  try {
    globalThis.localStorage?.setItem(key, value);
  } catch {
    // Not remembered. Nothing else depends on it.
  }
}

export function lastRole(): 0 | 1 {
  return read(ROLE_KEY) === 'taker' ? 1 : 0;
}

export function rememberRole(role: 0 | 1): void {
  write(ROLE_KEY, role === 1 ? 'taker' : 'maker');
}

export function lastLifetime(): number | null {
  const v = Number(read(LIFETIME_KEY));
  return Number.isInteger(v) && v > 0 ? v : null;
}

export function rememberLifetime(epochs: number): void {
  write(LIFETIME_KEY, String(epochs));
}

export function readPref(key: string): string | null {
  return read(key);
}

export function writePref(key: string, value: string): void {
  write(key, value);
}
