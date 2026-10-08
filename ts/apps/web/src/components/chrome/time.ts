/** mm:ss for a countdown. Negative and fractional seconds clamp down. */
export function formatCountdown(seconds: number): string {
  const total = Number.isFinite(seconds) ? Math.max(0, Math.floor(seconds)) : 0;
  const minutes = Math.floor(total / 60);
  const rest = total % 60;
  return `${String(minutes).padStart(2, '0')}:${String(rest).padStart(2, '0')}`;
}

/** "1h 05m" from an hour up, mm:ss below. */
export function formatRemaining(seconds: number): string {
  const total = Number.isFinite(seconds) ? Math.max(0, Math.floor(seconds)) : 0;
  if (total < 3600) return formatCountdown(total);
  const hours = Math.floor(total / 3600);
  const minutes = Math.floor((total % 3600) / 60);
  return `${hours}h ${String(minutes).padStart(2, '0')}m`;
}

/** First and last characters of an address. */
export function shortAddress(address: string, keep = 4): string {
  return address.length > keep * 2 + 1
    ? `${address.slice(0, keep)}...${address.slice(-keep)}`
    : address;
}
