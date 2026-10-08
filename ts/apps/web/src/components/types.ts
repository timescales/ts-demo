// Shapes the presentational components accept. They mirror the public API
// so callers can pass SDK values straight through.

/**  `PublicPhase`. `unknown` is a phase a newer node added. */
export type PublicPhase =
  | 'scheduled'
  | 'open'
  | 'closed'
  | 'committed'
  | 'revealed'
  | 'executing'
  | 'posted'
  | 'settled'
  | 'aborting'
  | 'aborted'
  | 'unknown';

export type Side = 'buy' | 'sell';

/** u64 values (epochs, slots) arrive as bigint or as decimal strings. */
export type U64 = bigint | string;

export type Tone =
  'neutral' | 'accent' | 'buy' | 'sell' | 'info' | 'warning' | 'danger' | 'simulated';
