// The product name and mark live here and in Wordmark.tsx only, so a
// rename is a change to this file. Copy interpolates `brand.name`.

export const brand = {
  /** Product name as used in running text. */
  name: 'Timescales',
  /** The wordmark's text: always lowercase. */
  wordmark: 'timescales',
  /** Three slats in the lock-up: three successive epochs. */
  slats: 3,
} as const;
