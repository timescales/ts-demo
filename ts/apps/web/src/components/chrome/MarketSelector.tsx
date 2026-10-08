import { componentsCopy } from '../copy';
import { Select } from '../primitives/Select';

export interface MarketOption {
  /** Public market address. */
  address: string;
  /** Pair, e.g. "SOL/USDC". */
  label: string;
  /** Null while the market's parameters are not loaded yet. */
  flow: 'single_book' | 'dual_flow' | null;
}

export interface MarketSelectorProps {
  markets: readonly MarketOption[];
  value: string;
  onChange: (address: string) => void;
  id?: string | undefined;
  /** Label beside the select, for the top bar. */
  compact?: boolean | undefined;
}

export function MarketSelector({
  markets,
  value,
  onChange,
  id,
  compact = false,
}: MarketSelectorProps) {
  const copy = componentsCopy.market;
  return (
    <Select
      id={id}
      layout={compact ? 'inline' : 'stacked'}
      label={copy.label}
      value={value}
      onValueChange={onChange}
      options={markets.map((market) => ({
        value: market.address,
        label:
          market.flow === null
            ? market.label
            : `${market.label} (${market.flow === 'dual_flow' ? copy.dualFlow : copy.singleBook})`,
      }))}
    />
  );
}
