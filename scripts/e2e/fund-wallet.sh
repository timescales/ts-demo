#!/usr/bin/env bash
# Funds a browser wallet on the local stack: SOL for rent and fees, and the
# market's test base and quote tokens (minted by the INSECURE-LOCAL admin).
#
#   scripts/e2e/fund-wallet.sh <wallet-address> [sol] [base] [quote]
#
# Defaults: 5 SOL, 1000 base and 100000 quote tokens. On localnet the SOL is
# airdropped. On devnet it comes from the funder.
set -euo pipefail

# shellcheck source=scripts/e2e/env.sh
source "$(dirname "${BASH_SOURCE[0]}")/env.sh"

wallet="${1:-}"
[[ -n "$wallet" ]] || e2e_die "usage: scripts/e2e/fund-wallet.sh <wallet-address> [sol] [base] [quote]"
sol="${2:-5}"
base="${3:-1000}"
quote="${4:-100000}"

e2e_need solana "install the Agave release"
e2e_need spl-token "install the Agave release"
[[ -f "$TIMESCALES_E2E_ENV" ]] || e2e_die "no local stack ($TIMESCALES_E2E_ENV); run scripts/e2e/up.sh first"

admin="$(json_get "$TIMESCALES_E2E_ENV" keys.admin)"
base_mint="$(json_get "$TIMESCALES_E2E_ENV" mints.base.address)"
quote_mint="$(json_get "$TIMESCALES_E2E_ENV" mints.quote.address)"
url=(--url "$TIMESCALES_RPC_URL")

if [[ "$TIMESCALES_CLUSTER" == localnet ]]; then
  solana airdrop "$sol" "$wallet" "${url[@]}" >/dev/null
  e2e_log "airdropped $sol SOL to $wallet"
else
  solana transfer "$wallet" "$sol" --from "$TIMESCALES_FUNDER_KEYPAIR" \
    --fee-payer "$TIMESCALES_FUNDER_KEYPAIR" --allow-unfunded-recipient "${url[@]}" >/dev/null
  e2e_log "sent $sol SOL to $wallet from the funder"
fi

for pair in "base:$base_mint:$base" "quote:$quote_mint:$quote"; do
  IFS=: read -r name mint amount <<<"$pair"
  # The associated account may already exist from an earlier run.
  spl-token create-account "$mint" --owner "$wallet" --fee-payer "$admin" "${url[@]}" \
    >/dev/null 2>&1 || true
  spl-token mint "$mint" "$amount" --recipient-owner "$wallet" \
    --mint-authority "$admin" --fee-payer "$admin" "${url[@]}" >/dev/null
  e2e_log "minted $amount $name tokens ($mint) to $wallet"
done
