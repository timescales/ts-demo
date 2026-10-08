#!/usr/bin/env bash
# Builds the settlement program.
#
#   scripts/build-program.sh               -> target/sbf/timescales_settlement_program.so
#                                             (feature `localnet`: MIN_TIMELOCK = 0)
#   scripts/build-program.sh --production  -> target/sbf-production/timescales_settlement_program.so
#
# The output directory is absolute, so CARGO_TARGET_DIR never moves the.so.
# Tests find it through TIMESCALES_PROGRAM_SO, resolved against the
# repository root.
set -euo pipefail

repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
manifest="$repo/programs/timescales-settlement/Cargo.toml"

case "${1:-}" in
  "")
    out="$repo/target/sbf"
    features=(--features localnet)
    ;;
  --production)
    out="$repo/target/sbf-production"
    features=()
    ;;
  *)
    echo "usage: scripts/build-program.sh [--production]" >&2
    exit 2
    ;;
esac

mkdir -p "$out"
cargo build-sbf --manifest-path "$manifest" --sbf-out-dir "$out" ${features[@]+"${features[@]}"} -- --locked
echo "built $out/timescales_settlement_program.so"
