#!/usr/bin/env bash
# Simulation never reaches a production binary.
#
# 1. The dependency tree of each service package, without dev edges, must
#    not enable a simulation-only feature.
# 2. The service binaries, built the way release images build them, must
#    not contain the `timescales:SIMULATION_BUILD=1` marker. A linker may
#    drop an unreferenced `#[used]` static, so the simulation CLI built with
#    the same profile must contain the marker first.
#
# TIMESCALES_GUARD_PROFILE selects the cargo profile of step 2 (default
# release).
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"

packages=(timescales-node timescales-krc timescales-enclave)
binaries=(timescales-node timescales-admin timescales-krc timescales-enclave)
control_pkg=timescales-cli
control_bin=timescales
profile="${TIMESCALES_GUARD_PROFILE:-release}"
marker='timescales:SIMULATION_BUILD=1'
forbidden='feature "(simulation|mpc-simulation|fault-injection|sim-platform)"'

# Counts every match rather than using grep -q: -q stops reading at the
# first match, `strings` then dies of SIGPIPE, and under pipefail a binary
# that contains the marker would be reported as clean.
has_marker() {
  local n
  n="$(strings "$1" | grep -cF "$marker" || true)"
  [[ "$n" -gt 0 ]]
}

fail=0
for pkg in "${packages[@]}"; do
  tree="$(cargo tree -e features,no-dev --locked -p "$pkg")"
  hits="$(grep -E "$forbidden" <<<"$tree" | sort -u || true)"
  if [[ -n "$hits" ]]; then
    echo "$pkg: simulation-only features in the dependency tree:" >&2
    echo "$hits" >&2
    fail=1
  else
    echo "$pkg: dependency tree clean"
  fi
done

pkg_args=()
for pkg in "${packages[@]}"; do
  pkg_args+=(-p "$pkg")
done
cargo build --locked --profile "$profile" "${pkg_args[@]}"
cargo build --locked --profile "$profile" -p "$control_pkg"

target_dir="$(cargo metadata --format-version 1 --no-deps --locked |
  sed -n 's/.*"target_directory":"\([^"]*\)".*/\1/p')"
profile_dir="$profile"
[[ "$profile" == dev ]] && profile_dir=debug

if ! has_marker "$target_dir/$profile_dir/$control_bin"; then
  echo "$control_bin: simulation build lacks the $marker marker; the marker check below would prove nothing" >&2
  exit 1
fi
echo "$control_bin: simulation build carries the marker"

for bin in "${binaries[@]}"; do
  path="$target_dir/$profile_dir/$bin"
  if [[ ! -f "$path" ]]; then
    echo "$bin: binary not found at $path" >&2
    fail=1
  elif has_marker "$path"; then
    echo "$bin: contains the $marker marker" >&2
    fail=1
  else
    echo "$bin: no simulation marker"
  fi
done

exit "$fail"
