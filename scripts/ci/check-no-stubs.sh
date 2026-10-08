#!/usr/bin/env bash
# Fails if any of the given paths still contains a stub: Rust `unimplemented!`
# or `todo!`, or a TypeScript `NotImplementedError`. Tracked and untracked
# (but not ignored) files are searched.
#
#   scripts/ci/check-no-stubs.sh crates/timescales-service/src crates/timescales-service/tests
set -euo pipefail

if [[ $# -eq 0 ]]; then
  echo "usage: scripts/ci/check-no-stubs.sh <path>..." >&2
  exit 2
fi
cd "$(git rev-parse --show-toplevel)"

hits="$(git grep -n -I --untracked -E 'unimplemented!|todo!|NotImplementedError' -- "$@" || true)"
if [[ -n "$hits" ]]; then
  echo "stubs left in $*:" >&2
  echo "$hits" >&2
  exit 1
fi
echo "no stubs in $*"
