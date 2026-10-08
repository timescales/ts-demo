#!/usr/bin/env bash
# Stops the native end-to-end stack that scripts/e2e/up.sh started, by pid
# file, services first and the validator last.
#
#   scripts/e2e/down.sh [--keep-ledger]
#
#   --keep-ledger  keep the chain state, the keys, the service data and
#                  env.json, so `up.sh --resume` can restart on them.
#                  Without it, all of target/e2e except logs/ is removed.
set -euo pipefail

# shellcheck source=scripts/e2e/env.sh
source "$(dirname "${BASH_SOURCE[0]}")/env.sh"

keep_ledger=0
for arg in "$@"; do
  case "$arg" in
    --keep-ledger) keep_ledger=1 ;;
    -h | --help)
      sed -n '2,9p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
      exit 0
      ;;
    *) e2e_die "unknown argument $arg (see --help)" ;;
  esac
done

for name in node dealer krc-1 krc-2 krc-3 enclave-a enclave-b enclave-c web validator; do
  e2e_stop "$name"
done
# Anything else up.sh may have started.
if [[ -d "$TIMESCALES_E2E_PIDS" ]]; then
  for pidfile in "$TIMESCALES_E2E_PIDS"/*.pid; do
    [[ -e "$pidfile" ]] || continue
    e2e_stop "$(basename "$pidfile" .pid)"
  done
fi

if [[ "$keep_ledger" == 0 && -d "$TIMESCALES_E2E_DIR" ]]; then
  # Key files are 0400 and the data directories 0700. Both are ours.
  find "$TIMESCALES_E2E_DIR" -mindepth 1 -maxdepth 1 ! -name logs -exec chmod -R u+w {} +
  find "$TIMESCALES_E2E_DIR" -mindepth 1 -maxdepth 1 ! -name logs -exec rm -rf {} +
  e2e_log "removed the stack state under $TIMESCALES_E2E_DIR (logs kept)"
else
  e2e_log "kept the ledger and state under $TIMESCALES_E2E_DIR"
fi
