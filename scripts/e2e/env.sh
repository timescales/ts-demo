# Shared settings of the native end-to-end stack.
#
#   source scripts/e2e/env.sh
#
# Sourced by up.sh and down.sh. Source it in a shell to get the same paths,
# ports and URLs the stack uses (the e2e tests read the TIMESCALES_* names
# below). Every value can be overridden from the environment.

TIMESCALES_REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
export TIMESCALES_REPO

export TIMESCALES_E2E_DIR="${TIMESCALES_E2E_DIR:-$TIMESCALES_REPO/target/e2e}"
export TIMESCALES_E2E_LEDGER="$TIMESCALES_E2E_DIR/ledger"
export TIMESCALES_E2E_LOGS="$TIMESCALES_E2E_DIR/logs"
export TIMESCALES_E2E_PIDS="$TIMESCALES_E2E_DIR/pids"
export TIMESCALES_E2E_SECRETS="$TIMESCALES_E2E_DIR/secrets"
export TIMESCALES_E2E_CONFIG="$TIMESCALES_E2E_DIR/config"
export TIMESCALES_E2E_DATA="$TIMESCALES_E2E_DIR/data"
# Written by `timescales-admin bootstrap-local`. Read by the e2e tests and
# `timescales-loadgen --env`.
export TIMESCALES_E2E_ENV="${TIMESCALES_E2E_ENV:-$TIMESCALES_E2E_DIR/env.json}"

export TIMESCALES_PROGRAM_ID="${TIMESCALES_PROGRAM_ID:-FDQqHeaCY2iG9kbjkGGJngY2rgend8dW4JjfXmCQytQL}"
export TIMESCALES_PROGRAM_SO="${TIMESCALES_PROGRAM_SO:-$TIMESCALES_REPO/target/sbf/timescales_settlement_program.so}"
export TIMESCALES_MARKET_CONFIG="${TIMESCALES_MARKET_CONFIG:-$TIMESCALES_REPO/config/markets/local-dual.json}"

# localnet runs solana-test-validator here. Devnet uses $TIMESCALES_RPC_URL
# and the program already deployed there.
export TIMESCALES_CLUSTER="${TIMESCALES_CLUSTER:-localnet}"
export TIMESCALES_PROGRAM_KEYPAIR="${TIMESCALES_PROGRAM_KEYPAIR:-$TIMESCALES_REPO/programs/timescales-settlement/target/deploy/timescales_settlement_program-keypair.json}"

export TIMESCALES_RPC_PORT="${TIMESCALES_RPC_PORT:-8899}"
export TIMESCALES_RPC_URL="${TIMESCALES_RPC_URL:-http://127.0.0.1:$TIMESCALES_RPC_PORT}"
# The validator's faucet holds the SOL that bootstrap-local hands out.
export TIMESCALES_FUNDER_KEYPAIR="${TIMESCALES_FUNDER_KEYPAIR:-$TIMESCALES_E2E_LEDGER/faucet-keypair.json}"

# The web app is served by `vite preview` on this origin. The node's SIWS
# URI, session domains and CORS, and the enclaves' session domains, are
# templated from it.
export TIMESCALES_WEB_PORT="${TIMESCALES_WEB_PORT:-4173}"
export TIMESCALES_WEB_ORIGIN="${TIMESCALES_WEB_ORIGIN:-http://localhost:$TIMESCALES_WEB_PORT}"
export TIMESCALES_WEB_DOMAIN="${TIMESCALES_WEB_ORIGIN#*://}"

export TIMESCALES_NODE_URL="${TIMESCALES_NODE_URL:-http://127.0.0.1:8080}"
export TIMESCALES_NODE_ADMIN_URL="${TIMESCALES_NODE_ADMIN_URL:-http://127.0.0.1:8081}"
export TIMESCALES_NODE_OPS_PORT="${TIMESCALES_NODE_OPS_PORT:-9100}"
# Members 1..3, enclaves a..c: listener and ops ports in index order.
TIMESCALES_MEMBER_PORTS=(8095 8096 8097)
TIMESCALES_MEMBER_OPS_PORTS=(9101 9102 9103)
TIMESCALES_DEALER_OPS_PORT=9104
TIMESCALES_ENCLAVES=(a b c)
TIMESCALES_ENCLAVE_PORTS=(8090 8091 8092)
TIMESCALES_ENCLAVE_OPS_PORTS=(9105 9106 9107)

# Binaries: the stack runs what `cargo build` put under CARGO_TARGET_DIR.
export TIMESCALES_BIN_DIR="${TIMESCALES_BIN_DIR:-${CARGO_TARGET_DIR:-$TIMESCALES_REPO/target}/debug}"

e2e_log() {
  printf '[e2e] %s\n' "$*" >&2
}

e2e_die() {
  e2e_log "error: $*"
  exit 1
}

e2e_need() {
  command -v "$1" >/dev/null 2>&1 || e2e_die "$1 is not on PATH ($2)"
}

# e2e_start NAME COMMAND...: runs COMMAND in the background with its output
# in $TIMESCALES_E2E_LOGS/NAME.log and its pid in $TIMESCALES_E2E_PIDS/NAME.pid.
e2e_start() {
  local name="$1"
  shift
  mkdir -p "$TIMESCALES_E2E_LOGS" "$TIMESCALES_E2E_PIDS"
  if e2e_running "$name"; then
    e2e_die "$name is already running (pid $(cat "$TIMESCALES_E2E_PIDS/$name.pid"))"
  fi
  nohup "$@" >"$TIMESCALES_E2E_LOGS/$name.log" 2>&1 &
  echo $! >"$TIMESCALES_E2E_PIDS/$name.pid"
  e2e_log "started $name (pid $!, log $TIMESCALES_E2E_LOGS/$name.log)"
}

e2e_running() {
  local pidfile="$TIMESCALES_E2E_PIDS/$1.pid"
  [[ -f "$pidfile" ]] && kill -0 "$(cat "$pidfile")" 2>/dev/null
}

# e2e_stop NAME: SIGTERM, then SIGKILL after 10 s. Removes the pid file.
e2e_stop() {
  local name="$1" pidfile="$TIMESCALES_E2E_PIDS/$1.pid" pid i
  [[ -f "$pidfile" ]] || return 0
  pid="$(cat "$pidfile")"
  if kill -0 "$pid" 2>/dev/null; then
    kill "$pid" 2>/dev/null || true
    for ((i = 0; i < 100; i++)); do
      kill -0 "$pid" 2>/dev/null || break
      sleep 0.1
    done
    if kill -0 "$pid" 2>/dev/null; then
      e2e_log "$name did not stop; killing pid $pid"
      kill -9 "$pid" 2>/dev/null || true
    fi
    e2e_log "stopped $name (pid $pid)"
  fi
  rm -f "$pidfile"
}

# e2e_wait_http URL SECONDS [NAME]: waits for a 2xx answer. Fails early if
# the process NAME has exited.
e2e_wait_http() {
  local url="$1" seconds="$2" name="${3:-}" i
  for ((i = 0; i < seconds * 4; i++)); do
    if curl -fsS -o /dev/null --max-time 2 "$url" 2>/dev/null; then
      return 0
    fi
    if [[ -n "$name" ]] && ! e2e_running "$name"; then
      e2e_die "$name exited; see $TIMESCALES_E2E_LOGS/$name.log"
    fi
    sleep 0.25
  done
  e2e_die "no answer from $url after ${seconds}s"
}

# e2e_wait_rpc SECONDS: waits until the validator answers getHealth.
e2e_wait_rpc() {
  local seconds="$1" i body
  body='{"jsonrpc":"2.0","id":1,"method":"getHealth"}'
  for ((i = 0; i < seconds * 4; i++)); do
    if curl -fsS --max-time 2 -H 'Content-Type: application/json' -d "$body" \
      "$TIMESCALES_RPC_URL" 2>/dev/null | grep -q '"result":"ok"'; then
      return 0
    fi
    if [[ -f "$TIMESCALES_E2E_PIDS/validator.pid" ]] && ! e2e_running validator; then
      e2e_die "the validator exited; see $TIMESCALES_E2E_LOGS/validator.log"
    fi
    sleep 0.25
  done
  e2e_die "$TIMESCALES_RPC_URL did not report healthy after ${seconds}s"
}

# json_get <file> <dotted.path>: one value of a JSON file (strings unquoted).
json_get() {
  node -e 'const v = JSON.parse(require("fs").readFileSync(process.argv[1], "utf8"));
    let x = v; for (const k of process.argv[2].split(".")) x = x[k];
    process.stdout.write(typeof x === "string" ? x : JSON.stringify(x));' "$1" "$2"
}
