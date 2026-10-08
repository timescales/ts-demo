#!/usr/bin/env bash
# Native end-to-end stack: a local validator with the settlement
# program, a market with three simulated enclaves and receipt quorum 2, the
# key-release committee, the dealer, the node and the web app.
#
#   scripts/e2e/up.sh [--validator-only] [--e2e-wallet] [--resume] [--deploy]
#
#   --validator-only  build the program and start the validator, then stop
#                     (steps 1 and 3, the service binaries are not built).
#   --e2e-wallet      build the web app with VITE_E2E_WALLET=1 (the test
#                     wallet the browser tests drive).
#   --resume          restart on the ledger `down.sh --keep-ledger` kept:
#                     no --reset, and the keys, market and env.json of the
#                     previous run are reused.
#   --deploy          with TIMESCALES_CLUSTER=devnet: deploy the program
#                     when it is not on the cluster yet (pays about 1 SOL
#                     from $TIMESCALES_FUNDER_KEYPAIR).
#
# With TIMESCALES_CLUSTER=devnet no validator is started: the stack runs
# against $TIMESCALES_RPC_URL.
#
# Everything lives under target/e2e (ledger/, logs/, pids/, secrets/,
# config/, data/, env.json). scripts/e2e/down.sh stops it. Every key is
# labelled INSECURE-LOCAL and every enclave runs the simulated platform.
set -euo pipefail

# shellcheck source=scripts/e2e/env.sh
source "$(dirname "${BASH_SOURCE[0]}")/env.sh"
# shellcheck source=scripts/e2e/templates.sh
source "$(dirname "${BASH_SOURCE[0]}")/templates.sh"

validator_only=0
e2e_wallet=0
resume=0
deploy=0
remote=0
[[ "$TIMESCALES_CLUSTER" == localnet ]] || remote=1
for arg in "$@"; do
  case "$arg" in
    --validator-only) validator_only=1 ;;
    --e2e-wallet) e2e_wallet=1 ;;
    --resume) resume=1 ;;
    --deploy) deploy=1 ;;
    -h | --help)
      sed -n '2,27p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
      exit 0
      ;;
    *) e2e_die "unknown argument $arg (see --help)" ;;
  esac
done

trap 'rc=$?; ((rc == 0)) || e2e_log "up.sh failed; scripts/e2e/down.sh stops what it started"' EXIT

cd "$TIMESCALES_REPO"
if [[ "$remote" == 0 ]]; then
  e2e_need solana-test-validator "install the Agave release"
else
  [[ "$TIMESCALES_CLUSTER" == devnet ]] || e2e_die "TIMESCALES_CLUSTER must be localnet or devnet"
  [[ "$validator_only" == 0 ]] || e2e_die "--validator-only is for localnet"
  e2e_need solana "install the Agave release"
fi
e2e_need cargo-build-sbf "install the Agave release"
e2e_need curl "needed to probe the services"
if [[ "$validator_only" == 0 ]]; then
  e2e_need node "Node 24 builds and serves the web app"
  e2e_need npm "Node 24 builds and serves the web app"
fi

if [[ "$resume" == 0 && -d "$TIMESCALES_E2E_DIR" ]]; then
  for pid in "$TIMESCALES_E2E_PIDS"/*.pid; do
    [[ -e "$pid" ]] || continue
    e2e_die "a stack is still running ($pid); run scripts/e2e/down.sh first"
  done
  # A previous run's keys and market are replaced by fresh ones.
  rm -rf "$TIMESCALES_E2E_SECRETS" "$TIMESCALES_E2E_CONFIG" "$TIMESCALES_E2E_DATA" \
    "$TIMESCALES_E2E_ENV" "$TIMESCALES_E2E_DIR/committee.bin" "$TIMESCALES_E2E_DIR/market-params.json"
fi
mkdir -p "$TIMESCALES_E2E_DIR" "$TIMESCALES_E2E_LOGS" "$TIMESCALES_E2E_PIDS"

# 1. The program, with the `localnet` feature (MIN_TIMELOCK = 0).
e2e_log "building the settlement program"
scripts/build-program.sh >"$TIMESCALES_E2E_LOGS/build-program.log" 2>&1 ||
  e2e_die "program build failed; see $TIMESCALES_E2E_LOGS/build-program.log"
[[ -f "$TIMESCALES_PROGRAM_SO" ]] || e2e_die "no program at $TIMESCALES_PROGRAM_SO"

# 2. Service binaries: the node alone, then the simulated-platform builds of
# the committee, the enclave and the admin CLI (separate invocations).
if [[ "$validator_only" == 0 ]]; then
  e2e_log "building timescales-node, timescales-krc and timescales-enclave (sim-platform)"
  cargo build --locked -p timescales-node -p timescales-krc -p timescales-enclave \
    --features timescales-node/sim-platform,timescales-krc/sim-platform,timescales-enclave/sim-platform \
    >"$TIMESCALES_E2E_LOGS/build-sim.log" 2>&1 ||
    e2e_die "build failed; see $TIMESCALES_E2E_LOGS/build-sim.log"
fi

# 3. The validator, or on devnet the program already deployed there.
if [[ "$remote" == 1 ]]; then
  e2e_wait_rpc 30
  url=(--url "$TIMESCALES_RPC_URL")
  funder="$(solana address -k "$TIMESCALES_FUNDER_KEYPAIR")"
  e2e_log "funder $funder holds $(solana balance "$funder" "${url[@]}")"
  if ! solana program show "$TIMESCALES_PROGRAM_ID" "${url[@]}" >/dev/null 2>&1; then
    [[ "$deploy" == 1 ]] ||
      e2e_die "program $TIMESCALES_PROGRAM_ID is not on $TIMESCALES_CLUSTER; rerun with --deploy"
    e2e_log "deploying $TIMESCALES_PROGRAM_ID to $TIMESCALES_CLUSTER"
    solana program deploy "$TIMESCALES_PROGRAM_SO" --program-id "$TIMESCALES_PROGRAM_KEYPAIR" \
      --keypair "$TIMESCALES_FUNDER_KEYPAIR" "${url[@]}" >"$TIMESCALES_E2E_LOGS/deploy.log" 2>&1 ||
      e2e_die "deploy failed; see $TIMESCALES_E2E_LOGS/deploy.log"
  fi
  solana program show "$TIMESCALES_PROGRAM_ID" "${url[@]}" --output json \
    >"$TIMESCALES_E2E_DIR/program.json"
  upgrade_authority="$(json_get "$TIMESCALES_E2E_DIR/program.json" authority)"
  e2e_log "program $TIMESCALES_PROGRAM_ID on $TIMESCALES_CLUSTER (upgrade authority $upgrade_authority)"
else
  reset=(--reset)
  if [[ "$resume" == 1 ]]; then
    [[ -d "$TIMESCALES_E2E_LEDGER" ]] || e2e_die "--resume needs the ledger of a previous run"
    reset=()
  fi
  e2e_start validator solana-test-validator ${reset[@]+"${reset[@]}"} --quiet \
    --ledger "$TIMESCALES_E2E_LEDGER" \
    --rpc-port "$TIMESCALES_RPC_PORT" \
    --bpf-program "$TIMESCALES_PROGRAM_ID" "$TIMESCALES_PROGRAM_SO"
  e2e_wait_rpc 60
  # The faucet key funds bootstrap-local. Key loaders refuse files that group
  # or others can read.
  chmod 600 "$TIMESCALES_FUNDER_KEYPAIR"
  e2e_log "validator ready at $TIMESCALES_RPC_URL (program $TIMESCALES_PROGRAM_ID)"
  # A program loaded with --bpf-program has the default address as its
  # upgrade authority.
  upgrade_authority=11111111111111111111111111111111
fi

if [[ "$validator_only" == 1 ]]; then
  exit 0
fi

admin() {
  "$TIMESCALES_BIN_DIR/timescales-admin" "$@"
}

if [[ "$resume" == 0 || ! -f "$TIMESCALES_E2E_ENV" ]]; then
  # 4. Keys.
  admin keygen --profile local --out "$TIMESCALES_E2E_SECRETS" >"$TIMESCALES_E2E_DIR/keys.out.json"

  # 5. Market id from the admin (creator) and a random salt. The committee
  # of the three members, threshold 2.
  salt="$(od -An -N32 -tx1 /dev/urandom | tr -d ' \n')"
  admin_key="$(json_get "$TIMESCALES_E2E_SECRETS/keys.json" admin)"
  admin market id --creator "$admin_key" --salt "$salt" --program "$TIMESCALES_PROGRAM_ID" \
    >"$TIMESCALES_E2E_DIR/market.json"
  market="$(json_get "$TIMESCALES_E2E_DIR/market.json" address)"
  admin committee build --market "$market" --threshold 2 \
    --members "$TIMESCALES_E2E_SECRETS/members.toml" \
    --out "$TIMESCALES_E2E_DIR/committee.bin" >/dev/null

  # 6. Mints, vaults, InitMarket, airdrops. Writes env.json.
  admin bootstrap-local --secrets "$TIMESCALES_E2E_SECRETS" --salt "$salt" \
    --committee "$TIMESCALES_E2E_DIR/committee.bin" \
    --market-config "$TIMESCALES_MARKET_CONFIG" \
    --funder "$TIMESCALES_FUNDER_KEYPAIR" \
    --sol-each "${TIMESCALES_SOL_EACH:-10}" --admin-sol "${TIMESCALES_ADMIN_SOL:-100}" \
    --service-sol "${TIMESCALES_SERVICE_SOL:-10}" \
    --timelock-slots "${TIMESCALES_TIMELOCK_SLOTS:-20}" \
    --receipt-quorum "${TIMESCALES_RECEIPT_QUORUM:-2}" \
    --out "$TIMESCALES_E2E_ENV" \
    --rpc "$TIMESCALES_RPC_URL" --program "$TIMESCALES_PROGRAM_ID" >/dev/null
fi
market="$(json_get "$TIMESCALES_E2E_ENV" market.address)"
genesis="$(json_get "$TIMESCALES_E2E_ENV" genesis_hash)"
e2e_log "market $market ready"

# 7. The web app, served by vite preview under the production headers.
e2e_log "building the web app"
npm ci --prefix ts >"$TIMESCALES_E2E_LOGS/npm-ci.log" 2>&1 ||
  e2e_die "npm ci failed; see $TIMESCALES_E2E_LOGS/npm-ci.log"
# The build pins this deployment: without its program, genesis and market
# the app only browses epochs and never seals orders.
rpc_allowlist=""
[[ "$remote" == 0 ]] || rpc_allowlist="$TIMESCALES_CLUSTER|$TIMESCALES_RPC_URL"
VITE_E2E_WALLET="$e2e_wallet" \
  VITE_CLUSTER="$TIMESCALES_CLUSTER" \
  VITE_RPC_ALLOWLIST="$rpc_allowlist" \
  VITE_PROGRAM_ID="$TIMESCALES_PROGRAM_ID" \
  VITE_GENESIS_HASH="$genesis" \
  VITE_MARKETS="$market" \
  VITE_UPGRADE_AUTHORITY="$upgrade_authority" \
  npm run --prefix ts -w @timescales/web build \
  >"$TIMESCALES_E2E_LOGS/web-build.log" 2>&1 ||
  e2e_die "web build failed; see $TIMESCALES_E2E_LOGS/web-build.log"
# vite itself (not an npm wrapper) holds the pid file, so down.sh stops it.
# A remote RPC must also be in the preview's connect-src.
if [[ "$remote" == 1 ]]; then
  rpc_origin="$(node -e 'process.stdout.write(new URL(process.argv[1]).origin)' "$TIMESCALES_RPC_URL")"
  export TIMESCALES_PREVIEW_CONNECT_SRC="$rpc_origin ${rpc_origin/#http/ws}"
fi
e2e_start web bash -c 'cd "$1" && exec ../../node_modules/.bin/vite preview --port "$2" --strictPort' \
  web "$TIMESCALES_REPO/ts/apps/web" "$TIMESCALES_WEB_PORT"
e2e_wait_http "$TIMESCALES_WEB_ORIGIN/" 60 web

# 8. Configurations for that origin (scripts/e2e/templates.sh), then
# enclaves, members, node and dealer.
mkdir -p "$TIMESCALES_E2E_CONFIG" "$TIMESCALES_E2E_DATA"
chmod 700 "$TIMESCALES_E2E_DATA"
K="$TIMESCALES_E2E_SECRETS/keys.json"
export E2E_MARKET="$market" E2E_GENESIS="$genesis"
E2E_COMMITTEE_FILE="$(json_get "$TIMESCALES_E2E_ENV" market.committee_file)"
E2E_PARAMS_FILE="$(json_get "$TIMESCALES_E2E_ENV" market.params_file)"
E2E_DEALER_PUB="$(json_get "$K" dealer)"
E2E_NODE_PUB="$(json_get "$K" node_service)"
E2E_VENDOR_ROOT="$(json_get "$K" sim_vendor_root)"
export E2E_COMMITTEE_FILE E2E_PARAMS_FILE E2E_DEALER_PUB E2E_NODE_PUB E2E_VENDOR_ROOT
executors=()
for i in 0 1 2; do
  executors+=("$(json_get "$TIMESCALES_E2E_ENV" "enclaves.$i.executor_hex")")
done

for i in 0 1 2; do
  x="${TIMESCALES_ENCLAVES[$i]}"
  mkdir -p "$TIMESCALES_E2E_DATA/enclave-$x"
  e2e_enclave_config "$i" >"$TIMESCALES_E2E_CONFIG/enclave-$x.toml"
done
for i in 1 2 3; do
  mkdir -p "$TIMESCALES_E2E_DATA/krc-$i" "$TIMESCALES_E2E_DATA/krc-$i-shares"
done
mkdir -p "$TIMESCALES_E2E_DATA/node" "$TIMESCALES_E2E_DATA/dealer"
chmod 700 "$TIMESCALES_E2E_DATA/node"
e2e_node_config "${executors[@]}" >"$TIMESCALES_E2E_CONFIG/node.toml"
e2e_dealer_config >"$TIMESCALES_E2E_CONFIG/dealer.toml"

# Enclaves first: their registration evidence gives the measurement the
# members' policy pins, and `executor verify` checks it with that policy.
for i in 0 1 2; do
  x="${TIMESCALES_ENCLAVES[$i]}"
  e2e_start "enclave-$x" "$TIMESCALES_BIN_DIR/timescales-enclave" run \
    --config "$TIMESCALES_E2E_CONFIG/enclave-$x.toml"
done
nonce="$(od -An -N32 -tx1 /dev/urandom | tr -d ' \n')"
measurements=""
for i in 0 1 2; do
  x="${TIMESCALES_ENCLAVES[$i]}"
  e2e_wait_http "http://127.0.0.1:${TIMESCALES_ENCLAVE_OPS_PORTS[$i]}/readyz" 60 "enclave-$x"
  curl -fsS "http://127.0.0.1:${TIMESCALES_ENCLAVE_PORTS[$i]}/enclave/v1/identity?market=$market&nonce=$nonce" \
    >"$TIMESCALES_E2E_DIR/identity-$x.json"
  m="$(json_get "$TIMESCALES_E2E_DIR/identity-$x.json" measurement)"
  [[ "$measurements" == *"\"$m\""* ]] || measurements+="${measurements:+, }\"$m\""
done
for i in 1 2 3; do
  e2e_member_config "$i" "$measurements" >"$TIMESCALES_E2E_CONFIG/krc-$i.toml"
done
for i in 0 1 2; do
  x="${TIMESCALES_ENCLAVES[$i]}"
  admin executor verify --identity "$TIMESCALES_E2E_DIR/identity-$x.json" --nonce "$nonce" \
    --market "$market" --member-config "$TIMESCALES_E2E_CONFIG/krc-1.toml" \
    --program "$TIMESCALES_PROGRAM_ID" >"$TIMESCALES_E2E_DIR/verify-$x.json" ||
    e2e_die "enclave $x registration evidence did not verify"
done

for i in 1 2 3; do
  e2e_start "krc-$i" "$TIMESCALES_BIN_DIR/timescales-krc" member run \
    --config "$TIMESCALES_E2E_CONFIG/krc-$i.toml"
done
for i in 1 2 3; do
  e2e_wait_http "http://127.0.0.1:${TIMESCALES_MEMBER_OPS_PORTS[$((i - 1))]}/readyz" 60 "krc-$i"
done

e2e_start node "$TIMESCALES_BIN_DIR/timescales-node" run --config "$TIMESCALES_E2E_CONFIG/node.toml"
e2e_wait_http "http://127.0.0.1:$TIMESCALES_NODE_OPS_PORT/readyz" 120 node
e2e_start dealer "$TIMESCALES_BIN_DIR/timescales-krc" dealer --config "$TIMESCALES_E2E_CONFIG/dealer.toml"
e2e_wait_http "http://127.0.0.1:$TIMESCALES_DEALER_OPS_PORT/readyz" 60 dealer

# The node is ready for traders once four epochs ahead have keys.
e2e_log "waiting for keys_ready_ahead >= 4"
for ((n = 0; n < 480; n++)); do
  ahead="$(curl -fsS --max-time 2 "$TIMESCALES_NODE_URL/v1/status" 2>/dev/null |
    node -e 'let s = ""; process.stdin.on("data", (d) => (s += d)).on("end", () => {
      try { const m = (JSON.parse(s).markets ?? []).find((x) => x.market === process.argv[1]);
        process.stdout.write(String(m?.keys_ready_ahead ?? 0)); }
      catch { process.stdout.write("0"); } });' "$market" || echo 0)"
  if ((ahead >= 4)); then
    e2e_log "stack ready: web $TIMESCALES_WEB_ORIGIN, node $TIMESCALES_NODE_URL, env $TIMESCALES_E2E_ENV"
    exit 0
  fi
  e2e_running node || e2e_die "the node exited; see $TIMESCALES_E2E_LOGS/node.log"
  sleep 0.5
done
e2e_die "keys_ready_ahead stayed below 4 for 4 minutes; see $TIMESCALES_E2E_LOGS/"
