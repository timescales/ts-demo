# Configuration templates of the native stack, sourced
# by up.sh after env.sh. Each function prints one TOML file. They read:
#
#   E2E_MARKET, E2E_GENESIS          market address and genesis hash (base58)
#   E2E_COMMITTEE_FILE, E2E_PARAMS_FILE
#   E2E_DEALER_PUB, E2E_NODE_PUB     dealer and node service keys (hex)
#   E2E_VENDOR_ROOT                  simulated vendor root (hex)
#
# and the paths, ports and web origin of env.sh. Every service is profile
# "local" and the enclaves run the simulated platform (INSECURE-LOCAL).

e2e_member_urls() {
  local i out=""
  for i in 0 1 2; do
    out+="${out:+, }\"http://127.0.0.1:${TIMESCALES_MEMBER_PORTS[$i]}\""
  done
  printf '%s' "$out"
}

e2e_chain_table() {
  cat <<EOF
cluster = "${TIMESCALES_CLUSTER:-localnet}"
genesis_hash = "$E2E_GENESIS"
program_id = "$TIMESCALES_PROGRAM_ID"
rpc_urls = ["$TIMESCALES_RPC_URL"]
EOF
}

e2e_telemetry_table() {
  cat <<EOF
log_format = "pretty"
log_filter = "info"
otlp_endpoint = ""
EOF
}

# e2e_enclave_config INDEX (0..2)
e2e_enclave_config() {
  local i="$1" x="${TIMESCALES_ENCLAVES[$1]}" S="$TIMESCALES_E2E_SECRETS"
  cat <<EOF
# INSECURE-LOCAL: simulated platform. The host can read every order.
[enclave]
profile = "local"
listen = "127.0.0.1:${TIMESCALES_ENCLAVE_PORTS[$i]}"
ops_listen = "127.0.0.1:${TIMESCALES_ENCLAVE_OPS_PORTS[$i]}"
platform = "simulated"
simulated_key_file = "$S/enclave-$x.keys"
simulated_vendor_seed = "$S/sim-vendor.hex"
fee_payer_keypair = "$S/enclave-$x-fee-payer.json"
node_keys = ["$E2E_NODE_PUB"]
member_urls = [$(e2e_member_urls)]
member_timeout_ms = 5000
post_deadline_ms = 60000
settle_backstop_after_ms = 20000
reveal_backstop_slots = 8
allow_sign_message_grants = true
max_concurrent_executions = 2
max_body_bytes = 16777216
result_cache_entries = 32

[[enclave.market]]
address = "$E2E_MARKET"
committee_file = "$E2E_COMMITTEE_FILE"
session_domains = ["$TIMESCALES_WEB_DOMAIN"]

[enclave.chain]
$(e2e_chain_table)
rpc_agree = 1
rpc_timeout_ms = 5000
poll_interval_ms = ${TIMESCALES_POLL_MS:-400}

[enclave.chain.priority_fee]
mode = "fixed"
fixed_micro_lamports = "0"
percentile = 75
max_micro_lamports = "200000"

[enclave.telemetry]
$(e2e_telemetry_table)
EOF
}

# e2e_member_config INDEX (1..3) MEASUREMENTS (quoted hex, comma-separated)
e2e_member_config() {
  local i="$1" measurements="$2" S="$TIMESCALES_E2E_SECRETS"
  cat <<EOF
# INSECURE-LOCAL key-release committee member $i.
[member]
profile = "local"
index = $i
listen = "127.0.0.1:${TIMESCALES_MEMBER_PORTS[$((i - 1))]}"
ops_listen = "127.0.0.1:${TIMESCALES_MEMBER_OPS_PORTS[$((i - 1))]}"
data_dir = "$TIMESCALES_E2E_DATA/krc-$i"
identity_key = "$S/member-$i-identity.hex"
transport_key = "$S/member-$i-transport.hex"
kek_file = "$S/member-$i-kek.keys"
kek_ratchet_epochs = 64
shares_dir = "$TIMESCALES_E2E_DATA/krc-$i-shares"
dealer_keys = ["$E2E_DEALER_PUB"]
skew_ms = 30000
nonce_ttl_ms = 60000
max_nonces_per_epoch_executor = 16
max_outstanding_nonces = 4096
max_releases_per_epoch = 8
per_caller_rps = 10
per_caller_burst = 20
prune_interval_ms = 10000
audit_retention_days = 90

[[member.market]]
address = "$E2E_MARKET"
committee_file = "$E2E_COMMITTEE_FILE"

[member.chain]
$(e2e_chain_table)
rpc_agree = 1
release_commitment = "confirmed"
confirmed_cache_ms = 2000
rpc_timeout_ms = 5000

[member.policy]
platforms = ["simulated"]
measurements = [$measurements]
allow_debug = false
min_tcb = "up_to_date"
simulated_vendor_root = "$E2E_VENDOR_ROOT"

[member.telemetry]
$(e2e_telemetry_table)
EOF
}

# e2e_node_config EXECUTOR_HEX_A EXECUTOR_HEX_B EXECUTOR_HEX_C
e2e_node_config() {
  local i S="$TIMESCALES_E2E_SECRETS" executors=("$@")
  cat <<EOF
# INSECURE-LOCAL node of the native stack, serving $TIMESCALES_WEB_ORIGIN.
[node]
id = "node-local"
profile = "local"
data_dir = "$TIMESCALES_E2E_DATA/node"
shutdown_grace_ms = 30000
accept_chain_ahead = false

[api]
listen = "${TIMESCALES_NODE_URL#http://}"
public_base_url = "$TIMESCALES_WEB_ORIGIN"
session_domains = ["$TIMESCALES_WEB_DOMAIN"]
cors_allowed_origins = ["$TIMESCALES_WEB_ORIGIN"]
trusted_proxy_cidrs = ["127.0.0.1/32"]
max_body_bytes = 4096
submit_max_body_bytes = 2048
max_concurrency = 512
request_timeout_ms = 10000
ws_max_connections = 5000
ws_max_connections_per_ip = 20
ws_max_subscriptions = 16
ws_send_queue = 256
ws_heartbeat_ms = 15000
ws_inbound_max_bytes = 4096
event_log_hours = 24

[api.rate_limit]
per_ip_rps = 20
per_ip_burst = 40
per_session_rps = 5
per_session_burst = 20
per_wallet_submit_rps = 5
per_wallet_submit_burst = 20

[sessions]
max_ttl_s = 86400
nonce_ttl_s = 300
max_per_wallet = 4
skew_ms = 30000
allow_sign_message_grants = true

[admin]
listen = "${TIMESCALES_NODE_ADMIN_URL#http://}"
token_file = "$S/admin-token"
dealer_keys = ["$E2E_DEALER_PUB"]

[metrics]
listen = "127.0.0.1:$TIMESCALES_NODE_OPS_PORT"

[telemetry]
$(e2e_telemetry_table)
service_name = "timescales-node"

[solana]
$(e2e_chain_table)
rpc_timeout_ms = 5000
read_commitment = "confirmed"
release_commitment = "confirmed"
poll_interval_ms = ${TIMESCALES_POLL_MS:-400}
confirm_timeout_ms = 60000
tx_max_attempts = 8
max_parallel_txs = 16
cu_margin_pct = 20
min_relay_balance_lamports = "100000000"
min_cranker_balance_lamports = "200000000"
reclaim_batches = true

[solana.priority_fee]
mode = "fixed"
fixed_micro_lamports = "0"
percentile = 75
max_micro_lamports = "200000"

[keys]
relay_keypair = "$S/relay.json"
cranker_keypair = "$S/cranker.json"
service_key = "$S/node-service.hex"
kek_file = "$S/node-kek.hex"
nonce_key_file = "$S/node-nonce.hex"

[store]
synchronous = "full"
group_commit_ms = 2
group_commit_max = 256
readers = 4
queue = 8192
busy_timeout_ms = 5000
private_keep_epochs = 64
wallet_link_hours = 24
backup_every_epochs = 0
backup_dir = "$TIMESCALES_E2E_DATA/node/backups"

[execution]
spare_executions = 1
attempts_per_enclave = 2
attempt_timeout_ms = 60000
retry_backoff_ms = 500
circuit_open_after = 3
circuit_half_open_after_ms = 30000
expected_platform = "simulated"
EOF
  for i in 0 1 2; do
    cat <<EOF

[[execution.enclave]]
url = "http://127.0.0.1:${TIMESCALES_ENCLAVE_PORTS[$i]}"
identity = "${executors[$i]}"
executor = "${executors[$i]}"
EOF
  done
  cat <<EOF

[[market]]
address = "$E2E_MARKET"
name = "LOCAL-BASE/LOCAL-QUOTE"
base_symbol = "LBASE"
quote_symbol = "LQUOTE"
params_file = "$E2E_PARAMS_FILE"
committee_file = "$E2E_COMMITTEE_FILE"
epoch_interval_ms = 20000
padding = { kind = "power_of_two", min = 64 }
cover_carry_probability = 0.5
max_real_per_epoch = 1024
max_park_ahead_epochs = 6
idle_policy = "commit"
max_idle_extend = 6

[market.quota]
max_envelopes_per_wallet_per_epoch = 16
max_parked_per_wallet = 64
require_trader_account = true
min_available_value_quote = "1000000"
min_value_per_envelope_quote = "1000000"
ban_epochs = 64

[market.reference]
source = "last_clearing"
initial_tick = "10000"
EOF
}

e2e_dealer_config() {
  local S="$TIMESCALES_E2E_SECRETS"
  cat <<EOF
# INSECURE-LOCAL trusted dealer: it sees every epoch key it deals.
[dealer]
profile = "local"
data_dir = "$TIMESCALES_E2E_DATA/dealer"
identity_key = "$S/dealer.hex"
lookahead_epochs = 16
interval_ms = 2000
ack_timeout_ms = 5000
node_url = "$TIMESCALES_NODE_ADMIN_URL"
node_identity = "$E2E_NODE_PUB"
ops_listen = "127.0.0.1:$TIMESCALES_DEALER_OPS_PORT"
member_urls = [$(e2e_member_urls)]

[[dealer.market]]
address = "$E2E_MARKET"
committee_file = "$E2E_COMMITTEE_FILE"

[dealer.chain]
$(e2e_chain_table)
rpc_timeout_ms = 5000

[dealer.telemetry]
$(e2e_telemetry_table)
EOF
}
