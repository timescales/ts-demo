# Timescales - Colosseum Hackathon Demo

Sealed-bid batch auctions with confidential execution, settled on Solana.

Orders are sealed to a per-epoch key whose secret exists only as threshold
shares held by a committee. At the cutoff the relay commits the batch root on
chain, a beacon taken from later slots orders the batch, the committee
releases the key to attested executors, a quorum of executors signs one
outcome, and a native Solana program re-checks every balance change before
any funds move.

> Research code. Not audited. The enclave platform in every provided
> configuration is simulated. Do not use with real funds.

## Layout

| Path | What it holds |
| --- | --- |
| `crates/timescales-core` | canonical encoding, hashing, keys, sealed envelopes, price commitments |
| `crates/timescales-auction` | the auction: validation, collateral, clearing, allocation, settlement deltas, receipts |
| `crates/timescales-executor` | execution backends: reference pipeline, attested enclave with key release, MPC, proofs, scheduler |
| `crates/timescales-chain` | Solana: instruction builders, account layouts, RPC and LiteSVM providers |
| `crates/timescales-service` | shared service layer: wire messages, API types, configuration, signed envelopes, TLS, SQLite, relay |
| `crates/timescales-node` | the node (`timescales-node`) and the admin tool (`timescales-admin`) |
| `crates/timescales-enclave` | the enclave service |
| `crates/timescales-krc` | committee member and dealer |
| `crates/timescales-cli` | demo, workload generation, benchmarks, bounded model checker, examples |
| `programs/timescales-settlement` | the on-chain settlement program |
| `ts/packages/sdk` | TypeScript SDK |
| `ts/apps/web` | trading app |
| `config/` | market parameters |
| `scripts/` | local stack, program build, CI checks |

## Requirements

Rust 1.98 (see `rust-toolchain.toml`), Node 24, and the Solana CLI with
`cargo build-sbf` and `solana-test-validator` for the program and the local
stack.

## Build and test

```sh
cargo build --workspace
cargo test --workspace
```

```sh
scripts/build-program.sh
cd programs/timescales-settlement && cargo test
```

```sh
cd ts
npm install
npm run typecheck
npm run lint
npm test
```

## Demo in one process

Runs the relay, threshold key release, attested execution, failover to the
MPC committee in epoch 3, receipt checks and settlement against an in-memory
chain. Every key comes from a fixed seed, which the flag acknowledges.

```sh
cargo run --release -p timescales-cli -- demo --epochs 4 --orders 300 --traders 100 --fail-tee-at 3 --insecure-dev-keys
```

## Local stack

Starts a local validator with the program, a market with three simulated
enclaves and receipt quorum 2, a committee of three with threshold two, the
dealer, the node and the trading app. State lives under `target/e2e`.

```sh
scripts/e2e/up.sh
```

The node API listens on `http://127.0.0.1:8080` and the app on
`http://localhost:4173`. `scripts/e2e/down.sh` stops everything.

To trade from a browser wallet, give it SOL and the market's test tokens on
the local validator first:

```sh
scripts/e2e/fund-wallet.sh <wallet-address>
```

Wallets cannot simulate transactions against a local validator, so they warn
before signing. The app sends the signed transaction to the local RPC itself.
After restarting the stack, reload the app: each run creates a new market and
rebuilds the app pinned to it.

## Research tools

```sh
cargo run --release -p timescales-cli --bin timescales-bench -- plan quick
cargo run --release -p timescales-cli --bin timescales-formal -- --orders 3 --ticks 4 --max-qty 3
```

The first runs a benchmark suite (`quick`, `full`, `reference`, `tee`,
`mpc`, `zk`, `sort`, `sizes`) and writes results under `target/bench`. The
second checks the clearing and allocation rule exhaustively over every small
book.

## Licence

MIT.
