// Places one order through a running node with the built SDK, the way the
// web app does: verified market context, one session grant, one intent
// signature, sealing and parking, then follows it until it ends (E16.
// The second wallet of the stack browser test).
//
//   npm run --prefix ts -w @timescales/sdk build
//   node ts/packages/sdk/scripts/place-order.ts --market <address> --keypair <file> \
//     --program <id> --upgrade-authority <address|none> --side sell --lots 5 --limit-tick 10000
//
// The keypair is a Solana CLI keypair file and signs like a wallet that
// follows every request (the SDK's test wallet). The pins (program,
// upgrade authority, cluster, market) come from the command line, never
// from the node. The genesis hash is the one the given RPC serves.
import { readFileSync } from 'node:fs';
import { parseArgs } from 'node:util';
import type { Address, Instruction } from '@solana/kit';
import { ServerClock, TimescalesApi, TimescalesStream } from '@timescales/sdk/api';
import { b58, ed25519PublicKey, equal, hex } from '@timescales/sdk/core';
import { openJournal } from '@timescales/sdk/journal';
import { OrderService, badge, type OrderRecord } from '@timescales/sdk/orders';
import {
  associatedTokenAddress,
  buildTraderTx,
  checkSignedTx,
  createTimescalesRpc,
  depositIx,
  openTraderIx,
  sendAndConfirm,
  traderPda,
} from '@timescales/sdk/solana';
import { createTestWallet } from '@timescales/sdk/testing';
import type { AppPins } from '@timescales/sdk/verify';
import { TradingSession } from '@timescales/sdk/wallet';

const USAGE = `usage: place-order.ts --market ADDRESS --keypair FILE --program ID --upgrade-authority ADDRESS|none
  [--api URL] [--rpc URL] [--cluster localnet|devnet|mainnet-beta]
  [--side buy|sell] [--role maker|taker] [--kind limit|market] [--limit-tick N] [--lots N] [--epochs N]
  [--deposit-base ATOMS] [--deposit-quote ATOMS] [--no-wait] [--timeout-s N]`;

const { values } = parseArgs({
  options: {
    api: { type: 'string', default: 'http://127.0.0.1:8080' },
    rpc: { type: 'string', default: 'http://127.0.0.1:8899' },
    market: { type: 'string' },
    keypair: { type: 'string' },
    program: { type: 'string' },
    'upgrade-authority': { type: 'string' },
    cluster: { type: 'string', default: 'localnet' },
    side: { type: 'string', default: 'buy' },
    role: { type: 'string', default: 'maker' },
    kind: { type: 'string', default: 'limit' },
    'limit-tick': { type: 'string' },
    lots: { type: 'string', default: '1' },
    epochs: { type: 'string', default: '2' },
    'deposit-base': { type: 'string', default: '0' },
    'deposit-quote': { type: 'string', default: '0' },
    'no-wait': { type: 'boolean', default: false },
    'timeout-s': { type: 'string', default: '300' },
    help: { type: 'boolean', default: false },
  },
});

function fail(message: string): never {
  console.error(`place-order: ${message}`);
  process.exit(1);
}

if (values.help) {
  console.log(USAGE);
  process.exit(0);
}
if (values.market === undefined || values.keypair === undefined || values.program === undefined) {
  fail(`--market, --keypair and --program are required\n${USAGE}`);
}
const authorityArg = values['upgrade-authority'];
if (authorityArg === undefined)
  fail(`--upgrade-authority is required ("none" for a frozen program)\n${USAGE}`);
const clusterArg = values.cluster;
if (clusterArg !== 'localnet' && clusterArg !== 'devnet' && clusterArg !== 'mainnet-beta') {
  fail('--cluster must be localnet, devnet or mainnet-beta');
}
const cluster: AppPins['cluster'] = clusterArg;
const pick = <T extends string>(name: string, value: string, options: readonly T[]): T => {
  if (!(options as readonly string[]).includes(value))
    fail(`--${name} must be one of ${options.join(', ')}`);
  return value as T;
};
const side = pick('side', values.side, ['buy', 'sell']) === 'buy' ? 0 : 1;
const role = pick('role', values.role, ['maker', 'taker']) === 'maker' ? 0 : 1;
const kind = pick('kind', values.kind, ['limit', 'market']) === 'limit' ? 0 : 1;
if (kind === 0 && values['limit-tick'] === undefined) fail('a limit order needs --limit-tick');

function address(name: string, value: string): Address {
  try {
    b58.decode(value, 32);
  } catch {
    fail(`--${name} is not a base58 address`);
  }
  return value as Address;
}

const market = address('market', values.market);
const program = address('program', values.program);
const upgradeAuthority =
  authorityArg === 'none' ? null : address('upgrade-authority', authorityArg);

// A Solana CLI keypair file: 64 numbers, the secret seed then the public key.
const key = Uint8Array.from(JSON.parse(readFileSync(values.keypair, 'utf8')) as number[]);
if (key.length !== 64) fail('the keypair file must hold 64 bytes');
const seed = key.subarray(0, 32);
if (!equal(ed25519PublicKey(seed), key.subarray(32))) fail('the keypair file is inconsistent');
const wallet = createTestWallet({ seed, name: 'place-order keypair' });
const owner = wallet.address;

async function main(): Promise<number> {
  const api = new TimescalesApi({ baseUrl: values.api });
  const clock = new ServerClock();
  await clock.sync(api);
  const info = await api.info();
  const rpc = createTimescalesRpc(values.rpc);
  const pins: AppPins = {
    programId: program,
    genesisHash: await rpc.genesisHash(),
    cluster,
    market,
    upgradeAuthority,
  };
  console.log(`wallet ${owner} on ${cluster}, node ${info.nodeVersion} (${info.profile})`);

  // Optional account opening and deposit, signed and sent like a wallet transaction.
  const depositBase = BigInt(values['deposit-base']);
  const depositQuote = BigInt(values['deposit-quote']);
  let minContextSlot: bigint | undefined;
  if (depositBase > 0n || depositQuote > 0n) {
    const m = (await rpc.market(market)).value;
    const [traderAddress] = await traderPda(program, market, owner);
    const instructions: Instruction[] = [];
    if ((await rpc.trader(traderAddress)) === null) {
      instructions.push(await openTraderIx({ program, owner, market }));
    }
    for (const [amount, sideName, mint, vault] of [
      [depositBase, 'base', m.baseMint, m.baseVault],
      [depositQuote, 'quote', m.quoteMint, m.quoteVault],
    ] as const) {
      if (amount === 0n) continue;
      const source = await associatedTokenAddress(owner, mint);
      instructions.push(
        await depositIx({ program, owner, market, source, vault, side: sideName, amount }),
      );
    }
    const { wire, lastValidBlockHeight } = await buildTraderTx({
      rpc,
      feePayer: owner,
      instructions,
    });
    const signed = await wallet.signTransaction!(wire);
    const checked = checkSignedTx(wire, signed);
    if (checked.kind !== 'ok')
      fail(
        `the signed transaction does not match: ${checked.kind === 'fail' ? checked.reason : ''}`,
      );
    const tx = await sendAndConfirm(
      rpc,
      signed,
      checked.value.lastValidBlockHeight ?? lastValidBlockHeight,
    );
    if (tx.status !== 'confirmed')
      fail(
        `deposit ${tx.status}: ${JSON.stringify(tx, (_k, v: unknown) => (typeof v === 'bigint' ? v.toString() : v))}`,
      );
    console.log(`deposited in ${tx.signature} at slot ${tx.slot}`);
    minContextSlot = tx.slot;
  }

  const session = await TradingSession.open({
    api,
    wallet,
    info,
    clock,
    market,
    ...(minContextSlot !== undefined ? { minContextSlot } : {}),
  });
  const journal = await openJournal({ cluster, program, wallet: owner });
  const streamUrl = `${values.api.replace(/^http/, 'ws').replace(/\/+$/, '')}/v1/stream`;
  const stream = new TimescalesStream({ url: streamUrl });
  const svc = new OrderService({ api, rpc, journal, stream, clock, pins });
  await svc.start(wallet, session);
  const ctx = await svc.context(market);
  console.log(
    `market ${market} verified at slot ${ctx.verifiedAtSlot}; enclave: ${ctx.enclaveLabel}`,
  );

  const prepared = svc.prepare({
    market,
    side,
    role,
    kind,
    ...(kind === 0 ? { limitTick: BigInt(values['limit-tick']!) } : {}),
    quantityLots: BigInt(values.lots),
    lifetimeEpochs: Number(values.epochs),
  });
  if (prepared.warnings.length > 0) console.log(`warnings: ${prepared.warnings.join(', ')}`);
  if (prepared.blockers.length > 0) fail(`blocked: ${prepared.blockers.join(', ')}`);
  console.log(
    `epochs ${prepared.epochs.from}..${prepared.epochs.to}, parked to ${prepared.epochs.parkedTo}`,
  );

  const placed = await svc.submit(prepared, { onStep: (s) => console.log(`  ${s}`) });
  console.log(
    `order ${placed.id} commitment ${hex.encode(placed.commitment)}: ${placed.state.kind}`,
  );
  if (placed.state.kind !== 'working') {
    svc.dispose();
    stream.close();
    return 1;
  }

  const ENDED = new Set<OrderRecord['state']['kind']>([
    'filled',
    'expired',
    'cancelled',
    'cancel_too_late',
    'verification_failed',
  ]);
  let final: OrderRecord = placed;
  if (!values['no-wait']) {
    const deadline = Date.now() + Number(values['timeout-s']) * 1000;
    let shown = '';
    final = await new Promise<OrderRecord>((resolve) => {
      let latest = placed;
      const off = svc.subscribe((records) => {
        const r = records.find((x) => x.id === placed.id);
        if (r === undefined) return;
        latest = r;
        const b = badge(r);
        const line = b.epoch === undefined ? b.state : `${b.state} #${b.epoch}`;
        if (line !== shown) {
          shown = line;
          console.log(`  ${line}`);
        }
        if (ENDED.has(r.state.kind)) {
          off();
          clearInterval(timer);
          resolve(r);
        }
      });
      // Stream events drive progress. A periodic reconcile covers a stream that is down.
      const timer = setInterval(() => {
        if (Date.now() > deadline) {
          off();
          clearInterval(timer);
          resolve(latest);
          return;
        }
        svc.reconcile(prepared.epochs.from).catch(() => undefined);
      }, 5_000);
    });
  }
  console.log(
    `final: ${final.state.kind}, filled ${final.filled} of ${final.body.kind === 'place' ? final.body.order.quantity : 0n} lots` +
      (final.fills.length > 0 ? ` at ticks ${final.fills.map((f) => f.tick).join(', ')}` : ''),
  );
  svc.dispose();
  stream.close();
  return values['no-wait'] || final.state.kind === 'filled' || final.state.kind === 'expired'
    ? 0
    : 1;
}

main().then(
  (code) => process.exit(code),
  (e: unknown) => fail(e instanceof Error ? e.message : String(e)),
);
