use std::io::Write;
use std::path::Path;
use std::process::Command;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use cpu_time::ProcessTime;
use rand::{Rng, SeedableRng};
use serde_json::{Value, json};
use timescales_core::identity::ExecutorKey;
use timescales_core::{CommitmentScheme, Encode, FlowMode, MarketParams, TraderId};
use timescales_executor::mpc::{
    Engine, Fp, LtCircuit, MpcCommittee, MpcConfig, MpcExecutor, NetworkModel,
};
use timescales_executor::prover::Keys;
use timescales_executor::tee::LocalTeeDeployment;
use timescales_executor::workload::{WorkloadConfig, attach_masked, default_params, generate};
use timescales_executor::zk::{Groth16Prover, shape_for};
use timescales_executor::{
    ConfidentialExecutor, ExecutionResult, LocalKeySchedule, ReferenceExecutor,
};

use crate::stats::{ms, percentile};

pub(crate) struct RunConfig {
    pub n: usize,
    pub reps: usize,
    pub parties: usize,
    pub circuit: String,
    pub authenticated: bool,
    pub half_width: u32,
}

fn params(scheme: CommitmentScheme, half_width: u32) -> MarketParams {
    let mut p = default_params(FlowMode::DualFlow, scheme);
    p.band_half_width = half_width;
    p
}

fn workload_cfg(p: MarketParams, n: usize, seed: u64) -> WorkloadConfig {
    let mut c = WorkloadConfig::new(p, n, seed);
    c.traders = (n / 4).clamp(4, 10_000);
    c
}

fn machine() -> Value {
    json!({
        "os": std::env::consts::OS,
        "arch": std::env::consts::ARCH,
        "threads": std::thread::available_parallelism().map(|n| n.get()).unwrap_or(1),
        "profile": if cfg!(debug_assertions) { "debug" } else { "release" },
    })
}

fn stage_means(results: &[ExecutionResult]) -> Value {
    let mut sums: Vec<(&str, Duration)> = Vec::new();
    for r in results {
        for (k, d) in &r.metrics.stages {
            match sums.iter_mut().find(|(n, _)| *n == k) {
                Some(e) => e.1 += *d,
                None => sums.push((k, *d)),
            }
        }
    }
    let n = results.len().max(1) as u32;
    Value::Object(
        sums.into_iter()
            .map(|(k, d)| (k.to_string(), json!(ms(d / n))))
            .collect(),
    )
}

async fn plaintext(kind: &str, c: &RunConfig) -> Result<Value> {
    let p = params(CommitmentScheme::Sha256, c.half_width);
    let cfg = workload_cfg(p, c.n, 7);
    let t = Instant::now();
    let (batch, tee) = if kind == "tee" {
        let dep = LocalTeeDeployment::new(5, 3, 1);
        dep.prepare_epoch(p.market, cfg.epoch);
        let w = generate(&cfg, dep.keys.as_ref());
        dep.commit(&w.batch.header);
        (w.batch, Some(dep))
    } else {
        let keys = LocalKeySchedule::new([7; 32]);
        (generate(&cfg, &keys).batch, None)
    };
    let gen_ms = ms(t.elapsed());
    let reference = ReferenceExecutor::new(
        Arc::new(LocalKeySchedule::new([7; 32])),
        ExecutorKey::from_seed([1; 32]),
    );
    let cpu = ProcessTime::now();
    let mut totals = Vec::with_capacity(c.reps);
    let mut results = Vec::with_capacity(c.reps);
    for _ in 0..c.reps {
        let t = Instant::now();
        let r = match &tee {
            Some(dep) => dep.executor.execute(batch.clone()).await?,
            None => reference.execute(batch.clone()).await?,
        };
        totals.push(t.elapsed());
        results.push(r);
    }
    let cpu_ms = ms(cpu.elapsed()) / c.reps as f64;
    let r0 = &results[0];
    Ok(json!({
        "experiment": kind,
        "n": c.n,
        "reps": c.reps,
        "band_ticks": 2 * c.half_width + 1,
        "generate_ms": gen_ms,
        "p50_ms": ms(percentile(&totals, 50)),
        "p95_ms": ms(percentile(&totals, 95)),
        "p99_ms": ms(percentile(&totals, 99)),
        "throughput_orders_per_s": c.n as f64 / percentile(&totals, 50).as_secs_f64(),
        "cpu_ms_per_rep": cpu_ms,
        "peak_heap_bytes": crate::peak_bytes(),
        "stages_mean_ms": stage_means(&results),
        "accepted": r0.metrics.accepted,
        "fills": r0.artifacts.fills.len(),
        "input_bytes": batch.envelopes.len() * timescales_core::intent::ENVELOPE_LEN,
        "machine": machine(),
    }))
}

async fn mpc(c: &RunConfig) -> Result<Value> {
    let p = params(CommitmentScheme::Sha256, c.half_width);
    let cfg = workload_cfg(p, c.n, 11);
    let keys = LocalKeySchedule::new([7; 32]);
    let circuit = if c.circuit == "ripple" {
        LtCircuit::Ripple
    } else {
        LtCircuit::LogDepth
    };
    let committee = Arc::new(MpcCommittee::new(
        MpcConfig {
            parties: c.parties,
            authenticated: c.authenticated,
            circuit,
            dealer_seed: Some(rand_chacha::ChaCha20Rng::seed_from_u64(3).get_seed()),
        },
        ExecutorKey::from_seed([3; 32]),
    ));
    let exec = MpcExecutor::new(committee.clone());
    let mut reports = Vec::new();
    let mut walls = Vec::new();
    let mut input_bytes = 0usize;
    for rep in 0..c.reps {
        // Masks are single use: fresh inputs per repetition.
        let mut w = generate(
            &WorkloadConfig {
                seed: 11 + rep as u64,
                ..cfg.clone()
            },
            &keys,
        );
        attach_masked(&mut w, &committee);
        input_bytes = w.batch.masked.iter().map(|m| m.to_bytes().len()).sum();
        let t = Instant::now();
        exec.execute(w.batch).await?;
        walls.push(t.elapsed());
        reports.push(committee.last_report().context("report")?);
    }
    let r = &reports[0];
    let compute: Vec<Duration> = reports.iter().map(|r| r.per_party_compute()).collect();
    let lan: Vec<Duration> = reports
        .iter()
        .map(|r| r.online_latency(&NetworkModel::LAN))
        .collect();
    let wan: Vec<Duration> = reports
        .iter()
        .map(|r| r.online_latency(&NetworkModel::WAN))
        .collect();
    let phases: Vec<Value> = r
        .phases
        .iter()
        .map(|(name, m)| json!({"phase": name, "rounds": m.rounds, "bytes": m.bytes, "multiplications": m.multiplications, "comparisons": m.comparisons}))
        .collect();
    Ok(json!({
        "experiment": "mpc",
        "n": c.n,
        "reps": c.reps,
        "parties": c.parties,
        "circuit": c.circuit,
        "authenticated": c.authenticated,
        "band_ticks": 2 * c.half_width + 1,
        "simulation_wall_p50_ms": ms(percentile(&walls, 50)),
        "per_party_compute_p50_ms": ms(percentile(&compute, 50)),
        "per_party_compute_p95_ms": ms(percentile(&compute, 95)),
        "online_lan_p50_ms": ms(percentile(&lan, 50)),
        "online_lan_p99_ms": ms(percentile(&lan, 99)),
        "online_wan_p50_ms": ms(percentile(&wan, 50)),
        "online_wan_p99_ms": ms(percentile(&wan, 99)),
        "rounds": r.meter.rounds,
        "bytes_total": r.meter.bytes,
        "bytes_per_party": r.meter.bytes_per_party(r.parties),
        "multiplications": r.meter.multiplications,
        "comparisons": r.meter.comparisons,
        "mac_checks": r.meter.mac_checks,
        "preprocessing": {
            "triples": r.preprocessing.triples,
            "bits": r.preprocessing.bits,
            "bounded_randoms": r.preprocessing.bounded_randoms,
            "input_masks": r.preprocessing.input_masks,
            "dealer_ms": ms(r.dealer_time),
        },
        "phases": phases,
        "input_bytes": input_bytes,
        "peak_heap_bytes": crate::peak_bytes(),
        "machine": machine(),
    }))
}

async fn zk(c: &RunConfig) -> Result<Value> {
    let mut p = params(CommitmentScheme::PoseidonBn254, c.half_width);
    // The circuit is sized for exactly `n` envelopes.
    p.max_batch_envelopes = u32::try_from(c.n.next_power_of_two()).unwrap_or(u32::MAX);
    let mut cfg = workload_cfg(p, c.n, 13);
    cfg.cancel_pct = 0;
    let keys = Arc::new(LocalKeySchedule::new([7; 32]));
    let w = generate(&cfg, keys.as_ref());
    let shape = shape_for(&w.batch.header, c.n);
    let constraints = timescales_executor::prover::constraint_count(shape)?;
    let mut rng = rand_chacha::ChaCha20Rng::seed_from_u64(1);
    let t = Instant::now();
    let pk = Arc::new(Keys::setup(shape, &mut rng)?);
    let setup = t.elapsed();
    let pk_bytes = pk.to_bytes()?.len();
    let vk_bytes = pk.vk_bytes().len();

    let exec = ReferenceExecutor::new(keys, ExecutorKey::from_seed([1; 32]))
        .with_prover(Arc::new(Groth16Prover::new(pk.clone())));
    let mut prove = Vec::new();
    let mut total = Vec::new();
    let mut last = None;
    for _ in 0..c.reps {
        let t = Instant::now();
        let r = exec.execute(w.batch.clone()).await?;
        total.push(t.elapsed());
        prove.push(r.metrics.stage("prove").unwrap_or_default());
        last = Some(r);
    }
    let r = last.context("no run")?;
    let bundle = timescales_executor::verifier::ProofBundle::from_bytes(
        &r.proof.as_ref().context("proof")?.bytes,
    )?;
    let vk = timescales_executor::verifier::decode_vk(&pk.vk_bytes())?;
    let commitments: Vec<_> = w.batch.envelopes.iter().map(|e| e.commitment).collect();
    let mut verify = Vec::new();
    for _ in 0..20 {
        let t = Instant::now();
        timescales_executor::verifier::verify_bundle(
            &vk,
            &bundle,
            &w.batch.header,
            &commitments,
            &w.batch.prior_state,
            &r.artifacts,
            &r.receipt.outcome.clearing,
        )?;
        verify.push(t.elapsed());
    }
    Ok(json!({
        "experiment": "zk",
        "n": c.n,
        "reps": c.reps,
        "band_ticks": shape.ticks,
        "qty_bits": shape.qty_bits,
        "constraints": constraints,
        "setup_ms": ms(setup),
        "prove_p50_ms": ms(percentile(&prove, 50)),
        "prove_p95_ms": ms(percentile(&prove, 95)),
        "execute_and_prove_p50_ms": ms(percentile(&total, 50)),
        "verify_p50_ms": ms(percentile(&verify, 50)),
        "verify_p99_ms": ms(percentile(&verify, 99)),
        "proof_bytes": bundle.proof.len(),
        "bundle_bytes": bundle.to_bytes().len(),
        "proving_key_bytes": pk_bytes,
        "verifying_key_bytes": vk_bytes,
        "peak_heap_bytes": crate::peak_bytes(),
        "machine": machine(),
    }))
}

/// Oblivious bitonic sort in the same MPC engine: the generic baseline the
/// band encoding is compared against.
fn sort_baseline(c: &RunConfig) -> Result<Value> {
    let n = c.n.next_power_of_two();
    let mut e = Engine::new(c.parties, c.authenticated, LtCircuit::LogDepth, 5);
    let mut rng = rand_chacha::ChaCha20Rng::seed_from_u64(9);
    let keys: Vec<Fp> = (0..n)
        .map(|_| Fp::from_u64(rng.gen_range(0..1u64 << 40)))
        .collect();
    let owner = TraderId([0; 32]);
    let (off, masks) = e.dealer().input_masks(owner, n);
    let s = e.dealer().take_masks(&owner, off, n).context("masks")?;
    let d: Vec<Fp> = keys.iter().zip(&masks).map(|(x, m)| *x - *m).collect();
    let mut v = e.add_public(&s, &d);
    let t = Instant::now();
    // Each stage compares disjoint pairs, so a stage is one vector `min`.
    let mut k = 2;
    while k <= n {
        let mut j = k / 2;
        while j > 0 {
            let mut lo = Vec::new();
            let mut hi = Vec::new();
            for i in 0..n {
                let l = i ^ j;
                if l > i {
                    if i & k == 0 {
                        lo.push(i);
                        hi.push(l);
                    } else {
                        lo.push(l);
                        hi.push(i);
                    }
                }
            }
            let a = v.gather(&lo);
            let b = v.gather(&hi);
            let mn = e.min(&a, &b, 42)?;
            let mx = a.add(&b).sub(&mn);
            let mut idx = vec![0usize; n];
            let mut parts = Vec::new();
            for (p, (&x, &y)) in lo.iter().zip(&hi).enumerate() {
                idx[x] = parts.len();
                parts.push(mn.gather(&[p]));
                idx[y] = parts.len();
                parts.push(mx.gather(&[p]));
            }
            let all =
                timescales_executor::mpc::shares::Shared::concat(&parts.iter().collect::<Vec<_>>());
            v = all.gather(&idx);
            j /= 2;
        }
        k *= 2;
    }
    let wall = t.elapsed();
    let out = e.open(&v)?;
    e.mac_check()?;
    if out.windows(2).any(|w| w[0].value() > w[1].value()) {
        bail!("sort network produced unsorted output");
    }
    let m = e.meter();
    let per_party = wall / u32::try_from(c.parties).unwrap_or(1);
    Ok(json!({
        "experiment": "sort",
        "n": n,
        "parties": c.parties,
        "comparisons": m.comparisons,
        "multiplications": m.multiplications,
        "rounds": m.rounds,
        "bytes_per_party": m.bytes_per_party(c.parties),
        "per_party_compute_ms": ms(per_party),
        "online_lan_ms": ms(per_party + NetworkModel::LAN.overhead(&m, c.parties)),
        "online_wan_ms": ms(per_party + NetworkModel::WAN.overhead(&m, c.parties)),
        "note": "sorts n 42-bit keys only; a full sort-based matcher needs at least this plus allocation",
        "machine": machine(),
    }))
}

fn sizes(c: &RunConfig) -> Result<Value> {
    let p = params(CommitmentScheme::Sha256, c.half_width);
    let keys = LocalKeySchedule::new([7; 32]);
    let mut cfg = workload_cfg(p, 64, 1);
    cfg.cancel_pct = 0;
    let mut w = generate(&cfg, &keys);
    let committee = MpcCommittee::new(MpcConfig::default(), ExecutorKey::from_seed([3; 32]));
    attach_masked(&mut w, &committee);
    let masked = w
        .batch
        .masked
        .iter()
        .map(|m| m.to_bytes().len())
        .max()
        .unwrap_or(0);
    Ok(json!({
        "experiment": "sizes",
        "band_ticks": 2 * c.half_width + 1,
        "sealed_envelope_bytes": timescales_core::intent::ENVELOPE_LEN,
        "masked_intent_bytes": masked,
        "batch_header_bytes": w.batch.header.to_bytes().len(),
        "machine": machine(),
    }))
}

pub(crate) async fn run(experiment: &str, c: &RunConfig) -> Result<Value> {
    match experiment {
        "reference" | "tee" => plaintext(experiment, c).await,
        "mpc" => mpc(c).await,
        "zk" => zk(c).await,
        "sort" => sort_baseline(c),
        "sizes" => sizes(c),
        other => bail!("unknown experiment {other}"),
    }
}

/// `(experiment, n, reps, extra args)` per suite.
fn suite(name: &str) -> Vec<(&'static str, usize, usize, Vec<String>)> {
    let s = |v: &[&str]| v.iter().map(|x| (*x).to_string()).collect::<Vec<_>>();
    let mut out = Vec::new();
    let plain = |e: &'static str, out: &mut Vec<_>| {
        for (n, reps) in [
            (100, 30),
            (1_000, 30),
            (10_000, 15),
            (100_000, 7),
            (1_000_000, 3),
        ] {
            out.push((e, n, reps, vec![]));
        }
    };
    let mpc = |out: &mut Vec<_>| {
        for (n, reps) in [(100, 5), (1_000, 3), (10_000, 1)] {
            out.push(("mpc", n, reps, vec![]));
        }
        for (circuit, auth) in [("ripple", "true"), ("log", "false")] {
            out.push((
                "mpc",
                1_000,
                2,
                s(&["--circuit", circuit, "--authenticated", auth]),
            ));
        }
        out.push(("mpc", 1_000, 2, s(&["--parties", "5"])));
        for w in ["8", "16", "64"] {
            out.push(("mpc", 1_000, 2, s(&["--half-width", w])));
        }
    };
    let zk = |out: &mut Vec<_>| {
        for (n, reps) in [(16, 3), (64, 3), (256, 2), (1_024, 1)] {
            out.push(("zk", n, reps, vec![]));
        }
        out.push(("zk", 64, 2, s(&["--half-width", "8"])));
    };
    let sort = |out: &mut Vec<_>| {
        // Same n for the auction and the sort so H4 compares like with like.
        for n in [128, 1_024, 4_096] {
            out.push(("sort", n, 1, vec![]));
            out.push(("mpc", n, 1, vec![]));
        }
    };
    match name {
        "reference" => plain("reference", &mut out),
        "tee" => plain("tee", &mut out),
        "mpc" => mpc(&mut out),
        "zk" => zk(&mut out),
        "sort" => sort(&mut out),
        "sizes" => out.push(("sizes", 0, 1, vec![])),
        // Needs well over 48 GB of heap. Runs under memory compression.
        "zk-large" => out.push(("zk", 4_096, 1, vec![])),
        "extra" => {
            for (circuit, auth) in [("ripple", "true"), ("log", "false")] {
                out.push((
                    "mpc",
                    1_000,
                    2,
                    s(&["--circuit", circuit, "--authenticated", auth]),
                ));
            }
            for n in [16, 64, 256] {
                out.push(("mpc", n, 3, vec![]));
            }
            out.push(("sort", 64, 1, vec![]));
        }
        "quick" => {
            out.push(("reference", 1_000, 5, vec![]));
            out.push(("tee", 1_000, 5, vec![]));
            out.push(("mpc", 100, 1, vec![]));
            out.push(("zk", 16, 1, vec![]));
            out.push(("sort", 128, 1, vec![]));
            out.push(("sizes", 0, 1, vec![]));
        }
        "full" => {
            plain("reference", &mut out);
            plain("tee", &mut out);
            mpc(&mut out);
            zk(&mut out);
            sort(&mut out);
            out.push(("sizes", 0, 1, vec![]));
        }
        _ => {}
    }
    out
}

pub(crate) fn plan(name: &str, dir: &Path) -> Result<()> {
    let runs = suite(name);
    if runs.is_empty() {
        bail!("unknown suite {name}");
    }
    std::fs::create_dir_all(dir)?;
    let exe = std::env::current_exe()?;
    for (exp, n, reps, extra) in runs {
        let file = dir.join(format!("{exp}.jsonl"));
        eprintln!("running {exp} n={n} reps={reps} {}", extra.join(" "));
        let t = Instant::now();
        let out = Command::new(&exe)
            .args([
                "run",
                "--experiment",
                exp,
                "--n",
                &n.to_string(),
                "--reps",
                &reps.to_string(),
            ])
            .args(&extra)
            .output()?;
        if !out.status.success() {
            let line = json!({"experiment": exp, "n": n, "error": String::from_utf8_lossy(&out.stderr).lines().last().unwrap_or("").to_string()});
            eprintln!("  failed: {line}");
            let mut f = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&file)?;
            writeln!(f, "{line}")?;
            continue;
        }
        let mut f = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&file)?;
        f.write_all(&out.stdout)?;
        eprintln!("  done in {:.1}s", t.elapsed().as_secs_f64());
    }
    Ok(())
}
