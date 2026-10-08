"""Per-epoch phase durations of the local stack, from the node's events table.

    scripts/e2e/epoch-phases.py target/e2e/data/node/node.sqlite "quorum 2" [first_epoch] [last_epoch]

Each line gives the milliseconds between consecutive milestones of one epoch
(cutoff, commit confirmed, beacon revealed, execution started, quorum
reached, receipt posted, verifying, applying, settled), then the medians.
The results in benchmarks/results/epoch-phases-quorum{1,2}.txt were taken
with scripts/e2e/up.sh (TIMESCALES_RECEIPT_QUORUM=1 or 2) and one resting
order placed with ts/packages/sdk/scripts/place-order.ts.
"""

import json
import sqlite3
import statistics
import sys

db, label = sys.argv[1], sys.argv[2]
first = int(sys.argv[3]) if len(sys.argv) > 3 else 0
last = int(sys.argv[4]) if len(sys.argv) > 4 else 10**9

con = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
rows = con.execute("select at_ms, event from events order by seq").fetchall()
by_epoch = {}
for at_ms, ev in rows:
    e = json.loads(ev)
    kind = e.get("kind", "")
    if not kind.startswith("epoch."):
        continue
    epoch = int(e["epoch"])
    if epoch < first or epoch > last:
        continue
    d = by_epoch.setdefault(epoch, {})
    if kind == "epoch.settlement":
        kind = f"epoch.settlement.{e.get('stage')}"
    if kind == "epoch.cosigned":
        d.setdefault("cosigned", []).append(at_ms)
        continue
    d.setdefault(kind, at_ms)  # first occurrence

milestones = [
    ("closed", "epoch.closed"),
    ("committed", "epoch.committed"),
    ("revealed", "epoch.revealed"),
    ("executing", "epoch.executing"),
    ("quorum", "epoch.quorum"),
    ("posted", "epoch.posted"),
    ("verifying", "epoch.settlement.verifying"),
    ("applying", "epoch.settlement.applying"),
    ("settled", "epoch.settled"),
]
cols = [
    ("close->commit", "closed", "committed"),
    ("commit->reveal", "committed", "revealed"),
    ("reveal->exec", "revealed", "executing"),
    ("exec->quorum", "executing", "quorum"),
    ("quorum->posted", "quorum", "posted"),
    ("posted->verifying", "posted", "verifying"),
    ("verifying->applying", "verifying", "applying"),
    ("applying->settled", "applying", "settled"),
    ("reveal->posted", "revealed", "posted"),
    ("posted->settled", "posted", "settled"),
    ("commit->settled", "committed", "settled"),
    ("close->settled", "closed", "settled"),
]
complete = []
print(f"# {label}")
print("epoch  " + "  ".join(f"{c[0]:>18}" for c in cols) + "  cosigs")
series = {c[0]: [] for c in cols}
for epoch in sorted(by_epoch):
    d = by_epoch[epoch]
    t = {name: d.get(kind) for name, kind in milestones}
    if any(t[n] is None for n in ("closed", "committed", "revealed", "settled")):
        continue
    vals = []
    for name, a, b in cols:
        if t.get(a) is None or t.get(b) is None:
            vals.append(None)
        else:
            v = t[b] - t[a]
            vals.append(v)
            series[name].append(v)
    complete.append(epoch)
    print(f"{epoch:5d}  " + "  ".join(f"{(v if v is not None else float('nan')):18.0f}" for v in vals) + f"  {len(d.get('cosigned', []))}")
print(f"epochs: {len(complete)} ({complete[0] if complete else '-'}..{complete[-1] if complete else '-'})")
for name, _, _ in cols:
    s = series[name]
    if s:
        print(f"median {name:>18}: {statistics.median(s):8.0f} ms   min {min(s):6.0f}  max {max(s):6.0f}")
