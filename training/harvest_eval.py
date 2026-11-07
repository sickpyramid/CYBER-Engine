"""Large-scale harvest + held-out detection scoreboard over the WHOLE corpus.

For every attack with a victim address on a Sourcify-supported chain:
  1. fetch the victim's exact verified source (keyless)
  2. compile + run the detection substrate (subprocess, isolated, parallel-safe solc)
  3. score rediscovery of the (code-aware) ground-truth class

Resumable (skips addresses already in results), concurrent, writes incrementally.
Run:  python training/harvest_eval.py [max_cases] [workers]
Watch: tail -f data/harvest.log
"""
from __future__ import annotations
import sys, json, tempfile, subprocess, time, threading
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from engine import db, fetch_source

RESULTS = ROOT / "data" / "eval_results.jsonl"
LOG = ROOT / "data" / "harvest.log"
_lock = threading.Lock()


def log(msg):
    line = f"[{time.strftime('%H:%M:%S')}] {msg}"
    with _lock:
        print(line, flush=True)
        with open(LOG, "a") as f:
            f.write(line + "\n")


def done_addresses():
    seen = set()
    if RESULTS.exists():
        for ln in RESULTS.read_text().splitlines():
            try:
                r = json.loads(ln)
                seen.add((r["chain"], r["address"].lower()))
            except Exception:
                pass
    return seen


def candidates(con, max_cases):
    rows = con.execute("""
        SELECT name, chain, vuln_class, victim_addrs, occurred_date
        FROM attacks
        WHERE victim_addrs NOT IN ('[]','') AND victim_addrs IS NOT NULL
          AND chain IS NOT NULL AND vuln_class != 'other'
        ORDER BY occurred_year DESC
    """).fetchall()
    out = []
    for r in rows:
        va = json.loads(r["victim_addrs"])
        if va and r["chain"] in fetch_source.CHAIN_IDS:
            out.append((r["chain"], va[0], r["vuln_class"], r["name"]))
    return out[:max_cases] if max_cases else out


def process(chain, addr, true_class, name):
    rec = {"name": name, "chain": chain, "address": addr, "true": true_class,
           "verified": False, "predicted_classes": [], "recall": False,
           "top1": False, "n_findings": 0, "error": None}
    try:
        with tempfile.TemporaryDirectory() as tmp:
            meta = fetch_source.fetch(chain, addr, tmp)
            if not meta or not meta.get("source_keys"):
                return rec  # unverified
            rec["verified"] = True
            kf = Path(tmp) / "keys.json"
            kf.write_text(json.dumps(meta["source_keys"]))
            proc = subprocess.run(
                [sys.executable, str(ROOT / "engine" / "detect.py"),
                 meta["src_root"], meta.get("solc") or "", str(kf)],
                capture_output=True, text=True, timeout=500)
            res = json.loads(proc.stdout.strip().splitlines()[-1]) if proc.stdout.strip() else {}
            preds = res.get("predicted_classes", [])
            rec["predicted_classes"] = preds
            rec["n_findings"] = res.get("n_findings", 0)
            rec["recall"] = true_class in preds
            rec["top1"] = bool(preds) and preds[0] == true_class
            rec["error"] = res.get("error")
    except subprocess.TimeoutExpired:
        rec["error"] = "timeout"
    except Exception as e:
        rec["error"] = f"{type(e).__name__}: {e}"
    return rec


def main(max_cases=None, workers=4):
    con = db.connect()
    seen = done_addresses()
    cands = [c for c in candidates(con, max_cases) if (c[0], c[1].lower()) not in seen]
    log(f"START  candidates={len(cands)} workers={workers} (already done: {len(seen)})")
    stats = {"tried": 0, "verified": 0, "recall": 0, "top1": 0}
    with ThreadPoolExecutor(max_workers=workers) as ex:
        futs = {ex.submit(process, c, a, t, n): (c, a) for c, a, t, n in cands}
        for fut in as_completed(futs):
            rec = fut.result()
            stats["tried"] += 1
            stats["verified"] += rec["verified"]
            stats["recall"] += rec["recall"]
            stats["top1"] += rec["top1"]
            with _lock:
                with open(RESULTS, "a") as f:
                    f.write(json.dumps(rec) + "\n")
            if rec["verified"]:
                mark = "HIT " if rec["recall"] else "miss"
                log(f"{mark} {rec['chain']:9} {rec['name'][:22]:22} true={rec['true']:16} "
                    f"pred={rec['predicted_classes'][:2]} n={rec['n_findings']}  "
                    f"[{stats['verified']} ver | rec {stats['recall']} | t1 {stats['top1']}]")
    v = stats["verified"] or 1
    log(f"DONE  tried={stats['tried']} verified={stats['verified']} "
        f"recall={stats['recall']}/{stats['verified']}={stats['recall']/v:.0%} "
        f"top1={stats['top1']}/{stats['verified']}={stats['top1']/v:.0%}")


if __name__ == "__main__":
    mc = int(sys.argv[1]) if len(sys.argv) > 1 else None
    wk = int(sys.argv[2]) if len(sys.argv) > 2 else 4
    main(mc, wk)
