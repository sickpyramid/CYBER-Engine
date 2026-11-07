"""Held-out rediscovery scoreboard (detection tier).

For corpus cases that (a) have a known vulnerability class and (b) a victim address
with verified source on Sourcify, fetch the *real* source, run the detection
substrate, and score whether the engine rediscovers the true class — on contracts
that are NOT its training signal.

detection-tier metrics:
  recall  = true class appears anywhere in findings
  top1    = true class is the highest-ranked finding

The exploit tier (fork + PoC drain) is scored separately once an archive RPC is wired.
"""
from __future__ import annotations
import sys, json, tempfile, subprocess, sqlite3
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from engine import db, fetch_source

# classes the deterministic substrate can plausibly catch (others need the reasoning layer)
STATIC_DETECTABLE = {"reentrancy", "access_control", "unchecked_external",
                     "arithmetic", "proxy_upgrade", "logic_accounting"}


def candidates(con, limit=None):
    rows = con.execute("""
        SELECT name, chain, vuln_class, victim_addrs, occurred_date
        FROM attacks
        WHERE victim_addrs NOT IN ('[]','') AND victim_addrs IS NOT NULL
          AND vuln_class IN ({})
        ORDER BY occurred_year DESC
    """.format(",".join("?" * len(STATIC_DETECTABLE))), tuple(STATIC_DETECTABLE)).fetchall()
    out = []
    for r in rows:
        va = json.loads(r["victim_addrs"])
        if va:
            out.append((r["chain"], va[0], r["vuln_class"], r["name"], r["occurred_date"]))
    return out[:limit] if limit else out


def evaluate(limit=None, verbose=True):
    con = db.connect()
    cands = candidates(con, limit)
    tried = verified = recall_hit = top1_hit = 0
    results = []
    for chain, addr, true_class, name, date in cands:
        tried += 1
        with tempfile.TemporaryDirectory() as tmp:
            meta = fetch_source.fetch(chain, addr, tmp)
            if not meta or not meta.get("source_keys"):
                if verbose: print(f"  skip (unverified)  {chain:9} {name[:20]}")
                continue
            verified += 1
            keys_file = Path(tmp) / "keys.json"
            keys_file.write_text(json.dumps(meta["source_keys"]))
            proc = subprocess.run(
                [sys.executable, str(ROOT / "engine" / "detect.py"),
                 meta["src_root"], meta.get("solc") or "", str(keys_file)],
                capture_output=True, text=True, timeout=600)
            try:
                res = json.loads(proc.stdout.strip().splitlines()[-1])
            except Exception:
                res = {"findings": [], "predicted_classes": []}
            preds = res.get("predicted_classes", [])
            top = preds[0] if preds else None
            rec = true_class in preds
            t1 = (top == true_class)
            recall_hit += rec
            top1_hit += t1
            results.append({"name": name, "chain": chain, "true": true_class,
                            "top": top, "recall": rec, "top1": t1,
                            "n_findings": len(res.get("findings", []))})
            if verbose:
                mark = "HIT " if rec else "miss"
                print(f"  {mark} {chain:9} {name[:20]:20} true={true_class:16} "
                      f"top={top or '-':16} findings={len(res.get('findings',[]))}")
    print("\n=== DETECTION-TIER SCOREBOARD ===")
    print(f"candidates tried:      {tried}")
    print(f"verified (had source): {verified}")
    if verified:
        print(f"recall (true class found):  {recall_hit}/{verified} = {recall_hit/verified:.0%}")
        print(f"top-1 (true class ranked #1): {top1_hit}/{verified} = {top1_hit/verified:.0%}")
    con.close()
    return results


if __name__ == "__main__":
    lim = int(sys.argv[1]) if len(sys.argv) > 1 else None
    evaluate(limit=lim)
