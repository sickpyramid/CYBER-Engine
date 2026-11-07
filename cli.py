#!/usr/bin/env python3
"""CyberAgent engine CLI.  Usage:
    python cli.py ingest defihacklabs        # parse the cloned corpus into data/corpus.sqlite
    python cli.py stats                       # show corpus summary
"""
import sys, json
from pathlib import Path
from engine import db

HERE = Path(__file__).resolve().parent
VENDOR = HERE / "vendor"

def cmd_ingest(which):
    con = db.connect()
    if which in ("defihacklabs", "all"):
        from engine.sources import defihacklabs
        root = VENDOR / "DeFiHackLabs"
        n = defihacklabs.ingest(con, root)
        con.execute("INSERT INTO ingest_runs(source,started_at,finished_at,rows_added,notes) VALUES (?,?,?,?,?)",
                    ("defihacklabs", db.now(), db.now(), n, str(root)))
        con.commit()
        print(f"defihacklabs: +{n} attacks")
    con.close()

def cmd_stats():
    con = db.connect()
    c = con.cursor()
    total = c.execute("SELECT COUNT(*) FROM attacks").fetchone()[0]
    print(f"TOTAL ATTACKS: {total}\n")
    print("By chain:")
    for r in c.execute("SELECT COALESCE(chain,'?') ch, COUNT(*) n FROM attacks GROUP BY ch ORDER BY n DESC"):
        print(f"  {r['ch']:12} {r['n']}")
    print("\nBy vuln class:")
    for r in c.execute("SELECT vuln_class, COUNT(*) n FROM attacks GROUP BY vuln_class ORDER BY n DESC"):
        print(f"  {r['vuln_class']:20} {r['n']}")
    print("\nBy year:")
    for r in c.execute("SELECT occurred_year, COUNT(*) n FROM attacks GROUP BY occurred_year ORDER BY occurred_year"):
        print(f"  {r['occurred_year']}  {r['n']}")
    rep = c.execute("SELECT COUNT(*) FROM attacks WHERE block_number IS NOT NULL").fetchone()[0]
    ms  = c.execute("SELECT COUNT(*) FROM attacks WHERE multi_stage=1").fetchone()[0]
    loss= c.execute("SELECT SUM(loss_usd) FROM attacks").fetchone()[0] or 0
    print(f"\nReplayable (have fork block): {rep}/{total}")
    print(f"Multi-stage flagged:          {ms}/{total}")
    print(f"Sum of parsed losses:         ${loss/1e9:.2f}B")
    con.close()

if __name__ == "__main__":
    if len(sys.argv) < 2: print(__doc__); sys.exit(1)
    cmd = sys.argv[1]
    if cmd == "ingest": cmd_ingest(sys.argv[2] if len(sys.argv) > 2 else "all")
    elif cmd == "stats": cmd_stats()
    else: print("unknown:", cmd); print(__doc__)
