#!/usr/bin/env python3
"""CyberAgent engine CLI.  Usage:
    python cli.py hunt <chain> <address> [block]  # SKILL entrypoint: brief for an agent to write+prove a PoC
    python cli.py prove <workdir|poc.sol>         # run the agent's PoC on a mainnet fork -> proven?
    python cli.py system <chain> <addr> <addr>... [--check <var>]  # cross-contract value-flow / escalation
    python cli.py detect <chain> <address>        # static (Slither) findings only
    python cli.py scoreboard [N]                  # held-out rediscovery eval over N corpus cases
    python cli.py ingest defihacklabs             # (re)build data/corpus.sqlite from DeFiHackLabs
    python cli.py stats                           # corpus summary

hunt + prove need no LLM key — the driving agent is the synthesizer. See SKILL.md.
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

def cmd_detect(chain, address):
    """Fetch a held-out target's verified source and run the detection substrate."""
    import tempfile
    from engine import fetch_source, detect
    with tempfile.TemporaryDirectory() as tmp:
        meta = fetch_source.fetch(chain, address, tmp)
        if not meta:
            print("no verified source on Sourcify for", chain, address); return
        print(f"target: {meta['contract']}  files={meta['n_files']}  solc={meta['solc']}")
        res = detect.analyze(meta["src_root"], meta["source_keys"], meta.get("solc"))
        print("predicted classes:", res.get("predicted_classes"))
        for f in res.get("findings", [])[:12]:
            if f["slug"] != "other":
                print(f"  [{f['impact']:13}] {f['slug']:18} {f['check']:22} {f['where'][:1]}")

def cmd_scoreboard(n):
    from training import eval_holdout
    eval_holdout.evaluate(limit=int(n) if n else None)

CHAIN_ALIAS = {"ethereum": "mainnet", "bsc": "bsc", "polygon": "polygon",
               "arbitrum": "arbitrum", "optimism": "optimism", "base": "base"}

def cmd_hunt(chain, address, block=None):
    """Skill entrypoint: prep everything an agent needs to write + prove a PoC.
    No LLM key needed — the DRIVING agent is the synthesizer."""
    from engine import fetch_source, mechanism, retrieval
    con = db.connect()
    if block is None:
        r = con.execute("SELECT block_number FROM attacks WHERE chain=? AND lower(victim_addrs) LIKE ?",
                        (chain, f'%{address.lower()}%')).fetchone()
        block = r["block_number"] if r and r["block_number"] else None
    work = HERE / "data" / "workdir" / f"{chain}_{address[:10]}"
    (work / "examples").mkdir(parents=True, exist_ok=True)
    meta = fetch_source.fetch(chain, address, str(work))
    if not meta or not meta.get("source_keys"):
        print(json.dumps({"ok": False, "reason": "no verified source on Sourcify"})); return
    src = ""
    for k in meta["source_keys"]:
        p = Path(meta["src_root"]) / k
        if p.exists(): src += f"\n// ===== FILE: {k} =====\n" + p.read_text(errors="replace")
    (work / "SOURCE.sol").write_text(src)
    mech = mechanism.analyze(meta["src_root"], meta["source_keys"], meta.get("solc"), meta.get("remappings"))
    ex = retrieval.retrieve_for_target(con, mech, chain=chain, k=4)
    ex_paths = []
    for e in ex:
        ep = work / "examples" / f"{e['name'][:30].replace('/','_')}.sol"
        ep.write_text(f"// {e['name']} | {e['vuln_class']} | {e['chain']} | block {e['block_number']}\n" + e["poc_code"])
        ex_paths.append(str(ep))
    brief = {
        "target": {"chain": chain, "address": address, "fork_alias": CHAIN_ALIAS.get(chain, chain),
                   "block": block, "contract": meta["contract"], "solc": meta["solc"]},
        "mechanism": {"archetypes": mech.get("archetypes"),
                      "predicted_classes": mech.get("predicted_classes"),
                      "top_hypotheses": mech.get("hypotheses", [])[:3]},
        "source_file": str(work / "SOURCE.sol"),
        "example_pocs": ex_paths,
        "write_poc_to": str(work / "attempt.sol"),
        "then_run": f"python cli.py prove {work}",
    }
    (work / "brief.json").write_text(json.dumps(brief, indent=1))
    print(json.dumps(brief, indent=1))

def cmd_system(args):
    """Cross-contract value-flow analysis across a protocol's contracts.
    Usage: system <chain> <addr1> <addr2> ...  [--check <variable>]
    Answers: does a finding on a value escalate downstream, or stay low-sev?"""
    from engine import system
    chain = args[0]
    check = None
    addrs = args[1:]
    if "--check" in addrs:
        i = addrs.index("--check"); check = addrs[i + 1]; addrs = addrs[:i]
    labels = {f"c{i}_{a[:6]}": a for i, a in enumerate(addrs)}
    res = system.analyze_system(labels, chain)
    print(res["summary"])
    print("\nCross-contract VALUE flows (escalation surfaces):")
    for f in res["value_flows"][:20]:
        print(f"  {res['contracts'].get(f['producer'],f['producer'])}.{f['getter']}() -> "
              f"{[res['contracts'].get(c,c) for c in f['consumers']]}")
    if check:
        print("\n--- escalation check:", check, "---")
        print(json.dumps(system.check_variable(res, check), indent=1, default=str))

def cmd_prove(path):
    """Prove the agent-written PoC on a mainnet fork. `path` = the attempt.sol or its workdir."""
    import shutil
    from engine import prover
    p = Path(path)
    poc = p / "attempt.sol" if p.is_dir() else p
    if not poc.exists():
        print(json.dumps({"ok": False, "reason": f"no PoC at {poc}"})); return
    gen = VENDOR / "DeFiHackLabs" / "src" / "test" / "_generated"
    gen.mkdir(parents=True, exist_ok=True)
    dst = gen / f"Attempt_{poc.parent.name}.sol"
    shutil.copy2(poc, dst)
    res = prover.prove(dst.relative_to(VENDOR / "DeFiHackLabs").as_posix(), VENDOR / "DeFiHackLabs")
    print(json.dumps(res, indent=1))

if __name__ == "__main__":
    if len(sys.argv) < 2: print(__doc__); sys.exit(1)
    cmd = sys.argv[1]
    if cmd == "ingest": cmd_ingest(sys.argv[2] if len(sys.argv) > 2 else "all")
    elif cmd == "stats": cmd_stats()
    elif cmd == "detect": cmd_detect(sys.argv[2], sys.argv[3])
    elif cmd == "scoreboard": cmd_scoreboard(sys.argv[2] if len(sys.argv) > 2 else None)
    elif cmd == "hunt": cmd_hunt(sys.argv[2], sys.argv[3], int(sys.argv[4]) if len(sys.argv) > 4 else None)
    elif cmd == "prove": cmd_prove(sys.argv[2])
    elif cmd == "system": cmd_system(sys.argv[2:])
    else: print("unknown:", cmd); print(__doc__)
