"""The creative loop — the relentless adversary.

held-out contract -> mechanism model -> retrieve similar historical attacks
   -> LLM synthesizes a Foundry PoC -> prover runs it on the fork
      -> drained? PROVEN. failed? feed the forge error back, refine, retry.

Run:
  python engine/creative_loop.py <chain> <address> [block] [attempts]
Needs: .env archive RPCs (prover), ANTHROPIC_API_KEY (synthesizer), forge on PATH.

This is the acceptance test automated: unseen contract in, proven exploit (or an honest
"not found after N attempts") out. Every proven PoC is a validated attack trace — the
training signal for self-play / the Qwen fine-tune later.
"""
from __future__ import annotations
import sys, json, tempfile, time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from engine import db, fetch_source, mechanism, retrieval, synthesize, prover

REPO = ROOT / "vendor" / "DeFiHackLabs"
GEN_DIR = REPO / "src" / "test" / "_generated"
CHAIN_ALIAS = {"ethereum": "mainnet", "bsc": "bsc", "polygon": "polygon",
               "arbitrum": "arbitrum", "optimism": "optimism", "base": "base"}


def _lookup_block(con, chain, address):
    r = con.execute("SELECT block_number FROM attacks WHERE chain=? AND lower(victim_addrs) LIKE ?",
                    (chain, f'%{address.lower()}%')).fetchone()
    return r["block_number"] if r and r["block_number"] else None


def run(chain, address, block=None, attempts=3, k=4, verbose=True):
    con = db.connect()
    block = block or _lookup_block(con, chain, address)
    alias = CHAIN_ALIAS.get(chain, chain)
    tmp = tempfile.mkdtemp(prefix="cyber_target_")
    meta = fetch_source.fetch(chain, address, tmp)
    if not meta or not meta.get("source_keys"):
        return {"ok": False, "reason": "unverified source", "chain": chain, "address": address}

    # 1) understand the mechanism
    mech = mechanism.analyze(meta["src_root"], meta["source_keys"], meta.get("solc"),
                             meta.get("remappings"))
    hyps = mech.get("hypotheses", [])
    if verbose:
        print(f"[mechanism] archetypes={mech.get('archetypes')} "
              f"predicted={mech.get('predicted_classes')[:3]} hypotheses={len(hyps)}")
    if not hyps:
        return {"ok": True, "proven": False, "reason": "no attack hypothesis", "mechanism": mech}

    # 2) retrieve similar historical attacks (building blocks)
    examples = retrieval.retrieve_for_target(con, mech, chain=chain, k=k)
    if verbose:
        print(f"[retrieval] {[e['name'] for e in examples]}")

    # concat source for the synthesizer
    src_text = ""
    for key in meta["source_keys"]:
        p = Path(meta["src_root"]) / key
        if p.exists():
            src_text += f"// FILE {key}\n" + p.read_text(errors="replace") + "\n"
    target = {"chain": chain, "alias": alias, "block": block, "address": address,
              "archetypes": mech.get("archetypes"), "source": src_text}

    # 3) synthesize -> prove -> refine loop
    GEN_DIR.mkdir(parents=True, exist_ok=True)
    top_hyp = hyps[0]
    hyp_text = json.dumps(top_hyp, indent=1)
    prior_error = None
    for i in range(1, attempts + 1):
        if verbose:
            print(f"[attempt {i}/{attempts}] synthesizing PoC for '{top_hyp['vuln_class']}' ...")
        try:
            poc = synthesize.synthesize(target, hyp_text, examples, prior_error)
        except RuntimeError as e:
            return {"ok": False, "reason": str(e), "mechanism": mech, "examples": [e['name'] for e in examples]}
        poc_path = GEN_DIR / f"Gen_{address[:8]}_{i}.sol"
        poc_path.write_text(poc)
        rel = poc_path.relative_to(REPO).as_posix()
        res = prover.prove(rel, REPO, timeout=300)
        if verbose:
            print(f"[attempt {i}] proven={res.get('proven')} err={res.get('error')} "
                  f"profit={res.get('profit_logs')}")
        if res.get("proven"):
            return {"ok": True, "proven": True, "attempts": i, "vuln_class": top_hyp["vuln_class"],
                    "attack_path": top_hyp.get("attack_path"), "profit": res.get("profit_logs"),
                    "poc_path": str(poc_path), "address": address, "chain": chain}
        prior_error = "\n".join(res.get("tail") or []) or res.get("error")

    return {"ok": True, "proven": False, "attempts": attempts, "address": address,
            "vuln_class": top_hyp["vuln_class"], "last_error": prior_error}


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print(__doc__); sys.exit(1)
    chain, address = sys.argv[1], sys.argv[2]
    block = int(sys.argv[3]) if len(sys.argv) > 3 else None
    attempts = int(sys.argv[4]) if len(sys.argv) > 4 else 3
    t0 = time.time()
    out = run(chain, address, block, attempts)
    out["elapsed_s"] = round(time.time() - t0, 1)
    print(json.dumps(out, indent=1, default=str))
