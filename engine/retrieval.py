"""Retrieval over the historical-attack corpus (the RAG layer).

Given a target's predicted vuln class(es) + archetype, pull the most similar prior
attacks — their reproduced PoCs are the building blocks the synthesizer adapts and
COMBINES. This is how the engine reuses 920 historical attacks instead of starting cold.

Lightweight by design (no embeddings server needed): class/chain filter + token overlap.
Swap in sentence-transformers later for semantic ranking; the interface stays the same.
"""
from __future__ import annotations
import re, json
from collections import Counter
from . import db

_TOKEN = re.compile(r"[a-zA-Z_][a-zA-Z0-9_]{3,}")
# generic solidity/boilerplate tokens that shouldn't drive similarity
_STOP = {"function", "address", "uint256", "memory", "public", "external", "returns",
         "require", "import", "pragma", "contract", "interface", "return", "storage",
         "internal", "bytes", "bool", "emit", "event", "mapping", "struct", "msg",
         "sender", "value", "this", "address(this)", "console", "vm", "test", "exploit",
         "forge", "std", "IERC20", "balanceOf", "approve", "transfer"}


def _tokens(code: str) -> Counter:
    toks = [t.lower() for t in _TOKEN.findall(code or "") if t not in _STOP]
    return Counter(toks)


def retrieve(con, vuln_classes, archetypes=None, chain=None, k=4, exclude_uid=None):
    """Return up to k similar historical attacks (dicts with poc_code) ranked by similarity."""
    archetypes = archetypes or []
    classes = list(vuln_classes) or ["other"]
    q = """SELECT uid,name,chain,vuln_class,multi_stage,poc_code,attack_txs,block_number,refs
           FROM attacks WHERE vuln_class IN ({}) AND poc_code IS NOT NULL
        """.format(",".join("?" * len(classes)))
    rows = con.execute(q, classes).fetchall()
    arch_terms = {a.lower() for a in archetypes}
    scored = []
    for r in rows:
        if exclude_uid and r["uid"] == exclude_uid:
            continue
        score = 2.0  # base: same vuln class
        if chain and r["chain"] == chain:
            score += 1.0
        code_l = (r["poc_code"] or "").lower()
        score += sum(1.0 for a in arch_terms if a in code_l)
        if r["multi_stage"]:
            score += 0.3
        scored.append((score, r))
    scored.sort(key=lambda x: x[0], reverse=True)
    out = []
    for score, r in scored[:k]:
        out.append({"uid": r["uid"], "name": r["name"], "chain": r["chain"],
                    "vuln_class": r["vuln_class"], "multi_stage": bool(r["multi_stage"]),
                    "score": round(score, 2), "poc_code": r["poc_code"],
                    "attack_txs": json.loads(r["attack_txs"] or "[]"),
                    "block_number": r["block_number"]})
    return out


def retrieve_for_target(con, mechanism_result, chain=None, k=4):
    """Convenience: feed a mechanism.analyze() result straight in."""
    return retrieve(con,
                    mechanism_result.get("predicted_classes", []),
                    mechanism_result.get("archetypes", []),
                    chain=chain, k=k)
