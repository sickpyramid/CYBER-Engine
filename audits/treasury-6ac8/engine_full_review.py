"""Run CYBER-Engine's real mechanism and retrieval modules on the verified source.

This is candidate generation, never exploit proof. The corpus remains the engine's
existing data/corpus.sqlite; no historic attack is replayed by this script.
"""
from __future__ import annotations
import json
import sys
from pathlib import Path

AUDIT = Path(__file__).resolve().parent
REPO = AUDIT.parents[1]
sys.path.insert(0, str(REPO))
from engine import db, mechanism, retrieval

manifest = json.loads((AUDIT / "source-manifest.json").read_text())
keys = [r["path"] for r in manifest["records"]]
source_root = AUDIT / "verified"
mech = mechanism.analyze(
    str(source_root), keys, "0.8.26",
    ["@openzeppelin/contracts/=lib/openzeppelin-contracts/contracts/"],
)
con = db.connect()
total = con.execute("SELECT COUNT(*) FROM attacks").fetchone()[0]
counts = {r[0]: r[1] for r in con.execute(
    "SELECT vuln_class, COUNT(*) FROM attacks GROUP BY vuln_class"
)}
classes = list(dict.fromkeys(mech.get("predicted_classes", [])))
for category in ("reentrancy", "logic_accounting"):
    if category not in classes:
        classes.append(category)
matches = retrieval.retrieve(
    con, classes, archetypes=mech.get("archetypes", []), chain="ethereum", k=20,
)
results = []
for match in matches:
    row = con.execute(
        "SELECT source,source_ref,refs,summary FROM attacks WHERE uid=?",
        (match["uid"],),
    ).fetchone()
    results.append({
        **{k: v for k, v in match.items() if k != "poc_code"},
        "source": row["source"], "source_ref": row["source_ref"],
        "refs": json.loads(row["refs"] or "[]"),
        "summary": row["summary"],
    })
output = {
    "target": manifest["target"], "engine": "original mechanism.analyze + retrieval.retrieve",
    "corpus_total": total, "corpus_classes": counts,
    "mechanism": mech, "retrieval_classes": classes,
    "matches": results, "replayed": False, "profit_proven": False,
}
(AUDIT / "engine-full-results.json").write_text(json.dumps(output, indent=2, default=str))
print(json.dumps({
    "corpus_total": total, "corpus_classes": counts,
    "archetypes": mech.get("archetypes"),
    "predicted_classes": mech.get("predicted_classes"),
    "model_summary": mech.get("model_summary"),
    "top_hypotheses": mech.get("hypotheses", [])[:6],
    "top_matches": [{k: v for k, v in m.items() if k not in ("summary", "refs")}
                    for m in results[:10]],
}, indent=2, default=str))
