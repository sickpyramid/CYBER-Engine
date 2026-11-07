"""Detection substrate: compile a target's exact standard-json and run Slither.

Robust multi-file path: Slither's Python API + SolcStandardJson (compiles any
Sourcify target, incl. OpenZeppelin imports, on legacy solc without --base-path).
Runs as a subprocess per target in the eval harness for isolation.

Usage (subprocess):  python engine/detect.py <src_root> <solc_version> <keys.json>
  -> prints findings JSON to stdout
"""
from __future__ import annotations
import subprocess, json, os, sys, inspect
from pathlib import Path
from collections import defaultdict

SLITHER_TO_TAXONOMY = {
    "reentrancy-eth": "reentrancy", "reentrancy-no-eth": "reentrancy",
    "reentrancy-benign": "reentrancy", "reentrancy-events": "reentrancy",
    "reentrancy-unlimited-gas": "reentrancy", "writing-after-call": "reentrancy",
    "arbitrary-send-eth": "unchecked_external", "arbitrary-send-erc20": "unchecked_external",
    "arbitrary-send-erc20-permit": "signature_replay",
    "controlled-delegatecall": "unchecked_external", "delegatecall-loop": "unchecked_external",
    "unchecked-lowlevel": "unchecked_external", "unchecked-send": "unchecked_external",
    "unchecked-transfer": "logic_accounting", "erc20-interface": "logic_accounting",
    "suicidal": "access_control", "unprotected-upgrade": "proxy_upgrade",
    "uninitialized-state": "proxy_upgrade", "uninitialized-storage": "proxy_upgrade",
    "incorrect-equality": "logic_accounting", "divide-before-multiply": "arithmetic",
    "weak-prng": "other", "tautology": "logic_accounting", "boolean-cst": "logic_accounting",
    "controlled-array-length": "arithmetic", "tx-origin": "access_control",
    "incorrect-modifier": "access_control",
}
IMPACT_RANK = {"High": 3, "Medium": 2, "Low": 1, "Informational": 0, "Optimization": 0}
CONF_RANK = {"High": 3, "Medium": 2, "Low": 1, "": 0}


def _ensure_solc(version: str | None):
    if not version:
        return
    env = dict(os.environ, PATH=f"{Path.home()/'.local/bin'}:{os.environ.get('PATH','')}")
    subprocess.run(["solc-select", "use", version], capture_output=True, env=env, timeout=120)
    # install on demand if 'use' failed
    r = subprocess.run(["solc", "--version"], capture_output=True, env=env, timeout=30)
    if version.split(".")[1] not in r.stdout.decode(errors="replace"):
        subprocess.run(["solc-select", "install", version], capture_output=True, env=env, timeout=400)
        subprocess.run(["solc-select", "use", version], capture_output=True, env=env, timeout=120)


def analyze(src_root: str, source_keys: list[str], solc: str | None = None) -> dict:
    """Compile + detect. Returns ranked, taxonomy-mapped findings."""
    _ensure_solc(solc)
    from crytic_compile import CryticCompile
    from crytic_compile.platform.solc_standard_json import SolcStandardJson
    from slither import Slither
    from slither.detectors import all_detectors
    from slither.detectors.abstract_detector import AbstractDetector

    cwd = os.getcwd()
    try:
        os.chdir(src_root)
        std = SolcStandardJson()
        for k in source_keys:
            if Path(k).exists():
                std.add_source_file(k)
        sl = Slither(CryticCompile(std, solc="solc"))
        dcls = [getattr(all_detectors, n) for n in dir(all_detectors)
                if inspect.isclass(getattr(all_detectors, n))
                and issubclass(getattr(all_detectors, n), AbstractDetector)
                and getattr(all_detectors, n) is not AbstractDetector]
        for D in dcls:
            sl.register_detector(D)
        raw = [d for grp in sl.run_detectors() for d in grp]
    finally:
        os.chdir(cwd)

    findings, counts = [], defaultdict(int)
    for d in raw:
        check = d.get("check", "")
        slug = SLITHER_TO_TAXONOMY.get(check, "other")
        counts[slug] += 1
        where = []
        for el in d.get("elements", [])[:3]:
            ln = (el.get("source_mapping") or {}).get("lines", [])
            where.append(f"{el.get('name')}:{ln[0] if ln else '?'}")
        findings.append({
            "check": check, "slug": slug, "impact": d.get("impact", "Informational"),
            "confidence": d.get("confidence", ""), "where": where,
            "desc": (d.get("description") or "").strip().split("\n")[0][:200],
        })
    # rank by impact then confidence; "other" slugs sink below classified ones at equal impact
    findings.sort(key=lambda f: (IMPACT_RANK.get(f["impact"], 0),
                                 f["slug"] != "other",
                                 CONF_RANK.get(f["confidence"], 0)), reverse=True)
    ranked_classes = [s for s, _ in sorted(counts.items(), key=lambda x: -x[1]) if s != "other"]
    return {"ok": True, "n_findings": len(findings), "counts": dict(counts),
            "predicted_classes": ranked_classes, "findings": findings}


if __name__ == "__main__":
    src_root, solc, keys_file = sys.argv[1], (sys.argv[2] or None), sys.argv[3]
    keys = json.load(open(keys_file))
    try:
        print(json.dumps(analyze(src_root, keys, solc)))
    except Exception as e:
        print(json.dumps({"ok": False, "error": f"{type(e).__name__}: {e}", "findings": [], "predicted_classes": []}))
