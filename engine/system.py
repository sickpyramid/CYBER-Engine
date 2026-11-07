"""System-level (multi-contract) value-flow analysis — the multi-stage upgrade.

A single-contract audit can't tell a low-sev accounting bug from a high-sev one. The
difference is whether the value is CONSUMED DOWNSTREAM: if contract A's getter feeds a
mint / price / reward / backing computation in contract B, a bug in A escalates.

Given a set of protocol addresses, this:
  1. fetches every contract's source
  2. extracts each contract's exposed getters (public vars + view fns) and the external
     calls it makes
  3. cross-links them by name (B calls `.g(` and A defines `g` -> A.g feeds B)
  4. flags value-bearing getters consumed cross-contract -> escalation hypotheses

Heuristic (name-based) by design — no on-chain address resolution needed to see the flow.
"""
from __future__ import annotations
import re, json, tempfile
from pathlib import Path
from . import fetch_source

# getter names that carry VALUE (feed minting/pricing/backing/rewards) vs mere telemetry
VALUE_TERMS = re.compile(
    r"price|value|backing|reserve|collateral|rate|earn|mint|reward|share|asset|"
    r"convertto|totalassets|latestanswer|latestvalue|exchangerate|peg|debt|ceiling|"
    r"redeem|redemption|backed|solvency|ratio|haircut|quote", re.I)
TELEMETRY_TERMS = re.compile(r"received|count|length|nonce|timestamp|lastsync|version|name|symbol|decimals", re.I)

RE_PUBLIC_VAR = re.compile(r"\b(?:uint\d*|int\d*|address|bool|bytes\d*)\s+public\s+(?:constant\s+|immutable\s+)?(\w+)")
RE_PUBLIC_MAP = re.compile(r"\bmapping\s*\([^)]*\)\s*(?:public)\s+(\w+)")
RE_VIEW_FN = re.compile(r"function\s+(\w+)\s*\([^)]*\)\s*(?:public|external)[^{;]*\b(?:view|pure)\b")
RE_EXT_CALL = re.compile(r"\.(\w+)\s*\(")


def _getters(code: str) -> set[str]:
    g = set()
    g |= set(RE_PUBLIC_VAR.findall(code))
    g |= set(RE_PUBLIC_MAP.findall(code))
    g |= set(RE_VIEW_FN.findall(code))
    return {x for x in g if len(x) > 2}


def _ext_calls(code: str) -> set[str]:
    return {m.group(1) for m in RE_EXT_CALL.finditer(code)}


def classify(name: str) -> str:
    if TELEMETRY_TERMS.search(name) and not VALUE_TERMS.search(name):
        return "telemetry"
    return "value" if VALUE_TERMS.search(name) else "neutral"


def analyze_system(addresses: dict[str, str], chain: str = "ethereum") -> dict:
    """addresses: {label: 0x..}. Returns the cross-contract value-flow map + escalations."""
    contracts = {}
    with tempfile.TemporaryDirectory() as tmp:
        for label, addr in addresses.items():
            meta = fetch_source.fetch(chain, addr, f"{tmp}/{label}")
            if not meta or not meta.get("source_keys"):
                contracts[label] = {"address": addr, "verified": False}
                continue
            code = ""
            for k in meta["source_keys"]:
                p = Path(meta["src_root"]) / k
                if p.exists():
                    code += p.read_text(errors="replace") + "\n"
            contracts[label] = {"address": addr, "verified": True, "name": meta["contract"],
                                "getters": _getters(code), "calls": _ext_calls(code)}

    # cross-link: getter g exposed by A is consumed by B if B calls .g( and B != A
    flows = []
    for a_label, a in contracts.items():
        if not a.get("verified"):
            continue
        for g in a["getters"]:
            consumers = [b_label for b_label, b in contracts.items()
                         if b.get("verified") and b_label != a_label and g in b["calls"]]
            if consumers:
                flows.append({"producer": a_label, "getter": g, "kind": classify(g),
                              "consumers": consumers})

    escalations = [f for f in flows if f["kind"] == "value"]
    escalations.sort(key=lambda f: len(f["consumers"]), reverse=True)
    return {"chain": chain,
            "contracts": {k: (v.get("name") if v.get("verified") else "UNVERIFIED")
                          for k, v in contracts.items()},
            "value_flows": escalations,
            "telemetry_only": sorted({f["getter"] for f in flows if f["kind"] == "telemetry"}),
            "summary": f"{len(escalations)} cross-contract VALUE flows (escalation surfaces), "
                       f"{len([f for f in flows if f['kind']=='telemetry'])} telemetry-only"}


def check_variable(system_result: dict, var: str) -> dict:
    """Danial's exact question: does <var> escalate cross-contract, or is it low-sev?"""
    v = var.lower()
    hits = [f for f in system_result["value_flows"] if v in f["getter"].lower()]
    if hits:
        return {"variable": var, "verdict": "ESCALATES",
                "why": f"consumed as VALUE by {sum(len(h['consumers']) for h in hits)} downstream reads",
                "flows": hits}
    tele = [g for g in system_result["telemetry_only"] if v in g.lower()]
    return {"variable": var,
            "verdict": "low-sev (telemetry)" if tele else "not consumed cross-contract",
            "why": "no downstream contract reads it for value/mint/price/reward"}
