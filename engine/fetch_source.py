"""Fetch a held-out target's exact verified compiler input — keyless via Sourcify.

Returns the standard-json sources + solc version so the detector can compile the
victim *exactly as deployed* (multi-file, OpenZeppelin imports and all).
"""
from __future__ import annotations
import json, urllib.request, urllib.error
from pathlib import Path

CHAIN_IDS = {
    "ethereum": 1, "bsc": 56, "polygon": 137, "gnosis": 100, "base": 8453,
    "avalanche": 43114, "arbitrum": 42161, "optimism": 10, "fantom": 250,
    "celo": 42220, "moonriver": 1285, "linea": 59144, "scroll": 534352,
    "blast": 81457, "zksync": 324, "cronos": 25,
}


def fetch(chain: str, address: str, out_dir: str | Path) -> dict | None:
    cid = CHAIN_IDS.get(chain)
    if not cid:
        return None
    url = (f"https://sourcify.dev/server/v2/contract/{cid}/{address}"
           "?fields=stdJsonInput,compilation,metadata")
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "cyber-engine"})
        with urllib.request.urlopen(req, timeout=30) as r:
            d = json.load(r)
    except (urllib.error.HTTPError, Exception):
        return None

    sj = d.get("stdJsonInput") or {}
    sources = sj.get("sources") or {}
    if not sources:
        return None

    src_root = Path(out_dir) / "src"
    src_root.mkdir(parents=True, exist_ok=True)
    keys = []
    for path, obj in sources.items():
        safe = path.replace("..", "").lstrip("/")
        full = src_root / safe
        full.parent.mkdir(parents=True, exist_ok=True)
        full.write_text(obj.get("content", ""))
        keys.append(safe)

    comp = d.get("compilation", {})
    solc = (comp.get("compilerVersion") or "").split("+")[0] or None
    md = d.get("metadata", {}) or {}
    target = None
    ct = (md.get("settings", {}) or {}).get("compilationTarget", {})
    if ct:
        target = list(ct.keys())[0]
    return {"src_root": str(src_root), "source_keys": keys, "solc": solc,
            "contract": comp.get("name"), "target": target,
            "n_files": len(keys), "chain": chain, "address": address}
