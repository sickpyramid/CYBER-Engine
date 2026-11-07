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


def fetch_etherscan(chain: str, address: str, out_dir: str | Path) -> dict | None:
    """Fallback source fetch via Etherscan V2 API (one key, all chains). Needs ETHERSCAN_API_KEY.
    New contracts verify on Etherscan far more than on Sourcify, so this is the fresh-target path."""
    import os
    key = os.environ.get("ETHERSCAN_API_KEY")
    cid = CHAIN_IDS.get(chain)
    if not key or not cid:
        return None
    url = (f"https://api.etherscan.io/v2/api?chainid={cid}&module=contract&action=getsourcecode"
           f"&address={address}&apikey={key}")
    try:
        with urllib.request.urlopen(urllib.request.Request(url, headers={"User-Agent": "cyber-engine"}), timeout=30) as r:
            d = json.load(r)
    except Exception:
        return None
    if d.get("status") != "1" or not d.get("result"):
        return None
    res = d["result"][0]
    sc = (res.get("SourceCode") or "").strip()
    name = res.get("ContractName") or "Contract"
    solc = (res.get("CompilerVersion") or "").lstrip("v").split("+")[0] or None
    if not sc:
        return None
    sources, remappings = {}, []
    if sc.startswith("{{") and sc.endswith("}}"):
        obj = json.loads(sc[1:-1])                        # standard-json-input, double-brace wrapped
        sources = obj.get("sources", {})
        remappings = (obj.get("settings", {}) or {}).get("remappings", []) or []
    elif sc.startswith("{"):
        obj = json.loads(sc)
        sources = obj.get("sources", obj)                 # may be {language,sources,..} or a bare sources map
        remappings = (obj.get("settings", {}) or {}).get("remappings", []) or []
    else:
        sources = {f"{name}.sol": {"content": sc}}        # single flat file
    src_root = Path(out_dir) / "src"
    src_root.mkdir(parents=True, exist_ok=True)
    keys = []
    for path, v in sources.items():
        content = v.get("content", "") if isinstance(v, dict) else str(v)
        safe = path.replace("..", "").lstrip("/")
        full = src_root / safe
        full.parent.mkdir(parents=True, exist_ok=True)
        full.write_text(content)
        keys.append(safe)
    if not keys:
        return None
    return {"src_root": str(src_root), "source_keys": keys, "solc": solc,
            "remappings": remappings, "contract": name, "target": None,
            "n_files": len(keys), "chain": chain, "address": address, "via": "etherscan"}


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
        return fetch_etherscan(chain, address, out_dir)   # Sourcify down -> try Etherscan

    sj = d.get("stdJsonInput") or {}
    sources = sj.get("sources") or {}
    if not sources:
        return fetch_etherscan(chain, address, out_dir)   # not on Sourcify -> try Etherscan

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
    remappings = (sj.get("settings", {}) or {}).get("remappings", []) or []
    md = d.get("metadata", {}) or {}
    target = None
    ct = (md.get("settings", {}) or {}).get("compilationTarget", {})
    if ct:
        target = list(ct.keys())[0]
    return {"src_root": str(src_root), "source_keys": keys, "solc": solc,
            "remappings": remappings, "contract": comp.get("name"), "target": target,
            "n_files": len(keys), "chain": chain, "address": address}
