"""Audited-exploit heuristics — detectors distilled from 10 real drains of AUDITED protocols.

The knowledge base is engine/knowledge/audited_exploits.md (10 case studies + 20 FLAG rules).
Most of those 20 rules are reasoning tasks for the synthesizing agent. This module mechanizes
the subset that is reliably grep-able on verified source, so the engine auto-raises them before
the human/LLM even reads the code. Each detector cites the rule number and the cases behind it.

The recurring lesson across all 10: the drain lived on a TRUST BOUNDARY the audit assumed safe —
an external price feed, a vault share price, a token's transfer semantics, a registered market,
a ported library, an off-chain keeper. These detectors look for exactly those boundaries.
"""
from __future__ import annotations
import re
from pathlib import Path

# ── rule patterns ────────────────────────────────────────────────────────────

# #2 spot/AMM-reserve price with no TWAP (Harvest, Cream, UwU)
RE_SPOT_PRICE = re.compile(r"getReserves\(\)|get_virtual_price|getVirtualPrice|"
                           r"\.price0CumulativeLast|reserve0\b.*reserve1\b|balanceOf\([^)]*\)\s*\*\s*\w*price", re.I)
RE_TWAP = re.compile(r"twap|timeWeighted|cumulativePrice|observe\(|consult\(", re.I)

# #3 donatable share-price oracle (Cream; ERC4626 first-depositor family)
RE_SHARE_PRICE = re.compile(r"pricePerShare|getPricePerFullShare|convertToAssets|"
                            r"totalAssets\(\)\s*[*/]\s*totalSupply|totalSupply\(\)\s*[*/]\s*totalAssets", re.I)
RE_VIRTUAL_SHARE = re.compile(r"virtual[_ ]?shares|_decimalsOffset|DEAD_SHARES|MINIMUM_LIQUIDITY|1000\s*\*\s*", re.I)

# #6 keeper/pusher price (UwU-class, keeper family) + whether a bound exists
RE_KEEPER_PUSH = re.compile(r"pushPrice|setPrice|updatePrice|keeperPush|reportPrice|"
                            r"onlyKeeper|onlyUpdater|onlyReporter|pricePusher", re.I)
RE_PRICE_BOUND = re.compile(r"circuitBreaker|deviation|maxDeviation|staleness|maxPriceAge|"
                            r"heartbeat|clamp|minPrice|maxPrice|anchor", re.I)

# #8 incomplete reentrancy coverage (Rari/Fei exitMarket, Penpie harvest)
RE_STATE_EXT_FN = re.compile(r"function\s+(\w+)\s*\([^)]*\)\s*(external|public)([^{;]*)\{", re.S)
RE_NONREENTRANT = re.compile(r"nonReentrant", re.I)

# #10 hook-capable asset on a plain-ERC20 fork (Hundred, Agave)
RE_HOOK_TOKEN = re.compile(r"onTokenTransfer|tokensReceived|callAfterTransfer|ERC777|ERC677|_afterTokenTransfer", re.I)

# #12 permissionless registration of a called-back object (Penpie)
RE_PERMISSIONLESS_REG = re.compile(r"function\s+(register|addMarket|addPool|createMarket|listToken|addToken)\w*\s*\([^)]*\)\s*(external|public)(?![^{;]*only)", re.I)

# #13 balance-delta accounting around an external call (Penpie)
RE_BALANCE_DELTA = re.compile(r"balanceAfter\s*-\s*balanceBefore|after\s*-\s*before|"
                              r"balanceOf\([^)]*\)\s*-\s*\w*[Bb]efore", re.I)


def _blob(src_root: str, keys: list[str]) -> str:
    root = Path(src_root); out = []
    for k in (keys or []):
        p = root / k
        if p.exists() and "openzeppelin" not in k.lower() and "/npm/" not in k.lower():
            try: out.append(p.read_text(errors="ignore"))
            except Exception: pass
    if not out:
        for p in root.rglob("*.sol"):
            if "openzeppelin" in str(p).lower(): continue
            try: out.append(p.read_text(errors="ignore"))
            except Exception: pass
    return "\n".join(out)


def scan(src_root: str, source_keys: list[str]) -> list[dict]:
    """Run the mechanizable audited-exploit heuristics over verified source."""
    src = _blob(src_root, source_keys)
    hits = []

    if RE_SPOT_PRICE.search(src) and not RE_TWAP.search(src):
        hits.append({"rule": 2, "severity": "high", "cases": "Harvest/Cream/UwU",
            "flag": "price read from instantaneous AMM reserves / virtual_price with NO TWAP "
                    "-> flash-loan oracle manipulation"})

    if RE_SHARE_PRICE.search(src) and not RE_VIRTUAL_SHARE.search(src):
        hits.append({"rule": 3, "severity": "high", "cases": "Cream/ERC4626",
            "flag": "collateral/share priced from totalAssets/totalSupply or pricePerShare with NO "
                    "virtual-share/dead-share guard -> donation share-inflation"})

    if RE_KEEPER_PUSH.search(src):
        bounded = bool(RE_PRICE_BOUND.search(src))
        hits.append({"rule": 6, "severity": "high" if not bounded else "medium",
            "cases": "UwU/Mango/keeper-family",
            "flag": ("off-chain keeper/pusher sets price with NO on-chain bound "
                     "(no deviation/staleness/clamp) -> keeper key compromise sets collateral price, "
                     "borrow the reserve dry") if not bounded else
                    ("off-chain keeper/pusher sets price; a bound EXISTS (deviation/staleness) -> verify "
                     "the bound is TIGHTER than the asset's real volatility x LTV, else a key compromise "
                     "still walks the price across windows to a drain (Poppie-pattern)")})

    # #8 incomplete reentrancy coverage
    fns = RE_STATE_EXT_FN.findall(src)
    if RE_NONREENTRANT.search(src) and fns:
        # functions whose header lacks nonReentrant but mutate (heuristic: non-view)
        guarded = len(re.findall(r"nonReentrant", src))
        total_ext = len(fns)
        unguarded = [n for (n, vis, mods) in fns if "nonReentrant" not in mods and "view" not in mods
                     and "pure" not in mods]
        if guarded and unguarded and len(unguarded) > guarded:
            hits.append({"rule": 8, "severity": "medium", "cases": "Rari-Fei/Penpie",
                "flag": f"nonReentrant used on some paths but {len(unguarded)} external state-mutating "
                        f"fns lack it (e.g. {unguarded[:5]}) -> cross-function reentrancy"})

    if RE_HOOK_TOKEN.search(src):
        hits.append({"rule": 10, "severity": "medium", "cases": "Hundred/Agave",
            "flag": "token-transfer hook semantics present/assumed -> if a fork of a plain-ERC20 "
                    "template, callback tokens enable transfer-callback reentrancy"})

    if RE_PERMISSIONLESS_REG.search(src):
        hits.append({"rule": 12, "severity": "high", "cases": "Penpie",
            "flag": "permissionless register/addMarket/addPool of an object the protocol later CALLS INTO "
                    "-> malicious-market injection + reentrancy"})

    if RE_BALANCE_DELTA.search(src):
        hits.append({"rule": 13, "severity": "medium", "cases": "Penpie",
            "flag": "reward/share credited as balanceAfter-balanceBefore around an external call "
                    "-> reentrant inflation of the measured delta if the call reaches attacker code"})

    return hits
