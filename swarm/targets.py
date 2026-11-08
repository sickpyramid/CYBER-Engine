"""Target acquisition — the swarm's eyes. Feeds a never-ending stream of contracts to hunt.

Priority: (1) anything the human queued in the UI, (2) Immunefi in-scope bounty targets,
(3) fresh low-TVL / recently-listed DeFi protocols from DefiLlama. The stream never ends while
the swarm runs; when sources are exhausted it waits for the manual queue or re-polls.

All network calls are best-effort: if a source is down we log and continue with the others.
"""
from __future__ import annotations
import asyncio, time, json
import httpx
from . import config

manual_queue: asyncio.Queue = asyncio.Queue()   # UI pushes {chain,address,name} here
_seen: set[str] = set()


def _key(t: dict) -> str:
    return f"{t.get('chain')}:{(t.get('address') or '').lower()}"


async def queue_target(chain: str, address: str, name: str = "manual"):
    await manual_queue.put({"chain": chain, "address": address, "name": name, "source": "manual"})


async def _defillama() -> list[dict]:
    """Recently-listed, sub-max-TVL protocols on the configured chains."""
    tc = config.TARGETS
    out = []
    try:
        async with httpx.AsyncClient(timeout=60, follow_redirects=True) as c:
            r = await c.get("https://api.llama.fi/protocols", headers={"User-Agent": "swarm"})
        now = time.time()
        chain_names = {"ethereum": "Ethereum", "eth": "Ethereum", "bsc": "BSC", "bnb": "BSC"}
        want = {chain_names.get(x.strip().lower()) for x in tc.chains}
        for p in r.json():
            la = p.get("listedAt") or 0
            tvl = p.get("tvl") or 0
            if not la or (now - la) / 86400 > tc.max_age_days:
                continue
            if not (tc.min_tvl < tvl < tc.max_tvl):
                continue
            chains = set(p.get("chains") or [])
            hit = want & chains
            if not hit:
                continue
            addr = p.get("address") or ""
            # DefiLlama addresses sometimes carry a "chain:0x.." prefix
            if ":" in addr:
                addr = addr.split(":")[-1]
            if not addr.startswith("0x"):
                continue
            chain = "ethereum" if "Ethereum" in hit else "bsc"
            out.append({"chain": chain, "address": addr,
                        "name": f"{p.get('name')} [{p.get('category')}]",
                        "source": "defillama", "tvl": int(tvl)})
    except Exception:
        pass
    return out


async def _immunefi() -> list[dict]:
    """Best-effort Immunefi in-scope smart-contract targets. Immunefi's public bounty list is
    JS-rendered; we try the known public JSON bundle and extract EVM addresses if reachable.
    If it fails, we return [] and rely on DefiLlama + manual."""
    if not config.TARGETS.use_immunefi:
        return []
    out = []
    try:
        async with httpx.AsyncClient(timeout=60, follow_redirects=True) as c:
            # public bounties index (unofficial; may change). Falls through quietly on failure.
            r = await c.get("https://immunefi.com/public-api/bounties/",
                            headers={"User-Agent": "swarm"})
            if r.status_code == 200:
                data = r.json()
                for b in (data if isinstance(data, list) else data.get("bounties", []))[:50]:
                    # scope assets with evm addresses
                    for a in (b.get("assets") or []):
                        url = (a.get("url") or "")
                        import re
                        m = re.search(r"0x[0-9a-fA-F]{40}", url)
                        if m:
                            chain = "bsc" if "bsc" in url.lower() or "bnb" in url.lower() else "ethereum"
                            out.append({"chain": chain, "address": m.group(0),
                                        "name": f"{b.get('project','?')} (Immunefi)",
                                        "source": "immunefi"})
    except Exception:
        pass
    return out


def make_stream(emit=None):
    """Return an async generator yielding de-duplicated targets forever."""
    async def gen():
        while True:
            # 1) drain the manual queue first (human priority)
            while not manual_queue.empty():
                t = await manual_queue.get()
                if _key(t) not in _seen:
                    _seen.add(_key(t)); yield t
            # 2) immunefi + defillama batch
            batch = []
            batch += await _immunefi()
            batch += await _defillama()
            fresh = [t for t in batch if _key(t) not in _seen]
            if emit:
                await emit({"type": "targets_fetched", "ts": time.time(),
                            "count": len(fresh), "sources": {"total": len(batch)}})
            for t in fresh:
                _seen.add(_key(t))
                yield t
            if not fresh:
                # nothing new — wait for a manual add or the next poll window
                try:
                    t = await asyncio.wait_for(manual_queue.get(), timeout=300)
                    if _key(t) not in _seen:
                        _seen.add(_key(t)); yield t
                except asyncio.TimeoutError:
                    pass
    return gen
