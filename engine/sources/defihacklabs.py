"""Ingest the DeFiHackLabs corpus (944+ reproduced historical exploits) into the DB.

Each PoC lives at vendor/DeFiHackLabs/src/test/YYYY-MM/<Name>_exp.sol and carries a
header comment with KeyInfo (loss, attacker, victim, attack tx) plus a Foundry
`createSelectFork(chain, block)` that tells us exactly how to replay it.
"""
from __future__ import annotations
import re, json
from pathlib import Path
from .. import db

SCANNER_CHAIN = {
    "etherscan.io": "ethereum", "bscscan.com": "bsc", "polygonscan.com": "polygon",
    "arbiscan.io": "arbitrum", "optimistic.etherscan.io": "optimism",
    "snowtrace.io": "avalanche", "ftmscan.com": "fantom", "basescan.org": "base",
    "cronoscan.com": "cronos", "gnosisscan.io": "gnosis", "celoscan.io": "celo",
    "moonriver.moonscan.io": "moonriver", "era.zksync.network": "zksync",
    "lineascan.build": "linea", "scrollscan.com": "scroll", "blastscan.io": "blast",
}
FORK_ALIAS_CHAIN = {
    "mainnet": "ethereum", "eth": "ethereum", "ethereum": "ethereum", "bsc": "bsc",
    "bnb": "bsc", "polygon": "polygon", "matic": "polygon", "arbitrum": "arbitrum",
    "arb": "arbitrum", "optimism": "optimism", "avalanche": "avalanche", "avax": "avalanche",
    "fantom": "fantom", "ftm": "fantom", "base": "base", "gnosis": "gnosis",
    "zksync": "zksync", "linea": "linea", "scroll": "scroll", "blast": "blast", "celo": "celo",
}

RE_TX     = re.compile(r"https?://([a-z0-9.\-]+)/tx/(0x[0-9a-fA-F]{64})")
RE_ADDR   = re.compile(r"0x[0-9a-fA-F]{40}")
RE_LOSS   = re.compile(r"Total\s*(?:Value\s*)?Lost\s*:?\s*~?\s*\$?\s*([0-9][0-9.,]*)\s*([kKmMbB]?)")
# block numbers may use Solidity numeric separators: 16_000_000
RE_FORK      = re.compile(r"create(?:Select)?Fork\(\s*[\"']([^\"']+)[\"']\s*,\s*([\d_]+)\)")
RE_FORK_BLK  = re.compile(r"create(?:Select)?Fork\([^,)]*,\s*([\d_]+)\s*\)")      # block, any alias type
RE_FORK_STR  = re.compile(r"create(?:Select)?Fork\(\s*[\"']([^\"']+)[\"']")        # alias string only
RE_BLOCKVAR  = re.compile(r"(?:block[_ ]?number|blocknumber|blockNumber|forkBlock|BLOCK)\s*=\s*([\d_]+)", re.I)
RE_ROLL      = re.compile(r"rollFork\(\s*([\d_]+)\s*\)")

def _int(s):
    try: return int(str(s).replace("_", ""))
    except (TypeError, ValueError): return None
RE_ATTACKER = re.compile(r"Attacker\s*:?\s*(0x[0-9a-fA-F]{40})", re.I)
RE_VICTIM   = re.compile(r"(?:Vulnerable|Vuln|Victim)\s*Contract\s*:?\s*(0x[0-9a-fA-F]{40})", re.I)
RE_LINK   = re.compile(r"https?://[^\s\)\"']+")


def _loss_usd(num: str, suffix: str) -> float | None:
    try:
        v = float(num.replace(",", ""))
    except ValueError:
        return None
    return v * {"k": 1e3, "m": 1e6, "b": 1e9}.get(suffix.lower(), 1.0)


def _header(code: str) -> str:
    """Grab the leading comment block (everything before the first contract/library)."""
    m = re.search(r"\b(contract|library|interface)\s", code)
    return code[: m.start()] if m else code[:2000]


def parse_file(path: Path, repo_root: Path) -> dict | None:
    code = path.read_text(errors="replace")
    header = _header(code)

    # chain + replay block from the Foundry fork call (most reliable).
    chain, block = None, None
    mf = RE_FORK.search(code)
    if mf:                                        # alias string + inline block
        chain = FORK_ALIAS_CHAIN.get(mf.group(1).lower())
        block = _int(mf.group(2))
    if block is None:                             # block w/ non-string alias (a var)
        mb = RE_FORK_BLK.search(code)
        if mb:
            block = _int(mb.group(1))
    if chain is None:                             # alias string even if block was a var
        ms = RE_FORK_STR.search(code)
        if ms:
            chain = FORK_ALIAS_CHAIN.get(ms.group(1).lower())
    if block is None:                             # block held in a variable/const
        mv = RE_BLOCKVAR.search(code)
        if mv:
            block = _int(mv.group(1))
    if block is None:                             # last resort: rollFork
        mr = RE_ROLL.search(code)
        if mr:
            block = _int(mr.group(1))

    # tx hashes + chain fallback from scanner domain
    txs, tx_chains = [], []
    for dom, tx in RE_TX.findall(header + code[:4000]):
        txs.append(tx)
        if dom in SCANNER_CHAIN:
            tx_chains.append(SCANNER_CHAIN[dom])
    if not chain and tx_chains:
        chain = tx_chains[0]

    loss = None
    ml = RE_LOSS.search(header)
    if ml:
        loss = _loss_usd(ml.group(1), ml.group(2))
        if loss is not None and loss > 1e11:   # >$100B single loss == parse junk
            loss = None

    attacker = RE_ATTACKER.search(header)
    victim = RE_VICTIM.search(header)
    refs = [u.rstrip(".,") for u in RE_LINK.findall(header)][:12]

    name = path.stem.replace("_exp", "").replace("_", " ").strip()
    date = path.parent.name  # YYYY-MM
    year = int(date[:4]) if re.match(r"\d{4}", date) else None

    vuln_slug, vuln_raw = db.classify_attack(header, name, code)
    low = code.lower()
    multi = int(any(k in low for k in ("flashloan", "flash loan", "flashswap")) or
                len(set(txs)) > 1 or "reentran" in low)

    return {
        "source": "defihacklabs",
        "source_ref": str(path.relative_to(repo_root)),
        "uid": db.make_uid("defihacklabs", name, date),
        "name": name,
        "protocol": name,
        "chain": chain,
        "occurred_date": date,
        "occurred_year": year,
        "loss_usd": loss,
        "vuln_class": vuln_slug,
        "vuln_raw": vuln_raw,
        "attacker_addrs": [attacker.group(1)] if attacker else [],
        "victim_addrs": [victim.group(1)] if victim else [],
        "attack_txs": list(dict.fromkeys(txs)),
        "block_number": block,
        "refs": refs,
        "poc_lang": "solidity",
        "poc_code": code,
        "summary": None,
        "raw_header": header.strip()[:4000],
        "multi_stage": multi,
    }


def ingest(con, repo_root: Path) -> int:
    test_dir = repo_root / "src" / "test"
    added = 0
    files = [p for p in test_dir.rglob("*.sol")
             if re.match(r"\d{4}-\d{2}", p.parent.name)]  # only dated attack dirs
    for p in sorted(files):
        try:
            rec = parse_file(p, repo_root)
        except Exception as e:
            print("  parse error", p.name, e)
            continue
        if rec and db.upsert_attack(con, rec):
            added += 1
    con.commit()
    return added
