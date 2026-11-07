"""SQLite access layer + vulnerability taxonomy + lightweight classifier."""
from __future__ import annotations
import sqlite3, json, re, hashlib, datetime
from pathlib import Path

HERE = Path(__file__).resolve().parent
SCHEMA = HERE / "schema.sql"
DEFAULT_DB = HERE.parent / "data" / "corpus.sqlite"


def connect(db_path: str | Path = DEFAULT_DB) -> sqlite3.Connection:
    db_path = Path(db_path)
    db_path.parent.mkdir(parents=True, exist_ok=True)
    con = sqlite3.connect(db_path)
    con.row_factory = sqlite3.Row
    con.executescript(SCHEMA.read_text())
    seed_taxonomy(con)
    return con


def now() -> str:
    return datetime.datetime.utcnow().isoformat(timespec="seconds") + "Z"


def make_uid(source: str, name: str, date: str) -> str:
    key = f"{source}|{re.sub(r'[^a-z0-9]', '', (name or '').lower())}|{date or ''}"
    return hashlib.sha1(key.encode()).hexdigest()[:16]


def upsert_attack(con: sqlite3.Connection, rec: dict) -> bool:
    """Insert an attack record; skip if uid already present. Returns True if added."""
    cols = ["source", "source_ref", "uid", "name", "protocol", "chain", "occurred_date",
            "occurred_year", "loss_usd", "vuln_class", "vuln_raw", "attacker_addrs",
            "victim_addrs", "attack_txs", "block_number", "refs", "poc_lang", "poc_code",
            "summary", "raw_header", "multi_stage", "ingested_at"]
    for jcol in ("attacker_addrs", "victim_addrs", "attack_txs", "refs"):
        if isinstance(rec.get(jcol), (list, dict)):
            rec[jcol] = json.dumps(rec[jcol])
    rec.setdefault("ingested_at", now())
    vals = [rec.get(c) for c in cols]
    try:
        con.execute(
            f"INSERT INTO attacks ({','.join(cols)}) VALUES ({','.join('?' * len(cols))})",
            vals,
        )
        return True
    except sqlite3.IntegrityError:
        return False


# ---------------------------------------------------------------------------
# Vulnerability taxonomy — stable slugs the model will learn to emit.
# ---------------------------------------------------------------------------
TAXONOMY = [
    ("reentrancy",            "Reentrancy (single / cross-function / cross-contract / read-only)", "evm",    ""),
    ("price_oracle_manip",    "Price / oracle manipulation (spot price, TWAP, LP ratio)",          "both",   ""),
    ("flashloan_assisted",    "Flashloan-assisted attack (capital bootstrap for another bug)",     "evm",    ""),
    ("access_control",        "Missing / broken access control / unprotected init",                "both",   ""),
    ("arithmetic",            "Arithmetic (overflow, rounding, precision, decimals)",              "both",   ""),
    ("logic_accounting",      "Business-logic / accounting / share-price inflation",               "both",   ""),
    ("unchecked_external",    "Unchecked external call / arbitrary call / delegatecall",            "evm",    ""),
    ("signature_replay",      "Signature replay / malleability / missing nonce / permit abuse",     "both",   ""),
    ("governance",            "Governance / proposal / timelock takeover",                         "both",   ""),
    ("first_depositor",       "First-depositor / empty-vault share inflation",                     "evm",    ""),
    ("slippage_sandwich",     "Missing slippage / MEV sandwich / donation",                        "evm",    ""),
    ("proxy_upgrade",         "Proxy / upgrade / storage-collision / uninitialized implementation", "evm",   ""),
    ("bridge",                "Bridge verification / fake-deposit / message-proof flaw",           "both",   ""),
    ("account_confusion",     "Account / PDA confusion, missing owner/signer checks (Solana)",     "solana", ""),
    ("cpi_arbitrary",         "Arbitrary CPI / program substitution (Solana)",                     "solana", ""),
    ("type_cosplay",          "Type cosplay / missing discriminator (Solana)",                     "solana", ""),
    ("other",                 "Other / uncategorized",                                            "both",   ""),
]


def seed_taxonomy(con: sqlite3.Connection) -> None:
    con.executemany(
        "INSERT OR IGNORE INTO vuln_taxonomy (slug,label,chain_scope,description) VALUES (?,?,?,?)",
        TAXONOMY,
    )
    con.commit()


# Keyword -> slug heuristics for a first-pass label (LLM pass refines later).
_CLASSIFIERS = [
    ("reentrancy",         r"re-?entranc"),
    ("price_oracle_manip", r"oracle|price manip|spot price|twap|getreserves|lp price|skim|manipulat"),
    ("flashloan_assisted", r"flash ?loan|flashloan|flashswap"),
    ("access_control",     r"access control|only ?owner|unprotected|missing (auth|permission)|initiali[sz]e"),
    ("arithmetic",         r"overflow|underflow|rounding|precision|decimals|division"),
    ("first_depositor",    r"first deposit|empty vault|share inflation|inflation attack|donation"),
    ("signature_replay",   r"signature|ecrecover|replay|permit|malleab|nonce"),
    ("unchecked_external", r"delegatecall|arbitrary call|arbitrary external|unchecked call|low-level call"),
    ("proxy_upgrade",      r"proxy|upgrade|uninitiali|storage collision|implementation"),
    ("governance",         r"governance|proposal|timelock|voting|quorum"),
    ("bridge",             r"bridge|cross-?chain|fake deposit|merkle proof|message proof"),
    ("account_confusion",  r"owner check|signer check|pda|account confusion|missing .*check"),
    ("cpi_arbitrary",      r"\bcpi\b|arbitrary program|program substitution"),
    ("type_cosplay",       r"type cosplay|discriminator"),
    ("logic_accounting",   r"accounting|business logic|miscalcul|balance|reward|debt|collateral"),
]


def classify(text: str) -> tuple[str, str]:
    """Return (slug, matched_raw). Cheap keyword pass; refined later by the LLM step."""
    t = (text or "").lower()
    for slug, pat in _CLASSIFIERS:
        m = re.search(pat, t)
        if m:
            return slug, m.group(0)
    return "other", ""
