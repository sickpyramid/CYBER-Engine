"""Swarm configuration — all secrets and tunables come from the environment (.env on the VPS).

NOTHING secret is hardcoded here. Copy .env.example -> .env on the Frankfurt VPS and fill it.
"""
from __future__ import annotations
import os
from dataclasses import dataclass, field

# ── provider (KiloCode, OpenAI-compatible) ───────────────────────────────────
KILO_BASE = os.environ.get("KILOCODE_BASE_URL", "https://kilo.ai/api/openrouter/v1")
KILO_TOKEN = os.environ.get("KILOCODE_API_KEY", "")  # the JWT; set in .env

# Per-role model routing. Five DIFFERENT free models so the agents genuinely disagree
# (not echo one base model) and rate limits spread across providers. All verified live.
# Override any role in .env (e.g. SWARM_MODEL_ATTACKER=...).
DEFAULT_MODEL = os.environ.get("SWARM_MODEL", "reflection/beam-free")
_ROLE_DEFAULTS = {
    "RECON":       "reflection/beam-free",                               # 1M ctx — holds big source
    "ATTACKER":    "nvidia/nemotron-3-ultra-550b-a55b:free",            # strongest free reasoner
    "SKEPTIC":     "nvidia/nemotron-3-nano-omni-30b-a3b-reasoning:free", # diff lineage -> real falsify
    "EXPLOIT_DEV": "cohere/north-mini-code:free",                        # code-specialized -> PoC
    "REFEREE":     "kilo-auto/free",                                     # auto-route, reliable verdict
}
def _model(role: str) -> str:
    return os.environ.get(f"SWARM_MODEL_{role.upper()}",
                          _ROLE_DEFAULTS.get(role.upper(), DEFAULT_MODEL))

# ── chains / RPC / explorer (read by the engine via these same env names) ─────
ETH_RPC = os.environ.get("ETH_ARCHIVE_RPC", "")
BSC_RPC = os.environ.get("BSC_ARCHIVE_RPC", "")
ETHERSCAN_KEY = os.environ.get("ETHERSCAN_API_KEY", "")

# ── swarm behaviour / safety rails ───────────────────────────────────────────
@dataclass
class Limits:
    # rate limiting between model calls (seconds) — protects your KiloCode quota
    min_call_interval: float = float(os.environ.get("SWARM_MIN_CALL_INTERVAL", "2.0"))
    # hard cap on model calls per target before we declare "no proven bug" and move on
    max_calls_per_target: int = int(os.environ.get("SWARM_MAX_CALLS_PER_TARGET", "60"))
    # wall-clock budget per target (seconds)
    max_seconds_per_target: int = int(os.environ.get("SWARM_MAX_SECONDS_PER_TARGET", "1200"))
    # global daily call cap (0 = unlimited) — a money/quota safety net
    max_calls_per_day: int = int(os.environ.get("SWARM_MAX_CALLS_PER_DAY", "5000"))
    # max tokens per completion (reflection models need headroom to emit content)
    max_tokens: int = int(os.environ.get("SWARM_MAX_TOKENS", "3000"))
    # retries on 429/5xx
    max_retries: int = int(os.environ.get("SWARM_MAX_RETRIES", "4"))

# ── targets / auto-hunt ──────────────────────────────────────────────────────
@dataclass
class TargetConfig:
    chains: list[str] = field(default_factory=lambda:
        os.environ.get("SWARM_CHAINS", "ethereum,bsc").split(","))
    max_tvl: int = int(os.environ.get("SWARM_MAX_TVL", "500000"))       # focus small/unaudited
    min_tvl: int = int(os.environ.get("SWARM_MIN_TVL", "1000"))
    max_age_days: float = float(os.environ.get("SWARM_MAX_AGE_DAYS", "30"))
    # include Immunefi in-scope targets (bounty hunting)
    use_immunefi: bool = os.environ.get("SWARM_USE_IMMUNEFI", "true").lower() == "true"
    use_defillama: bool = os.environ.get("SWARM_USE_DEFILLAMA", "true").lower() == "true"

# ── server ───────────────────────────────────────────────────────────────────
HOST = os.environ.get("SWARM_HOST", "0.0.0.0")
PORT = int(os.environ.get("SWARM_PORT", "8080"))

# where the engine lives (for shelling out to cli.py)
ENGINE_ROOT = os.environ.get("ENGINE_ROOT", os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

LIMITS = Limits()
TARGETS = TargetConfig()

def role_model(role: str) -> str:
    return _model(role)

def sanity() -> list[str]:
    """Return a list of missing-config warnings (printed at startup)."""
    warn = []
    if not KILO_TOKEN: warn.append("KILOCODE_API_KEY is empty — the swarm cannot call any model")
    if not ETH_RPC: warn.append("ETH_ARCHIVE_RPC is empty — Ethereum analysis/proving disabled")
    if not BSC_RPC: warn.append("BSC_ARCHIVE_RPC is empty — BSC analysis/proving disabled")
    if not ETHERSCAN_KEY: warn.append("ETHERSCAN_API_KEY is empty — source fetching degraded")
    return warn
