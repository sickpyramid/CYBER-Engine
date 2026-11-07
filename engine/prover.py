"""Exploit-validation tier: run a Foundry PoC against a mainnet-fork and confirm it works.

This is what turns a hypothesis into PROOF. A detection/mechanism finding is a claim;
a PoC that drains the real contract on a fork at the historical block is irrefutable.
Requires archive RPCs wired in .env (ETH_ARCHIVE_RPC, BSC_ARCHIVE_RPC) and the DeFiHackLabs
foundry project's rpc aliases pointed at them.

    from engine.prover import prove
    prove("src/test/2026-06/ThetanutsFi_exp.sol", repo_root)
"""
from __future__ import annotations
import subprocess, re, os
from pathlib import Path

FOUNDRY_BIN = Path.home() / ".foundry" / "bin"
RE_PASS = re.compile(r"\[PASS\]")
RE_FAIL = re.compile(r"\[FAIL")
RE_PROFIT = re.compile(r"(?:profit|gain|stolen|realized)[^\n]*?([\d][\d,\.]*)\s*(USD|USDC|USDT|ETH|BNB|DAI|WETH|WBNB)?",
                       re.I)
RE_GAS = re.compile(r"\(gas:\s*(\d+)\)")


def prove(poc_relpath: str, repo_root: str | Path, timeout: int = 300) -> dict:
    """Run one DeFiHackLabs-style PoC (a forge test) against the fork. Structured result."""
    repo_root = Path(repo_root)
    env = dict(os.environ, PATH=f"{FOUNDRY_BIN}:{os.environ.get('PATH','')}")
    try:
        r = subprocess.run(
            ["forge", "test", "--contracts", f"./{poc_relpath}", "-vv"],
            cwd=repo_root, env=env, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return {"ok": False, "proven": False, "error": "timeout", "poc": poc_relpath}

    out = r.stdout + "\n" + r.stderr
    proven = bool(RE_PASS.search(out)) and not RE_FAIL.search(out)
    profits = [f"{m.group(1)} {m.group(2) or ''}".strip() for m in RE_PROFIT.finditer(out)]
    gas = RE_GAS.search(out)
    # compile vs runtime failure distinction
    compiled = "Compiler run successful" in out or RE_PASS.search(out) or RE_FAIL.search(out)
    err = None
    if not proven:
        if not compiled:
            err = "compile_failed"
        elif RE_FAIL.search(out):
            err = "exploit_failed"
        else:
            err = "no_test_ran"
    return {"ok": True, "proven": proven, "poc": poc_relpath,
            "profit_logs": profits[:5], "gas": int(gas.group(1)) if gas else None,
            "error": err, "tail": out.strip().splitlines()[-4:] if not proven else None}
