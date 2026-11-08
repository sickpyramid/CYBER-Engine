"""Engine tool execution — parse an agent's `CALL:` line, run the engine, return text.

These are the hands of the swarm: the agents reason, these wrappers touch the chain and the
fork. Everything shells out to the engine already in this repo (cli.py / engine modules) so the
swarm and the CLI stay in sync.
"""
from __future__ import annotations
import asyncio, re, os, shlex, tempfile
from pathlib import Path
from . import config

ENGINE = Path(config.ENGINE_ROOT)
CALL_RE = re.compile(r"^\s*CALL:\s*(\w+)\s+(.*)$", re.M)
# a Solidity PoC code block the Exploit Dev emits
SOL_RE = re.compile(r"```(?:solidity|sol)?\s*(//[^\n]*SPDX[\s\S]+?)```", re.I)


def _env() -> dict:
    e = dict(os.environ)
    e["PATH"] = f"{Path.home()/'.foundry'/'bin'}:{e.get('PATH','')}"
    return e


async def _run(cmd: list[str], timeout: int = 300) -> str:
    try:
        p = await asyncio.create_subprocess_exec(
            *cmd, cwd=str(ENGINE), env=_env(),
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT)
        out, _ = await asyncio.wait_for(p.communicate(), timeout=timeout)
        return (out or b"").decode(errors="ignore")[:6000]
    except asyncio.TimeoutError:
        return "[tool timed out]"
    except Exception as e:
        return f"[tool error: {e}]"


def find_calls(text: str) -> list[tuple[str, str]]:
    return [(m.group(1).lower(), m.group(2).strip()) for m in CALL_RE.finditer(text or "")]


def extract_poc(text: str) -> str | None:
    m = SOL_RE.search(text or "")
    return m.group(1) if m else None


async def execute(tool: str, args: str, workdir: Path) -> str:
    """Run one engine tool. Returns a text result to feed back to the agents."""
    a = shlex.split(args) if args else []
    py = ["python3", "cli.py"]
    if tool in ("compose", "heuristics") and len(a) >= 2:
        return await _run(py + [tool, a[0], a[1]])
    if tool in ("source", "fetch") and len(a) >= 2:
        # reuse the engine's fetcher via a tiny inline call
        code = ("import sys,json;sys.path.insert(0,'.');from engine import fetch_source as F;"
                f"d=F.fetch('{a[0]}','{a[1]}','{workdir/'src'}');"
                "print('contract:',d.get('contract'),'files:',d.get('n_files')) if d else print('no verified source')")
        return await _run(["python3", "-I", "-c", code])
    if tool == "prove" and a:
        # the PoC was written to workdir/<name>.sol by the orchestrator; prove it
        name = a[0]
        poc = workdir / f"{name}.sol"
        if not poc.exists():
            # maybe they passed the current poc
            poc = workdir / "attempt.sol"
        if not poc.exists():
            return f"[prove: no PoC file at {poc}]"
        return await _run(py + ["prove", str(poc)], timeout=420)
    return f"[unknown tool '{tool}' or bad args '{args}']"
