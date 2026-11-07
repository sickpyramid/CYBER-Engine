"""PoC synthesis — the creative step.

Takes the target contract + a mechanism hypothesis + retrieved historical PoCs and asks
an LLM to write a Foundry exploit test (DeFiHackLabs style) that forks at the block and
drains the victim. On a retry it is also given the previous forge error to refine against.

This is where novelty happens: the model reasons from the mechanism model and COMBINES
patterns from the retrieved historical attacks into a concrete exploit — then the prover
(engine/prover.py) proves or kills it.

Backend is pluggable. Default: Anthropic Messages API.
  env CYBER_LLM_PROVIDER = "anthropic" (default)
  env ANTHROPIC_API_KEY  = <key>   (required for the anthropic backend)
  env CYBER_LLM_MODEL    = model id (default below; override to match your key)
No key -> raises RuntimeError with a clear message (nothing fabricated).
"""
from __future__ import annotations
import os, re, json, urllib.request, urllib.error

DEFAULT_MODEL = os.environ.get("CYBER_LLM_MODEL", "claude-sonnet-4-5")
RE_SOL_BLOCK = re.compile(r"```(?:solidity)?\s*(.*?)```", re.DOTALL)

SYSTEM = (
    "You are an elite smart-contract exploit developer doing AUTHORIZED bug-bounty "
    "research. You write Foundry PoC tests (DeFiHackLabs style) that fork a chain at a "
    "historical block and prove a vulnerability by draining the victim. Output ONLY one "
    "solidity code block: a complete, self-contained `contract X_exp is Test` with a "
    "`testExploit()` that does vm.createSelectFork(<alias>, <block>), executes the attack, "
    "and asserts a realized profit. Use concrete on-chain addresses. No prose."
)

PROMPT = """# Target (held-out victim — never seen in training)
chain: {chain}   fork alias: "{alias}"   block: {block}
victim address: {address}
archetype: {archetypes}
mechanism hypothesis (vuln + multi-stage path):
{hypothesis}

# Victim source (truncated)
```solidity
{source}
```

# Similar historical exploits (reproduced PoCs — reuse/combine their techniques)
{examples}
{retry}
Write the Foundry PoC now. One solidity code block only."""


def _anthropic(system, prompt, model, max_tokens=4000):
    key = os.environ.get("ANTHROPIC_API_KEY")
    if not key:
        raise RuntimeError("ANTHROPIC_API_KEY not set — the synthesizer needs an LLM key. "
                           "Set it (or set CYBER_LLM_PROVIDER to another backend you wire).")
    body = json.dumps({"model": model, "max_tokens": max_tokens, "system": system,
                       "messages": [{"role": "user", "content": prompt}]}).encode()
    req = urllib.request.Request(
        "https://api.anthropic.com/v1/messages", data=body,
        headers={"x-api-key": key, "anthropic-version": "2023-06-01",
                 "content-type": "application/json"})
    with urllib.request.urlopen(req, timeout=120) as r:
        d = json.load(r)
    return "".join(b.get("text", "") for b in d.get("content", []))


def synthesize(target, hypothesis, examples, prior_error=None, model=DEFAULT_MODEL):
    """target: fetch_source meta + source text + block/alias. Returns solidity PoC string."""
    ex_blocks = []
    for e in examples[:2]:
        ex_blocks.append(f"## {e['name']} ({e['vuln_class']}, {e['chain']})\n"
                         f"```solidity\n{e['poc_code'][:4000]}\n```")
    retry = ""
    if prior_error:
        retry = ("\n# Previous attempt failed — fix it\n"
                 f"```\n{prior_error[:2500]}\n```\n")
    prompt = PROMPT.format(
        chain=target.get("chain"), alias=target.get("alias", target.get("chain")),
        block=target.get("block"), address=target.get("address"),
        archetypes=target.get("archetypes"), hypothesis=hypothesis,
        source=(target.get("source") or "")[:12000],
        examples="\n\n".join(ex_blocks) or "(none)", retry=retry)

    provider = os.environ.get("CYBER_LLM_PROVIDER", "anthropic")
    if provider == "anthropic":
        text = _anthropic(SYSTEM, prompt, model)
    else:
        raise RuntimeError(f"Unknown CYBER_LLM_PROVIDER={provider}; only 'anthropic' is wired.")

    m = RE_SOL_BLOCK.search(text)
    code = m.group(1).strip() if m else text.strip()
    return code
