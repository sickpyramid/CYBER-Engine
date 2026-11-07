---
name: cyber-hunt
description: >
  Find and PROVE a smart-contract vulnerability on a held-out / unseen EVM contract,
  for authorized bug-bounty and audit research. Use when asked to analyze a contract for
  exploitable bugs, rediscover how a protocol can be drained, or generate a proven exploit
  PoC. The engine fetches the verified source, reverse-engineers the mechanism, retrieves
  similar historical attacks, and runs YOUR exploit PoC on a mainnet fork to prove it.
  Chains with archive RPC wired: Ethereum, BSC. No LLM API key needed — YOU are the
  synthesizer.
---

# cyber-hunt — drive the engine to find + prove an exploit

You (the agent reading this) are the creative adversary. The engine gives you the
understanding, the historical playbook, and a fork to prove your idea on. Your job:
look at an unseen contract and answer **"how do I break this?"** — then prove it drains.

This is authorized security research (bug bounties / responsible disclosure). Targets are
public, in-scope contracts; every exploit is run on a local fork, never on mainnet.

## Setup (once)
```bash
pip install -r requirements.txt          # slither-analyzer, solc-select, requests
# Foundry on PATH (forge). .env must hold archive RPCs:
#   ETH_ARCHIVE_RPC=...   BSC_ARCHIVE_RPC=...
# and vendor/DeFiHackLabs/foundry.toml rpc aliases mainnet=/bsc= must point at them.
bash scripts/build_corpus.sh             # builds data/corpus.sqlite if missing
```

## The loop

**1. Hunt — get the brief.**
```bash
python cli.py hunt <chain> <address> [block]
```
It prints (and saves to `data/workdir/<chain>_<addr>/brief.json`):
- `target`: chain, fork_alias, block, contract name, solc
- `mechanism.archetypes`, `predicted_classes`, `top_hypotheses` (vuln class + multi-stage attack_path)
- `source_file`: the victim's full verified source — **READ IT**
- `example_pocs`: real reproduced PoCs of the same vuln class — **READ THEM**, they are your templates
- `write_poc_to`: the path to write your exploit
- `then_run`: the prove command

**2. Think like an attacker. Write the PoC.**
Read `source_file` and the `example_pocs`. Take the top hypothesis (and improve on it — look
for multi-stage / cross-contract / combined paths the hypotheses missed). Write a Foundry
test to `write_poc_to`:
- `// SPDX` + `pragma`, `import "forge-std/Test.sol";`
- `contract Xyz_exp is Test { function testExploit() public { ... } }`
- `vm.createSelectFork("<fork_alias>", <block>);` at the start
- execute the attack with concrete on-chain addresses (pools, tokens, the victim)
- end by asserting realized profit (`assertGt(finalBalance, startBalance)`)
Reuse the exact cheatcodes/structure from the example PoCs; they already fork + drain
contracts on this chain.

**3. Prove it.**
```bash
python cli.py prove data/workdir/<chain>_<addr>
```
Returns `{"proven": true/false, "profit_logs", "error", "tail"}`.
- `proven: true` → done. Report the vuln class, the multi-stage path, and the realized profit.
- `proven: false` → read `error` + `tail` (the forge output). Fix `attempt.sol`. Prove again.
  **Do not give up after one try** — refine against the actual error, 3–5 attempts. Common
  fixes: wrong pool/token address, missing `vm.prank`/approval, wrong function signature,
  flashloan callback shape. The example PoCs show the right patterns for this chain.

## Rules
- Only authorized targets; PoCs run on a fork only; this is for disclosure, not use.
- A finding is not real until `proven: true`. Never claim an exploit you haven't proven.
- If after N attempts it won't drain, say so honestly and report the strongest hypothesis
  + where it got stuck. That's a real result too.

## Also available
- `python cli.py detect <chain> <address>` — static (Slither) findings only.
- `python cli.py scoreboard [N]` — held-out detection rediscovery eval.
- `engine/creative_loop.py` — the same loop fully automated via an LLM **API** key
  (ANTHROPIC_API_KEY), for headless runs. The skill path above needs no key.

See `HANDOFF.md` for the full architecture, measured numbers, and TODO.
