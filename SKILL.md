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

## Multi-contract / system analysis (don't audit single-layer!)
A finding on one contract is often low-sev ALONE but high-sev if another contract consumes
that value for minting/pricing/rewards. Before you rate severity, map the system:
```bash
python cli.py system <chain> <addr1> <addr2> ... [--check <variable>]
```
It prints the cross-contract VALUE flows (A.getter() consumed by B) and, with `--check`,
tells you whether a specific variable ESCALATES (consumed downstream for value) or is
low-sev telemetry (dead-ends). Use it to:
- turn a low-sev accounting finding into a high-sev cross-contract exploit when the value
  feeds a mint/price/backing path in another contract, and
- pick the real attack surface: the getters other contracts read for value (prices,
  reserve/backing values, rates) are where manipulation (flashloan/donation/oracle) pays off.
Then build a MULTI-STAGE PoC: manipulate the upstream value → trigger the downstream
mint/redeem/price → extract. Flashloan to bootstrap capital for the manipulation.

## A/B test the WHOLE hypothesis space (don't test one guess)
`engine/hypotheses.enumerate_hypotheses(mechanism_result, system_flows)` returns the full
space: single-contract + mathematical invariant violations (rounding, decimals,
fee-on-transfer, precision, first-depositor, overflow) + cross-contract (manipulate A →
trigger B) + flashloan combinations. Write a PoC for EACH, `prove` each, keep what drains.
Rank by result — that's the A/B matrix.

## Finding NOVEL / hidden bugs (the history makes good contracts immune)
A contract whose author knew the historical attacks is immune to replaying them. To find
UNKNOWN bugs you don't match patterns — you break the contract's own assumptions:
1. Read the target and extract ITS SPECIFIC invariants — properties that must always hold
   (`engine/invariants.candidate_invariants(archetypes)` gives starting points; add the
   ones unique to this contract's logic — its reward formula, its accounting identity).
2. Scaffold a stateful fuzz harness: `engine/invariants.scaffold(addr, alias, block,
   target_iface, handler_actions, invariant_asserts)` → a Foundry `StdInvariant` test.
   Fill the interface (functions to fuzz), the handler (bounded fuzz calls), and the
   `invariant_*` assertions.
3. Run it: `forge test --match-path <harness> ` — Foundry fuzzes millions of call
   sequences. **A failing invariant is a candidate NOVEL bug** (a state the author never
   anticipated). Minimize the failing sequence, confirm it, then weaponize it into a PoC
   and `prove` it.
This is how you find what nobody has seen: discover the broken state empirically, not from
the attack library.

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
