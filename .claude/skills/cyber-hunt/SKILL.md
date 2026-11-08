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

## READ THIS FIRST — the deep reasoning protocol
**`engine/knowledge/reasoning_protocol.md` is the core discipline. Read it before every hunt.**
Known bugs are already found by bots. The money is in exploits where every line is correct in
isolation and the drain comes from composing correct parts through another mechanism on-chain.
Do not grep for bad patterns and stop. Instead: state the protocol's INVARIANTS, list the
ASSUMPTIONS that defend them, and find the one assumption the code trusts but does not enforce
on-chain — then build the mechanism that violates it. Interrogate every external call (who's on
the other end, can the attacker run code there), every value read (where's it from, can it move
in one tx with a flash loan), every privileged key (hot or cold, fund-critical or ops), and the
whole rest of the chain (what can an attacker borrow/mint/own/pre-position to break a correct
function). The knowledge base — `audited_exploits.md`, `attack_sequences.md`, `bounty_research.md`,
`academic_research.md` — is the corpus of how real drains actually sequenced; `reasoning_protocol.md`
is how to think with it. These make the engine reason like a hunter, not match like a bot.

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

## Learn from audited drains — run the heuristics + read the case base
Audited protocols still get drained. The 10 best-documented cases + 20 FLAG rules distilled
from them live in `engine/knowledge/audited_exploits.md` — read it; the recurring lesson is
that the drain lived on a TRUST BOUNDARY the audit assumed safe (an external price feed, a
vault share price, a token's transfer semantics, a registered market, a ported library, an
off-chain keeper). Auto-raise the mechanizable subset on any target:
```bash
python cli.py heuristics <chain> <address>
```
These are CANDIDATES to verify, not verdicts (triage, then confirm each by hand or PoC). The
oracle/lending family is where forks die: a keeper-pushed price is only as safe as its on-chain
bound — verify the circuit-breaker / deviation cap is TIGHTER than the asset's real volatility x
the collateral LTV, or a key compromise walks the price to a drain across windows (Poppie pattern,
rule 6). For share/vault prices check the virtual-share guard (rule 3); for AMM-read prices check
TWAP (rule 2); for forks check deployed-vs-audit-date (rule 14).

## Composition / attack-graph — ALWAYS run this FIRST (think attacker, not auditor)
Before asking "is this contract sound?", ask the attacker's question: "what does it TRUST
and CALL that I can bend?" Most drains are composition, not a single-contract bug.
```bash
python cli.py compose <chain> <target_address>
```
It resolves the proxy to its EIP-1967 implementation, walks every privileged setter's
access gate to the on-chain address that really satisfies it (hop by hop), and classifies
each terminal — **EOA / Gnosis Safe (threshold+owners) / Timelock (delay) / custom
controller**. It flags what a single-contract audit cannot see: fund-critical power with
**no timelock** (instant, silent), **bare-EOA** terminals, **one key reused across two
tiers** (e.g. a hot role key that is also a multisig signer), and **external value routes**
(swap router / oracle) a flash loan can move. It emits staged multi-contract chains.
Use it to decide the shape of the attack:
- if a fund-critical gate (setVerifiers / upgrade / setOracle / sweep) has no timelock and
  resolves to an EOA or low-threshold multisig → the drain is a trust/governance vector
  (usually NOT a payable bounty bug, but say so plainly and name the one fix: a timelock).
- if value is routed through an external router/oracle with caller params → that is the
  KEYLESS composition surface: flash-loan-move the external pool, let the target execute
  against it. Build the multi-stage PoC from there.
Be honest: a 2-of-3 Safe admin is a real mitigation; "admin can rug" on a multisig is
usually informational. The prize is the keyless cross-contract path, not the key risk.

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
