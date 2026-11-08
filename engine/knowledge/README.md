# Engine knowledge base — how real exploits actually work

This corpus teaches the engine to reason like a hunter, not match like a bot. Read in this order:

1. **`reasoning_protocol.md`** — START HERE. The discipline: state the protocol's INVARIANTS, list
   the ASSUMPTIONS that defend them, find the assumption the code trusts but does not enforce
   on-chain, and build the mechanism that violates it. The CALL / VALUE / POWER / CROSS-PROTOCOL
   interrogation that catches composition bugs (where every line is correct in isolation).

2. **`attack_sequences.md`** — the step-by-step playbook. 12 attack families, each with a numbered
   setup→trigger→extraction naming the exact contracts/calls, the violated invariant, the
   preconditions to look for, and the fuzzer invariant that catches it. Ends with an 8-step
   cross-mechanism checklist and a signal→family quick-reference. This is the "how" for each class.

3. **`audited_exploits.md`** — 10 drains of AUDITED protocols, each with WHY the audit missed it
   (the drain lived on a trust boundary assumed safe) + 20 mechanizable FLAG rules. Mechanized in
   `engine/heuristics.py` (`cli.py heuristics <chain> <addr>`).

4. **`bounty_research.md`** — Immunefi's v2.3 severity classification (what actually qualifies as
   Critical), 20 source-confirmed disclosed bugs/drains, and distilled top-hunter methodology.
   Use it to rate severity honestly (code bug = payable; trust/centralization = usually info).

5. **`academic_research.md`** — 23 verified papers (SoK: DeFi Attacks, the flash-loan paper, ItyFuzz,
   Echidna, tool evaluations), the DASP10/SWC taxonomies, a detection-technique blind-spot matrix,
   and concrete fuzzing invariants for lending/AMM/vault/bridge.

## How the engine uses it
- `reasoning_protocol.md` + `attack_sequences.md` → how the synthesizing agent *thinks* through a target.
- `heuristics.py` (from `audited_exploits.md`) → auto-raised candidates to verify.
- `compose.py` → the trust graph + hot/cold key + trust-delegation seams (POWER + CROSS-PROTOCOL).
- `hypotheses.py` / `invariants.py` → enumerate the space + fuzz the invariants (novel bugs).
- `prover.py` → prove the chosen chain on a mainnet fork. A claim is not a finding until it's proven.

The recurring lesson across every source: **losses are dominated by oracle manipulation and
permissionless composability, not raw code typos.** The bug is almost always a correct function
manipulated through another mechanism on the chain. Hunt the trust boundary.
