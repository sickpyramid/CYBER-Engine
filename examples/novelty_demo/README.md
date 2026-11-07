# Novelty engine demo — fuzzing discovers an UNKNOWN bug

Proof that the invariant-fuzzing path finds bugs it was never told about.

`src/Vault.sol` has a hidden share-inflation flaw. The fuzzer (`test/Inflation.t.sol`) is
given ONLY an invariant — *"an honest, non-trivial depositor is never diluted to 0 shares"* —
and three generic actions (donate, attackerDeposit, victimDeposit). Nothing describes the attack.

Run:
```bash
forge test --match-contract InflationInvariant -vvv
```
The fuzzer discovers the exploit on its own and shrinks it to 3 calls:
`donate -> attackerDeposit -> victimDeposit` → victim rounds down to 0 shares → FAIL.

This is how the engine finds NOVEL vulnerabilities: state what must always be true, then let
the fuzzer search for a state that breaks it. The broken state is the bug.
