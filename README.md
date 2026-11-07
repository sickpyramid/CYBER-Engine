# CYBER-Engine

**An offensive-reasoning engine for smart-contract security.** It is fed the full
public history of on-chain exploits, learns the attack patterns and multi-stage
sequences, and is then pointed at *unseen* contracts to answer one question:

> **How can I break this system — from where, and in what multi-stage sequence?**

Built for **authorized security research and bug bounties** (Immunefi, Code4rena,
Sherlock, Cantina). Every target is public or in-scope; every finding is meant for
responsible disclosure. Chains: **EVM (Ethereum + L2s/sidechains)** and **Solana**.

---

## The acceptance test (the only metric that matters)

The engine is not "done" because a model emits the word *reentrancy*. It is done when:

1. The corpus is split into a **train set** (learned from) and a **held-out set it never sees**.
2. Given only the **pre-exploit contract** of a held-out case — with no hint a bug exists —
3. the engine independently names the **vulnerability, its location, and the multi-stage attack path**, and
4. **proves it** with a Foundry PoC that drains the real contract on a mainnet fork at the historical block.

Success = a **measured rediscovery rate** on held-out real contracts, proven by runnable
exploits. Honest target: 20–50% depending on bug class. A climbing number is the win.

---

## Architecture

```
  sources ─▶ ingest ─▶ corpus.sqlite ─▶ label/enrich ─▶ train/test split
                                                │
                                                ├─▶ RAG index  (retrieval over historical attacks)
                                                ├─▶ training corpus (instruction JSONL for Qwen LoRA)
                                                └─▶ detection loop:
                                                      static analysis (Slither/Mythril)
                                                      + retrieval of similar historical attacks
                                                      + reasoner ("how do I break this")
                                                      + Foundry fork-replay PROVER  ◀── scoreboard
```

- **The brain** is a strong reasoner driving the loop; the fine-tuned **Qwen** is the cheap,
  repeatable accelerant (structured extraction, triage, pattern-tagging) — not the lone brain.
- **Proof** always comes from execution on a mainnet fork, never from the model's say-so.

---

## Layout

| Path | What |
|---|---|
| `engine/schema.sql` | normalized corpus schema (attacks, steps, taxonomy) |
| `engine/db.py` | SQLite layer + vulnerability taxonomy + first-pass classifier |
| `engine/sources/` | one ingester per source (DeFiHackLabs first) |
| `cli.py` | `ingest` / `stats` entrypoint |
| `data/corpus.sqlite` | **the built historical-attack database** (ships in-repo) |
| `training/` | corpus-building + Qwen LoRA training (GPU-agnostic) |
| `scripts/build_corpus.sh` | reproduce the DB from scratch |

## Quick start

```bash
pip install -r requirements.txt
python cli.py stats                 # inspect the shipped corpus
# rebuild from source:
bash scripts/build_corpus.sh
```

## Detection tier (runs today, no API key)

```bash
pip install slither-analyzer solc-select
# fetch a held-out victim's exact verified source (keyless, Sourcify) and analyze it:
python cli.py detect polygon 0x3dC7E6FF0fB79770FA6FB05d1ea4deACCe823943   # Market -> reentrancy
python cli.py scoreboard 25                                               # held-out rediscovery eval
```

The detector compiles each target's **exact standard-json** (multi-file, OZ imports,
legacy solc) and runs 102 Slither detectors. Proven: fed the Market victim blind, it
independently flagged the `redeemFresh`/`borrowFresh` reentrancy that was exploited.

## Status

- [x] DeFiHackLabs ingester — 920 EVM exploits, 675 with replay fork-blocks
- [x] Keyless held-out source fetch (Sourcify std-json) + Slither detection substrate
- [x] Held-out scoreboard harness (detection tier) — single-case rediscovery proven (Market)
- [ ] **LLM labeling pass** — clean ground-truth labels (today the scoreboard scores against the weak keyword classifier)
- [ ] **Finding ranking + reasoning/retrieval layer** — raw Slither floods reentrancy; pick the true vuln + build the multi-stage path
- [ ] Harden compilation across all solc versions (some targets still fail to compile)
- [ ] More sources (reentrancy-list, SlowMist, rekt, Solana incidents)
- [ ] Foundry fork-replay PROVER (exploit tier) — needs an archive RPC key
- [ ] Qwen LoRA training corpus + script

### Honest read
The harness is real and runs on real held-out contracts. The current batch numbers are a
**floor, not a result** — they are capped by noisy labels and naive ranking, both known and
next on the list. Every fix from here is *measured* against the scoreboard.

---
*For authorized security testing and responsible disclosure only.*
