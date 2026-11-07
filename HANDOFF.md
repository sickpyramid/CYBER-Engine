# CYBER-Engine — Handoff / Continuation Guide

Read this first if you're a model or person picking up this project. It is the single
source of truth for where things stand and what to do next.

## What this is
An offensive-reasoning engine for smart-contract security (authorized bug-bounty /
audit research, responsible disclosure). It is fed the public history of on-chain
exploits, learns the patterns, and is pointed at **unseen** contracts to answer:
*"how can I break this — from where, in what multi-stage sequence?"* Chains: EVM
(Ethereum + BSC working; other L2s partial) and Solana (not started).

## The acceptance test (North Star — don't claim "done" without it)
Split the corpus into train / held-out. Give the engine ONLY a held-out victim's
pre-exploit source (no hint of the bug). It must name the vuln + location + multi-stage
path, and **prove it** with a Foundry PoC that drains the real contract on a mainnet
fork at the historical block. Success = a measured, climbing rediscovery rate, PoC-proven.

## The four tiers (all built + measured)
| Tier | File(s) | Status | Measured |
|---|---|---|---|
| 1. Corpus | `engine/sources/defihacklabs.py`, `data/corpus.sqlite` | ✅ | 920 attacks, 675 w/ fork block, code-aware labels |
| 2. Detection (static) | `engine/detect.py` | ✅ | ~19% held-out recall (reentrancy/logic); 0% on economic classes (that's expected) |
| 3. Mechanism reasoning | `engine/mechanism.py` | ✅ | 0%→43% on oracle/flashloan/proxy (the classes static analysis can't see) |
| 4. Exploit validation | `engine/prover.py` | ✅ | 6/8 historical exploits re-proven on fork; real drains confirmed |

## What's being built now: the CREATIVE LOOP (tiers 5–6)
```
held-out contract → mechanism.hypotheses() → retrieve similar historical attacks (RAG)
   → LLM synthesizes a Foundry PoC for the top hypothesis
      → prover.prove() runs it on the fork
         → drained? PROVEN.  failed? feed the trace back, refine, retry.  ← relentless
```
- `engine/retrieval.py` — RAG over the 920 attacks (find similar prior attacks to combine). [building]
- `engine/synthesize.py` — PoC synthesis; pluggable LLM backend (Anthropic API default). [building]
- `engine/creative_loop.py` — the orchestrator that wires it + the refine loop. [building]

**Why it matters:** tiers 2–3 *recognize* known shapes; they can't invent. The creative
loop is the part that generates NOVEL / COMBINED attacks, and the prover (tier 4) is the
feedback signal that keeps curiosity honest (a hypothesis is a hallucination until it drains).

## Setup / credentials
- Python deps: `pip install -r requirements.txt` (slither-analyzer, solc-select, requests).
- Foundry: installed at `~/.foundry/bin` (forge/anvil/cast). Release binary, not the installer script.
- `.env` (gitignored) holds archive RPCs — REQUIRED for the prover:
  - `ETH_ARCHIVE_RPC` (Alchemy, has archive) ; `BSC_ARCHIVE_RPC` (QuickNode, has archive).
  - The DeFiHackLabs `foundry.toml` rpc aliases `mainnet=` and `bsc=` must point at these.
- PoC synthesis (`synthesize.py`) needs an LLM key: set `ANTHROPIC_API_KEY` (or wire another provider).
- `.claude/settings.json` allows `Bash(forge:*)` etc. so the prover runs under auto mode.

## How to run each tier
```bash
bash scripts/build_corpus.sh                 # (re)build data/corpus.sqlite from DeFiHackLabs
python cli.py stats                           # corpus summary
python cli.py detect <chain> <address>        # static detection on a held-out victim
python cli.py scoreboard 25                   # held-out detection scoreboard
python -c "from engine import mechanism, fetch_source"   # mechanism layer (see tests)
python -c "from engine.prover import prove"   # exploit tier (needs .env RPCs + forge)
```

## Known limitations / honest state
- Many economic attacks are **cross-contract** (the manipulable price lives in a pool the
  victim trusts, not in the victim). Single-contract analysis caps mechanism recall ~43%.
  True fix = fetch+analyze the contract SYSTEM, or resolve the oracle via on-chain state (RPC).
- Ground-truth labels are code-heuristic, not perfect (`flashloan_assisted` is a vector tag).
- Only ETH+BSC have archive RPCs wired. Other chains' PoCs won't prove until their RPCs are set.
- Solana: not started (separate mechanism model + solana-test-validator sandbox).
- `vendor/DeFiHackLabs` is gitignored (cloned on build); `.env` is gitignored.

## TODO (priority order)
1. Finish the creative loop (retrieval → synthesize → loop) and demo one held-out PoC end-to-end.
2. Cross-contract / system-level analysis (fetch the trusted oracle/pool, analyze together).
3. Self-play: log which synthesized PoCs validate; build the training set of validated attack traces.
4. Qwen LoRA training on validated traces (GPU elsewhere — this box has none).
5. Solana support. 6. Auto-pipeline: watch newly-verified contracts, run the loop on demand.
