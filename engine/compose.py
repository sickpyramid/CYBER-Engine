"""Composition / attack-graph tier — "how can I break this using the WHOLE chain?"

The other tiers ask of ONE contract: is it sound? This tier assumes it is sound and asks
the attacker's real question: what does it TRUST and CALL, and can I bend the machine
*around* it so that "correct behaviour" still pays me?

Almost no real DeFi drain is a single-contract bug. It is composition:
  - a privileged setter whose gate resolves, on-chain, to a key/committee I can get, OR
  - value the target routes THROUGH an external contract whose state I can move
    (flash-loan an AMM, skew an oracle), while the target behaves exactly as designed.

So this module, given a target address + verified source, does what a human attacker does
during recon, but mechanically and on real chain state:

  1. TRUST GRAPH. Find every privileged function (its access gate) and every
     external-call / router / oracle / verifier surface in the source.
  2. RESOLVE. For each power, follow the on-chain pointer chain to the address that
     actually satisfies the gate, hop by hop (admin() -> safe, canUpgrade -> controller
     -> admin, owner(), etc.), and CLASSIFY each terminal: plain EOA, Gnosis Safe
     (threshold/owners), Timelock (delay), or unknown contract.
  3. WEAKNESSES. Flag the things that turn "trusted admin" into "drain vector":
       * fund-critical power with NO timelock   (instant, silent)
       * terminal is a bare EOA                  (one key = game over)
       * one key reused across two trust tiers   (warm key doing cold-key duty)
       * external value route (router/oracle) with caller-chosen params
  4. CHAINS. Emit staged, multi-contract attack scenarios, not single findings.

On-chain resolution shells out to `cast` against the archive RPCs already in .env
(ETH_ARCHIVE_RPC / BSC_ARCHIVE_RPC). Source analysis is regex/heuristic by design — it
points the on-chain probe at the right selectors; the chain state is the ground truth.
"""
from __future__ import annotations
import os, re, subprocess
from pathlib import Path

FOUNDRY_BIN = Path.home() / ".foundry" / "bin"

RPC_ENV = {"ethereum": "ETH_ARCHIVE_RPC", "eth": "ETH_ARCHIVE_RPC",
           "bsc": "BSC_ARCHIVE_RPC", "bnb": "BSC_ARCHIVE_RPC"}

# ---- source-side surface detection -----------------------------------------

# a privileged function = one whose body calls an access gate. Capture the fn + its gate.
RE_FUNC = re.compile(
    r"function\s+(\w+)\s*\(([^)]*)\)\s*(external|public)[^{]*\{([^}]*(?:\{[^}]*\}[^}]*)*?)\}",
    re.S)
# gate calls we recognise, and how "powerful" the role is
GATE_CALLS = re.compile(
    r"_requireAdmin|_requireGuardOrAdmin|_requireWhitelistManager|_requireRelayer|"
    r"onlyOwner|onlyRole|onlyAdmin|_checkOwner|_authorizeUpgrade|canUpgrade|"
    r"onlyGovernance|onlyTimelock|requireAuth", re.I)
# fund-critical powers: if these fire, funds can move or the proof/price check can be swapped
FUND_CRITICAL = re.compile(
    r"setverif|upgrade|_authorizeupgrade|setimplementation|setguard|setowner|"
    r"settreasur|setfeerecip|setoracle|setprice|setrouter|withdraw|sweep|rescue|"
    r"setwhitelist|settoken|mint|settrusted|setcontroller|migrat", re.I)
# external-call surfaces: value leaves or a price/proof is read from another contract
RE_ROUTER = re.compile(r"router|uniswap|swapexact|ISwap|AMM|pancake", re.I)
RE_ORACLE = re.compile(r"oracle|latestanswer|latestrounddata|getprice|priceof|chainlink|twap", re.I)
RE_VERIFIER = re.compile(r"verifier|verifyproof|_verifyproof|snark|groth16|plonk", re.I)
# getters that name an on-chain role we can resolve & classify
RE_ROLE_GETTER = re.compile(
    r"\baddress\s+public\s+(?:immutable\s+|constant\s+)?"
    r"(owner|admin|guard|treasury|upgradeController|whitelistManager|relayer|"
    r"governance|timelock|controller|pendingAdmin|proxyAdmin)\b", re.I)


def _cast(rpc: str, to: str, sig: str, *args: str, timeout: int = 25) -> str | None:
    env = dict(os.environ, PATH=f"{FOUNDRY_BIN}:{os.environ.get('PATH','')}")
    try:
        r = subprocess.run(["cast", "call", to, sig, *args, "--rpc-url", rpc],
                           capture_output=True, text=True, timeout=timeout, env=env)
    except Exception:
        return None
    out = (r.stdout or "").strip()
    return out if (r.returncode == 0 and out and out != "0x") else None


# EIP-1967 implementation slot
_IMPL_SLOT = "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc"


def impl_address(chain: str, proxy: str) -> str | None:
    """Resolve a proxy's current implementation from the EIP-1967 slot. The attacker's
    first recon move: you must analyze the LOGIC behind the proxy, not the proxy shell."""
    rpc = os.environ.get(RPC_ENV.get(chain, "ETH_ARCHIVE_RPC"), "")
    if not rpc:
        return None
    env = dict(os.environ, PATH=f"{FOUNDRY_BIN}:{os.environ.get('PATH','')}")
    try:
        r = subprocess.run(["cast", "storage", proxy, _IMPL_SLOT, "--rpc-url", rpc],
                           capture_output=True, text=True, timeout=25, env=env)
    except Exception:
        return None
    h = (r.stdout or "").strip()
    if not h.startswith("0x") or len(h) < 66:
        return None
    addr = "0x" + h[-40:]
    return addr if int(addr, 16) != 0 else None


def _codesize(rpc: str, addr: str) -> int:
    env = dict(os.environ, PATH=f"{FOUNDRY_BIN}:{os.environ.get('PATH','')}")
    try:
        r = subprocess.run(["cast", "code", addr, "--rpc-url", rpc],
                           capture_output=True, text=True, timeout=25, env=env)
    except Exception:
        return -1
    h = (r.stdout or "").strip()
    return (len(h) - 2) // 2 if h.startswith("0x") else -1


def classify_address(rpc: str, addr: str) -> dict:
    """What is this terminal? EOA / Gnosis Safe / Timelock / unknown contract — the
    single most important question in the whole graph, answered from chain state."""
    addr = addr.strip().lower()
    out = {"address": addr, "kind": "eoa", "detail": {}}
    sz = _codesize(rpc, addr)
    out["code_bytes"] = sz
    if sz <= 0:
        out["kind"] = "eoa"
        out["risk"] = "SINGLE KEY — one private key compromise is total control"
        return out
    # it's a contract. multisig?
    thr = _cast(rpc, addr, "getThreshold()(uint256)")
    owners = _cast(rpc, addr, "getOwners()(address[])")
    if thr and owners:
        out["kind"] = "gnosis_safe"
        n = owners.count("0x")
        out["detail"] = {"threshold": thr, "owners": _parse_addr_list(owners), "n_owners": n}
        out["risk"] = f"{thr}-of-{n} multisig — needs {thr} signer keys"
        return out
    # timelock?
    delay = _cast(rpc, addr, "getMinDelay()(uint256)") or _cast(rpc, addr, "delay()(uint256)")
    if delay:
        out["kind"] = "timelock"
        out["detail"] = {"delay_seconds": delay}
        out["risk"] = f"timelock, delay={delay}s — changes are observable & exit-able"
        return out
    # unknown contract — note if it exposes a generic forwarder (execute(address,bytes))
    out["kind"] = "contract"
    out["risk"] = "custom controller — resolve its own owner()/admin() next hop"
    return out


def _parse_addr_list(s: str) -> list[str]:
    return re.findall(r"0x[0-9a-fA-F]{40}", s)


def resolve_role(rpc: str, target: str, role: str, max_hops: int = 4) -> dict:
    """Follow a role pointer hop-by-hop to the address that really holds the power,
    classifying every hop. e.g. Nullmask -> upgradeController(admin) -> safe."""
    chain = []
    cur = target
    getter = f"{role}()(address)"
    seen = set()
    for _ in range(max_hops):
        nxt = _cast(rpc, cur, getter)
        if not nxt:
            break
        nxt = _parse_addr_list(nxt)
        if not nxt:
            break
        a = nxt[0]
        if a.lower() in seen or a == "0x0000000000000000000000000000000000000000":
            break
        seen.add(a.lower())
        cls = classify_address(rpc, a)
        chain.append({"via": getter, "resolved": a, **cls})
        if cls["kind"] in ("gnosis_safe", "timelock", "eoa"):
            break
        # unknown contract: try to walk its own admin()/owner() next
        getter = "admin()(address)"
        probe = _cast(rpc, a, getter)
        if not probe:
            getter = "owner()(address)"
            if not _cast(rpc, a, getter):
                break
        cur = a
    return {"role": role, "hops": chain}


def _source_blob(src_root: str, source_keys: list[str]) -> str:
    blob = []
    root = Path(src_root)
    for k in (source_keys or []):
        p = root / k
        if p.exists():
            try: blob.append(p.read_text(errors="ignore"))
            except Exception: pass
    if not blob:  # single-file fallback
        for p in root.rglob("*.sol"):
            try: blob.append(p.read_text(errors="ignore"))
            except Exception: pass
    return "\n".join(blob)


def analyze_composition(target: str, src_root: str, source_keys: list[str],
                        chain: str = "ethereum") -> dict:
    """Full attack-graph recon for one target: trust graph + external surfaces +
    staged multi-contract break scenarios. Honest about what is a bug vs a trust risk."""
    rpc = os.environ.get(RPC_ENV.get(chain, "ETH_ARCHIVE_RPC"), "")
    src = _source_blob(src_root, source_keys)

    # 1. privileged functions and their gates
    powers = []
    for m in RE_FUNC.finditer(src):
        name, _args, _vis, body = m.group(1), m.group(2), m.group(3), m.group(4)
        gate = GATE_CALLS.search(body)
        if gate:
            powers.append({"fn": name, "gate": gate.group(0),
                           "fund_critical": bool(FUND_CRITICAL.search(name))})

    # 2. role terminals (resolved on-chain)
    roles_in_src = sorted({g.group(1) for g in RE_ROLE_GETTER.finditer(src)}, key=str.lower)
    resolved = {}
    if rpc:
        for role in roles_in_src:
            r = resolve_role(rpc, target, role)
            if r["hops"]:
                resolved[role] = r

    # 3. external value/price surfaces
    surfaces = {
        "router_swap": bool(RE_ROUTER.search(src)),
        "oracle_price": bool(RE_ORACLE.search(src)),
        "snark_verifier": bool(RE_VERIFIER.search(src)),
    }

    # 4. weaknesses
    weaknesses = []
    # 4a. fund-critical power with no timelock terminal
    terminals = {role: r["hops"][-1] for role, r in resolved.items() if r["hops"]}
    has_timelock = any(t["kind"] == "timelock" for t in terminals.values())
    fund_powers = [p["fn"] for p in powers if p["fund_critical"]]
    if fund_powers and not has_timelock and terminals:
        weaknesses.append({
            "class": "no_timelock_on_fund_critical",
            "severity": "high-trust",
            "detail": f"fund-critical powers {sorted(set(fund_powers))[:8]} resolve to an "
                      f"admin with NO timelock -> changes are instant & silent (no exit window)",
        })
    # 4b. bare EOA terminal on a fund-critical gate
    for role, t in terminals.items():
        if t["kind"] == "eoa":
            weaknesses.append({
                "class": "eoa_terminal",
                "severity": "high-trust",
                "detail": f"role `{role}` terminates at a plain EOA {t['address']} — "
                          f"one key compromise controls it",
            })
    # 4c. key reused across two tiers (same address holds two roles / is a safe signer)
    addr_roles: dict[str, list[str]] = {}
    for role, t in terminals.items():
        addr_roles.setdefault(t["address"], []).append(role)
    safe_signers = set()
    for role, t in terminals.items():
        if t["kind"] == "gnosis_safe":
            safe_signers |= {o.lower() for o in t["detail"].get("owners", [])}
    for addr, rs in addr_roles.items():
        if len(rs) > 1:
            weaknesses.append({"class": "key_reuse_multi_role", "severity": "medium-trust",
                               "detail": f"{addr} holds multiple roles {rs} — one key, two tiers"})
        if addr in safe_signers:
            weaknesses.append({"class": "hot_key_is_cold_signer", "severity": "medium-trust",
                               "detail": f"{addr} (role {rs}) is ALSO a signer on the admin "
                                         f"multisig — a warm hot-key doing cold-key duty"})
    # 4d. external route with caller params (keyless composition)
    if surfaces["router_swap"]:
        weaknesses.append({
            "class": "external_price_route",
            "severity": "keyless-composition",
            "detail": "value is routed through an external swap router with caller-chosen "
                      "path/minOut -> flash-loan-skew the pool the swap traverses and let the "
                      "target execute against it (bounded by the user's minOut floor)",
        })
    if surfaces["oracle_price"]:
        weaknesses.append({
            "class": "external_oracle_read",
            "severity": "keyless-composition",
            "detail": "a price/collateral/mint path reads an external oracle -> if it reads a "
                      "spot/AMM reserve, flash-loan-move it within one tx",
        })

    # 5. trust-delegation seams (where value conservation leaves the Solidity)
    seams = trust_delegation(src)

    # 6. staged chains
    chains = _build_chains(target, powers, terminals, surfaces, has_timelock)

    return {
        "target": target, "chain": chain, "rpc_available": bool(rpc),
        "powers": powers, "roles": resolved, "surfaces": surfaces,
        "weaknesses": weaknesses, "trust_delegation": seams, "attack_chains": chains,
        "summary": _summary(target, terminals, has_timelock, weaknesses, chains, seams),
    }


# Where does the contract STOP enforcing value conservation itself and delegate it to an
# unverifiable component? Those seams are the only places left to attack once the plumbing
# is balance-delta'd and audited. This is the meta-lesson: find the trust boundary.
RE_BALANCE_DELTA = re.compile(r"balanceAfter\s*-\s*balanceBefore|balanceOf\([^)]*\)\s*-\s*\w*[Bb]efore|"
                              r"after\s*-\s*before", re.I)
RE_VERIFIER_TRUST = re.compile(r"_verifyProof|verifier\.verify|verifyProof", re.I)
RE_ANY_ROOT = re.compile(r"isKnownRoot|any historical root|ever had this root", re.I)


def trust_delegation(src: str) -> list[dict]:
    """Map the points where on-chain value conservation is HANDED OFF to something the
    Solidity cannot check: a zk circuit, a balance-delta measurement, an accepted-forever
    root. These are the real residual attack surface of a well-built protocol."""
    seams = []
    if RE_VERIFIER_TRUST.search(src):
        seams.append({
            "seam": "value_conservation_delegated_to_circuit",
            "note": "note/share values are credited/spent against an external SNARK verifier; "
                    "the contract does NOT (and cannot) check amountIn <= spent-note on-chain. "
                    "Entire solvency rests on the circuit binding every public input. If the "
                    "verifier is an immutable blob with no public circuit, this is UNAUDITABLE "
                    "from bytecode -> that unauditability is itself the finding.",
            "where_to_hunt": "the circuit (constraint-completeness), not the Solidity",
        })
    if RE_BALANCE_DELTA.search(src):
        seams.append({
            "seam": "balance_delta_measurement",
            "note": "an amount is measured as a pool balance delta (handles fee-on-transfer, "
                    "but trusts that nothing else moves that token between the two reads). "
                    "Attack only if a transfer hook / reentrancy can inflate the delta with "
                    "value the attacker does not themselves supply (usually a wash -> not a drain).",
            "where_to_hunt": "token transfer hooks on whitelisted tokens + reentrancy guard scope",
        })
    if RE_ANY_ROOT.search(src):
        seams.append({
            "seam": "any_historical_root_accepted",
            "note": "withdrawals accept any root the tree ever had; double-spend is stopped ONLY "
                    "by the nullifier set. Correct IF nullifier marking is atomic & pre-transfer. "
                    "Breaks catastrophically if a verifier swap/upgrade lets a forged proof pass.",
            "where_to_hunt": "nullifier write-before-transfer + the verifier-swap admin path",
        })
    return seams


def _build_chains(target, powers, terminals, surfaces, has_timelock) -> list[dict]:
    chains = []
    admin_t = None
    for role in ("upgradeController", "admin", "owner", "governance"):
        if role in terminals:
            admin_t = (role, terminals[role]); break
    # Chain: admin -> swap verifier/upgrade -> drain
    if surfaces["snark_verifier"] and admin_t:
        role, t = admin_t
        chains.append({
            "name": "admin_verifier_swap_drain",
            "needs_key": t["risk"],
            "timelock": "NONE — instant & silent" if not has_timelock else "delayed/observable",
            "stages": [
                f"1. obtain admin authority ({role} -> {t['kind']}: {t['risk']})",
                "2. admin -> setVerifiers(evilVerifier)  [or upgradeToAndCall to a backdoor impl]",
                "3. evilVerifier accepts any proof",
                "4. withdraw with a known historical root + fresh attacker nullifiers -> drains pool",
                "5. exit AS a shielded withdrawal — the privacy layer launders the theft",
            ],
            "verdict": "total drain IF admin keys obtained; not a protocol bug — trust/centralization. "
                       "A timelock is the one change that converts this to an exit-able window.",
        })
    # Chain: keyless swap sandwich via external route
    if surfaces["router_swap"]:
        chains.append({
            "name": "keyless_swap_price_shave",
            "needs_key": "none (keyless) — plus a thin-pair token on the whitelist",
            "stages": [
                "1. (if needed) a whitelist key adds a token with a thin external pair",
                "2. flash-loan-skew that pair's price",
                "3. a shielded/pool swap routing through it clears the victim's pre-skew minOut at a bad price",
                "4. restore the pair; pocket the delta out of pool funds",
            ],
            "verdict": "bounded by the user's minOut floor + private relayer mempool = MEV shave, "
                       "not an unbounded drain. Real if the relayer leaks txs to the public mempool.",
        })
    return chains


def _summary(target, terminals, has_timelock, weaknesses, chains, seams=None) -> str:
    lines = [f"COMPOSITION / ATTACK-GRAPH — {target}"]
    if terminals:
        lines.append("Trust terminals (who really holds each power):")
        for role, t in terminals.items():
            lines.append(f"  {role:18s} -> {t['address']}  [{t['kind']}] {t.get('risk','')}")
    lines.append(f"Timelock on fund-critical powers: {'YES' if has_timelock else 'NO'}")
    if weaknesses:
        lines.append("Composition weaknesses:")
        for w in weaknesses:
            lines.append(f"  [{w['severity']}] {w['class']}: {w['detail']}")
    if seams:
        lines.append("Trust-delegation seams (where value conservation leaves the Solidity):")
        for s in seams:
            lines.append(f"  - {s['seam']}: hunt -> {s['where_to_hunt']}")
    lines.append(f"Staged attack chains: {len(chains)}")
    for c in chains:
        lines.append(f"  * {c['name']} — {c['verdict'][:90]}")
    return "\n".join(lines)
