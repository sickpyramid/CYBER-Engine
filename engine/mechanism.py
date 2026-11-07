"""Mechanism reverse-engineering + adversarial hypothesis generation.

This is the layer static analysis can't do. It reads a contract into a structured
Protocol Model (archetype, state roles, authority, external dependencies, price
sources) and then reasons ADVERSARIALLY — for each economic assumption, "how do I
make this false?" — emitting ranked attack hypotheses with multi-stage paths.

It catches the classes Slither is blind to: flashloan-funded oracle manipulation,
share-inflation, unprotected init/upgrade, missing authority — because those are
semantic/economic properties, not code smells.

Static only (Slither IR). Subprocess-runnable:
    python engine/mechanism.py <src_root> <solc> <keys.json>
"""
from __future__ import annotations
import subprocess, json, os, sys, re
from pathlib import Path

# High-precision price-read signatures scanned directly in source (reliable across
# Slither API versions, and catches reads via external interfaces).
PRICE_READ_RE = re.compile(
    r"\.(getReserves|slot0|getAmountsOut|getAmountOut|latestAnswer|latestRoundData"
    r"|getUnderlyingPrice|price0CumulativeLast|price1CumulativeLast|consult|get_dy"
    r"|calc_withdraw_one_coin|getPrice|peek|read)\s*\(", re.I)
TWAP_RE = re.compile(r"twap|cumulative|observe|timeweighted", re.I)

# ---- attacker heuristics: signatures that betray a manipulable price source ----
SPOT_PRICE_SIGS = ("getreserves", "slot0", "getamountsout", "getamountout",
                   "price0cumulativelast", "price1cumulativelast", "balanceof",
                   "getunderlyingprice", "latestanswer", "consult", "quote",
                   "get_dy", "calc_withdraw_one_coin", "totalsupply")  # when used in pricing
TWAP_HINT = ("twap", "cumulative", "observe", "consult")
FLASHLOAN_SRC = ("flashloan", "flash", "flashswap", "uniswapv2call", "executeoperation",
                 "receiveflashloan", "pancakecall")
VAULT_FNS = {"deposit", "mint", "withdraw", "redeem", "totalassets", "converttoshares",
             "converttoassets", "previewdeposit", "previewredeem"}
LENDING_FNS = {"borrow", "repay", "liquidate", "liquidateborrow", "redeem", "mint",
               "accrueinterest", "exchangerate", "seize"}
AMM_FNS = {"swap", "addliquidity", "removeliquidity", "mint", "burn", "skim", "sync", "getreserves"}
BRIDGE_FNS = {"deposit", "withdraw", "relay", "processmessage", "claim", "verify", "mintwithproof"}
GOV_FNS = {"propose", "castvote", "execute", "queue", "delegate"}
SENSITIVE_WRITE_FNS = ("mint", "burn", "setowner", "transferownership", "setprice",
                       "setoracle", "upgrade", "initialize", "withdraw", "setfee",
                       "setadmin", "grantrole", "rescue", "sweep", "emergency")
AUTH_MODIFIERS = ("onlyowner", "onlyadmin", "onlygovernance", "onlyrole", "auth",
                  "restricted", "onlyoperator", "owneronly", "onlyguardian")


def _slither(src_root, solc, keys):
    artifacts = Path.home() / ".solc-select" / "artifacts" / f"solc-{solc}" if solc else None
    env = dict(os.environ, PATH=f"{Path.home()/'.local/bin'}:{os.environ.get('PATH','')}")
    if solc and artifacts and not artifacts.exists():
        subprocess.run(["solc-select", "install", solc], capture_output=True, env=env, timeout=400)
    if solc:
        os.environ["SOLC_VERSION"] = solc
    from crytic_compile import CryticCompile
    from crytic_compile.platform.solc_standard_json import SolcStandardJson
    from slither import Slither
    cwd = os.getcwd()
    os.chdir(src_root)
    try:
        std = SolcStandardJson()
        for k in keys:
            if Path(k).exists():
                std.add_source_file(k)
        return Slither(CryticCompile(std, solc="solc")), cwd
    except Exception:
        os.chdir(cwd)
        raise


def build_model(sl) -> dict:
    model = {"archetypes": [], "entry_points": [], "state_vars": [],
             "price_sources": [], "external_calls": [], "callbacks": [],
             "unprotected_sensitive": [], "has_initializer_guard": False}
    fn_names_all = set()
    for c in sl.contracts_derived:
        if c.is_interface or c.is_library:
            continue
        for v in c.state_variables:
            model["state_vars"].append({"name": v.name, "type": str(v.type)})
        for f in c.functions_entry_points:
            if f.is_constructor:
                continue
            name = (f.name or "").lower()
            fn_names_all.add(name)
            mods = [m.name.lower() for m in f.modifiers]
            if any(a in m for m in mods for a in AUTH_MODIFIERS):
                protected = True
            else:
                protected = any(a in name for a in ("onlyowner",))  # rare inline
            # external call signatures this fn reaches
            sigs = []
            try:
                for (_c, callee) in f.all_high_level_calls():
                    cn = getattr(callee, "name", "") or ""
                    sigs.append(cn.lower())
            except Exception:
                pass
            reads_price = any(any(s in sig for sig in sigs) for s in SPOT_PRICE_SIGS)
            writes = [sv.name for sv in f.state_variables_written]
            makes_ext = bool(sigs) or bool(f.low_level_calls)
            ep = {"fn": f.name, "visibility": f.visibility, "modifiers": mods,
                  "protected": protected, "reads_price": reads_price,
                  "writes": writes[:8], "ext_call": makes_ext}
            model["entry_points"].append(ep)
            if reads_price:
                model["price_sources"].extend([s for s in sigs if any(p in s for p in SPOT_PRICE_SIGS)])
            # unprotected + sensitive state change
            if (not protected and f.visibility in ("public", "external")
                    and any(k in name for k in SENSITIVE_WRITE_FNS) and writes):
                model["unprotected_sensitive"].append({"fn": f.name, "writes": writes[:6]})
            # callback / reentrancy surface: external call followed by state write
            if makes_ext and writes:
                model["callbacks"].append(f.name)
            if "initializer" in mods or "reinitializer" in mods:
                model["has_initializer_guard"] = True
    # archetype inference
    def hit(s): return len(fn_names_all & s)
    arche = []
    if hit(AMM_FNS) >= 2: arche.append("amm")
    if hit(LENDING_FNS) >= 2: arche.append("lending")
    if hit(VAULT_FNS) >= 2: arche.append("vault")
    if hit(BRIDGE_FNS) >= 2: arche.append("bridge")
    if hit(GOV_FNS) >= 2: arche.append("governance")
    model["archetypes"] = arche
    model["price_sources"] = sorted(set(model["price_sources"]))
    return model


def hypotheses(model: dict) -> list[dict]:
    """Adversarial reasoning: turn the model into ranked attack hypotheses."""
    H = []
    arche = set(model["archetypes"])
    # A spot read (getReserves/slot0/...) is manipulable even if the pair interface also
    # declares cumulative accumulators. Only down-weight if the read itself is time-weighted.
    spot = [s for s in model["price_sources"]
            if s in ("getreserves", "slot0", "getamountsout", "getamountout",
                     "latestanswer", "getunderlyingprice", "get_dy", "getprice", "peek")]

    # 1) Spot-price oracle -> flashloan oracle manipulation (the #1 blind spot)
    if spot:
        pricing_fns = [e["fn"] for e in model["entry_points"] if e["reads_price"]]
        H.append({
            "vuln_class": "price_oracle_manip", "confidence": 0.8,
            "evidence": f"spot price read from {model['price_sources']} in {pricing_fns[:3]}",
            "attack_path": [
                "flashloan a large amount of one asset",
                f"skew the pool/reserve the price is read from ({model['price_sources'][:2]})",
                f"invoke {pricing_fns[:1]} while price is distorted to mint/borrow/withdraw excess value",
                "unwind the skew and repay the flashloan, keeping the difference",
            ],
            "multi_stage": True,
        })
        # flashloan is the funding vector for the same bug
        H.append({"vuln_class": "flashloan_assisted", "confidence": 0.55,
                  "evidence": "manipulable single-block price in an accounting path",
                  "attack_path": ["flashloan bootstrap capital", "distort price", "extract", "repay"],
                  "multi_stage": True})

    # 2) Vault / lending share accounting -> first-depositor / inflation
    if arche & {"vault", "lending"}:
        H.append({
            "vuln_class": "first_depositor", "confidence": 0.45,
            "evidence": f"share-based {list(arche & {'vault','lending'})} accounting with external price/asset reads",
            "attack_path": [
                "be the first depositor with 1 wei to mint minimal shares",
                "donate/transfer assets directly to inflate assets-per-share",
                "later depositors' deposits round down to 0 shares; redeem to steal their assets",
            ],
            "multi_stage": True,
        })

    # 3) Unprotected sensitive functions -> access control
    for u in model["unprotected_sensitive"][:4]:
        H.append({
            "vuln_class": "access_control", "confidence": 0.7,
            "evidence": f"public/external {u['fn']} changes {u['writes']} with no auth modifier",
            "attack_path": [f"call {u['fn']} directly", "no owner/role check gates it",
                            "take ownership / mint / drain via the unguarded state change"],
            "multi_stage": False,
        })

    # 4) Unguarded initializer / upgrade -> proxy takeover
    init_fns = [e for e in model["entry_points"]
                if "initialize" in (e["fn"] or "").lower() and not e["protected"]]
    if init_fns and not model["has_initializer_guard"]:
        H.append({
            "vuln_class": "proxy_upgrade", "confidence": 0.65,
            "evidence": f"initialize() {[i['fn'] for i in init_fns]} lacks an initializer guard",
            "attack_path": ["front-run or re-call initialize()", "set yourself as owner/admin",
                            "upgrade implementation or drain via owner powers"],
            "multi_stage": True,
        })

    # 5) Reentrancy surface (ext call before state write) — complements Slither
    if model["callbacks"]:
        H.append({
            "vuln_class": "reentrancy", "confidence": 0.5,
            "evidence": f"state written after external call in {model['callbacks'][:4]}",
            "attack_path": ["enter via a callback token/hook during the external call",
                            "re-enter before state updates", "drain across the stale state window"],
            "multi_stage": True,
        })

    H.sort(key=lambda h: h["confidence"], reverse=True)
    return H


def analyze(src_root, source_keys, solc=None) -> dict:
    sl, cwd = _slither(src_root, solc, source_keys)
    try:
        model = build_model(sl)
    finally:
        os.chdir(cwd)
    # reliable source-text scan for price reads (fixes Slither call-extraction gaps,
    # and catches reads via external interfaces the IR walk misses)
    src_text = ""
    for k in source_keys:
        p = Path(src_root) / k
        if p.exists():
            src_text += p.read_text(errors="replace") + "\n"
    scanned = sorted({m.group(1).lower() for m in PRICE_READ_RE.finditer(src_text)})
    model["price_sources"] = sorted(set(model["price_sources"]) | set(scanned))
    model["_has_twap"] = bool(TWAP_RE.search(src_text))
    H = hypotheses(model)
    return {"ok": True, "archetypes": model["archetypes"],
            "price_sources": model["price_sources"],
            "predicted_classes": [h["vuln_class"] for h in H],
            "hypotheses": H, "model_summary": {
                "n_entry_points": len(model["entry_points"]),
                "n_price_reads": sum(e["reads_price"] for e in model["entry_points"]),
                "n_unprotected_sensitive": len(model["unprotected_sensitive"]),
                "n_callbacks": len(model["callbacks"])}}


if __name__ == "__main__":
    src_root, solc, keys_file = sys.argv[1], (sys.argv[2] or None), sys.argv[3]
    keys = json.load(open(keys_file))
    try:
        print(json.dumps(analyze(src_root, keys, solc)))
    except Exception as e:
        print(json.dumps({"ok": False, "error": f"{type(e).__name__}: {e}",
                          "predicted_classes": [], "hypotheses": []}))
