"""The swarm orchestrator — runs the 5-agent security team on a stream of targets.

Design that keeps it honest (not a hallucination loop):
  - The fork-PROVER is the referee. A target yields a FINDING only when a PoC drains a fork.
  - Each target is budget-boxed (calls + wall-clock). No proven bug -> log it, move to the next.
  - "Never stop" lives at the PIPELINE level: the swarm hunts target after target forever until
    the user stops it. It does not loop forever on one dead contract.
  - The user can inject messages any time; agents see them on their next turn.

Everything is streamed to the UI via the `emit` callback as event dicts.
"""
from __future__ import annotations
import asyncio, time, json, tempfile
from pathlib import Path
from . import config, kilo, roles, tools


class Swarm:
    def __init__(self, emit):
        self.emit = emit                      # async callback(event: dict)
        self.running = False
        self.paused = False
        self.target = None                    # current {chain, address, name}
        self.blackboard: list[dict] = []      # [{role, content, ts}]
        self.user_msgs: list[str] = []
        self.findings: list[dict] = []
        self.stats = {"targets": 0, "calls": 0, "findings": 0}
        self._stop = asyncio.Event()

    # ── event helpers ────────────────────────────────────────────────────────
    async def _ev(self, type_, **kw):
        await self.emit({"type": type_, "ts": time.time(), **kw})

    async def _post(self, role, content):
        entry = {"role": role, "content": content, "ts": time.time()}
        self.blackboard.append(entry)
        await self._ev("message", role=role, content=content,
                       target=self.target, stats=self.stats)

    def inject(self, msg: str):
        self.user_msgs.append(msg)

    def stop(self):
        self.running = False
        self._stop.set()

    # ── context building ─────────────────────────────────────────────────────
    def _context(self, role: str) -> list[dict]:
        sys = roles.ROLES[role]
        # last ~16 blackboard entries, trimmed
        recent = self.blackboard[-16:]
        convo = []
        for e in recent:
            tag = f"[{e['role']}]"
            c = e["content"]
            convo.append(f"{tag} {c[:1400]}")
        # fold in any pending user messages as high-priority guidance
        inj = ""
        if self.user_msgs:
            inj = "\n\n[TEAM LEAD (the human watching) just said]:\n" + "\n".join(self.user_msgs)
            self.user_msgs = []
        t = self.target or {}
        user = (f"CURRENT TARGET: {t.get('name','?')} on {t.get('chain')} at {t.get('address')}\n\n"
                f"Team conversation so far:\n" + "\n\n".join(convo) + inj +
                f"\n\nYou are {role}. Take your turn now.")
        return [{"role": "system", "content": sys}, {"role": "user", "content": user}]

    # ── one agent turn ───────────────────────────────────────────────────────
    async def _turn(self, role: str, workdir: Path) -> str:
        await self._ev("thinking", role=role, target=self.target)
        try:
            res = await kilo.chat(self._context(role), model=config.role_model(role))
        except kilo.DailyCapReached as e:
            await self._ev("system", content=f"daily cap reached: {e}; pausing")
            self.paused = True
            return ""
        except Exception as e:
            await self._post(role, f"[model error: {e}]")
            return ""
        self.stats["calls"] = kilo.calls_today()
        content = res["content"] or "[empty]"
        await self._post(role, content)

        # execute any engine tool calls the agent emitted
        for tool, args in tools.find_calls(content):
            if tool == "prove" and role != "REFEREE":
                continue  # only the referee proves
            await self._ev("tool", role=role, tool=tool, args=args, target=self.target)
            out = await tools.execute(tool, args, workdir)
            await self._post("ENGINE", f"({tool} {args}) ->\n{out}")
        return content

    # ── hunt one target to resolution or budget ──────────────────────────────
    async def hunt_target(self, target: dict):
        self.target = target
        self.blackboard = []
        self.stats["targets"] += 1
        workdir = Path(tempfile.mkdtemp(prefix="swarm_"))
        await self._ev("target_start", target=target, stats=self.stats)
        await self._post("SYSTEM", f"New target: {target['name']} ({target['chain']} {target['address']}). "
                                   f"Team question: HOW CAN THIS BE DRAINED?")

        start = time.time()
        calls0 = kilo.calls_today()
        lim = config.LIMITS

        # Recon always opens.
        await self._turn("RECON", workdir)

        found = False
        round_i = 0
        while self.running and not self._stop.is_set():
            # budget checks
            if time.time() - start > lim.max_seconds_per_target:
                await self._post("SYSTEM", "time budget exhausted for this target."); break
            if kilo.calls_today() - calls0 > lim.max_calls_per_target:
                await self._post("SYSTEM", "call budget exhausted for this target."); break
            while self.paused and self.running:
                await asyncio.sleep(5)

            round_i += 1
            await self._ev("round", n=round_i, target=target)

            await self._turn("ATTACKER", workdir)
            await self._turn("SKEPTIC", workdir)
            dev_out = await self._turn("EXPLOIT_DEV", workdir)

            # if the dev shipped a PoC, save it and let the Referee prove it
            poc = tools.extract_poc(dev_out)
            if poc:
                (workdir / "attempt.sol").write_text(poc)
                await self._ev("poc", target=target, size=len(poc))
                ref_out = await self._turn("REFEREE", workdir)
                # the Referee's prove tool output is already posted as ENGINE; detect success
                joined = "\n".join(e["content"] for e in self.blackboard[-4:])
                if "PASS" in joined and ("profit" in joined.lower() or "proven" in joined.lower()
                                         or "CONFIRMED" in ref_out.upper()):
                    found = True
                    finding = {"target": target, "poc": poc,
                               "summary": ref_out[:1200], "ts": time.time()}
                    self.findings.append(finding)
                    self.stats["findings"] += 1
                    await self._ev("finding", finding=finding, stats=self.stats)
                    await self._post("SYSTEM", "✅ CONFIRMED FINDING — proven on fork. Logged.")
                    break

        if not found:
            await self._post("SYSTEM", f"No proven drain on {target['name']}. Logged; moving on.")
            await self._ev("target_done", target=target, found=False, stats=self.stats)
        else:
            await self._ev("target_done", target=target, found=True, stats=self.stats)

    # ── the pipeline: hunt forever across the target stream ───────────────────
    async def run(self, target_source):
        self.running = True
        self._stop.clear()
        await self._ev("swarm_start", stats=self.stats)
        try:
            async for target in target_source():
                if not self.running or self._stop.is_set():
                    break
                try:
                    await self.hunt_target(target)
                except Exception as e:
                    await self._ev("system", content=f"target error: {e}")
        finally:
            self.running = False
            await self._ev("swarm_stop", stats=self.stats)
