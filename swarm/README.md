# Cyber Swarm — a live 5-agent exploit team you can watch and steer

Five AI agents work as an adversarial security team on a never-ending stream of smart contracts,
asking one question — **"how can this be drained?"** — and **nothing counts as a finding until a
Foundry PoC actually drains a mainnet fork.** You watch them argue live and chat in to steer them.

```
RECON ──► ATTACKER ──► SKEPTIC ──► EXPLOIT_DEV ──► REFEREE(prover)
 maps       finds        kills        writes          proves on a
 trust      the drain    fake finds   the PoC          real fork ✔/✘
 graph
```

- **Grounded, not hallucinating:** the SKEPTIC kills bad hypotheses; the REFEREE only accepts a
  bug it watched drain a fork. No fork-proof → not a finding.
- **Tireless at the pipeline level:** each target is budget-boxed (calls + time); no proven bug →
  logged, move to the next. It hunts target after target forever until you stop it.
- **5 different free models** (via KiloCode) so the agents genuinely disagree and rate limits spread.
- **Auto targets:** DefiLlama fresh-low-TVL feed + Immunefi in-scope, plus anything you queue in the UI.
- Uses the existing engine (`compose`, `heuristics`, `fetch_source`, `prover`) as the team's tools.

---

## Deploy on the Frankfurt VPS (Ubuntu)

### 1. Prereqs
```bash
sudo apt update && sudo apt install -y python3-venv python3-pip git curl
# Foundry (forge/cast) — the Referee needs it to prove PoCs on a fork
curl -L https://foundry.paradigm.xyz | bash && ~/.foundry/bin/foundryup
```

### 2. Get the code + install
```bash
git clone https://github.com/sickpyramid/cyber-engine.git
cd cyber-engine
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt            # engine deps (slither, solc-select, requests)
pip install -r swarm/requirements.txt      # server deps (fastapi, uvicorn, httpx, websockets)
bash scripts/build_corpus.sh               # builds data/corpus.sqlite (historical attacks)
# DeFiHackLabs vendor (for the prover's fork harness) — see HANDOFF.md if not present
```

### 3. Configure secrets (never commit these)
```bash
cp swarm/.env.example swarm/.env
nano swarm/.env     # fill KILOCODE_API_KEY, ETH_ARCHIVE_RPC, BSC_ARCHIVE_RPC, ETHERSCAN_API_KEY
```
> ⚠ **Rotate every key that was ever pasted in plaintext** (KiloCode JWT, QuickNode token). The
> `.env` lives only on the VPS and is gitignored.

### 4. Run
```bash
set -a; source swarm/.env; set +a
uvicorn swarm.server:app --host 0.0.0.0 --port 8080
```
Open `http://<vps-ip>:8080` → press **START HUNT**. You'll see the 5 agents work live.

### 5. Run it as a service (stays up)
`/etc/systemd/system/cyberswarm.service`:
```ini
[Unit]
Description=Cyber Swarm
After=network.target
[Service]
WorkingDirectory=/root/cyber-engine
EnvironmentFile=/root/cyber-engine/swarm/.env
ExecStart=/root/cyber-engine/.venv/bin/uvicorn swarm.server:app --host 0.0.0.0 --port 8080
Restart=always
[Install]
WantedBy=multi-user.target
```
```bash
sudo systemctl daemon-reload && sudo systemctl enable --now cyberswarm
journalctl -u cyberswarm -f      # live logs
```

### 6. Point icedeal.fun at it (replace the DeepSeek harness)
Nginx reverse proxy with WebSocket upgrade:
```nginx
server {
  server_name icedeal.fun;
  location / {
    proxy_pass http://127.0.0.1:8080;
    proxy_http_version 1.1;
    proxy_set_header Upgrade $http_upgrade;       # WebSocket
    proxy_set_header Connection "upgrade";
    proxy_set_header Host $host;
    proxy_read_timeout 86400;
  }
}
```
```bash
sudo certbot --nginx -d icedeal.fun    # TLS (wss:// works automatically once https is on)
```

---

## Using the UI
- **START HUNT** — begins the auto-pipeline (Immunefi + DefiLlama feed).
- **Queue a target** (right panel) — paste any contract address to jump the queue.
- **Chat box** — talk to the team mid-hunt: "focus on the swap path", "check the keeper bound",
  "that's just MEV, move on". Your message reaches every agent on their next turn as the TEAM LEAD.
- **Pause / Stop** — safety controls. Findings (fork-proven only) appear in the right panel.

## Safety & cost
- All models default to **free** KiloCode routes (`cost: 0`). The rails in `.env`
  (`SWARM_MIN_CALL_INTERVAL`, `SWARM_MAX_CALLS_PER_*`) throttle usage and cap the blast radius.
- Every exploit runs on a **local fork**, never mainnet. This is authorized research tooling.
- Treat proven findings as leads for **responsible disclosure / bug bounty submission**, not action.

## Architecture
| file | role |
|---|---|
| `config.py` | env-driven config; per-role model routing; safety rails |
| `kilo.py` | KiloCode OpenAI-compatible async client (rate-limited, reasoning-aware) |
| `roles.py` | the 5 role system prompts (grounded in the engine's reasoning protocol) |
| `tools.py` | runs engine tools (`compose`/`heuristics`/`source`/`prove`) on agent `CALL:` lines |
| `orchestrator.py` | the per-target debate loop + prover-as-referee + budgets + pipeline |
| `targets.py` | auto target feed (DefiLlama + Immunefi) + manual queue |
| `server.py` | FastAPI + WebSocket: serves UI, streams events, takes your chat/controls |
| `ui/index.html` | the live dark security dashboard |
