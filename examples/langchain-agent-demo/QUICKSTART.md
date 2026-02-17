# Quick Start — Phased Governance Demo

## One-time setup

```bash
cd kakveda-v1.0/examples/langchain-agent-demo
python3 -m venv .venv
. .venv/bin/activate
pip install -q -r requirements.txt
```

## Run Phase 1: Standalone Agent

**Goal:** Verify agent works without any external dependencies.

```bash
. .venv/bin/activate
python agent_app_phase1.py --platform linkedin --topic "AI growth" --no-governance
```

**Expected output:**
```
[PLATFORM] linkedin
[AGENT GENERATED CONTENT] Sharing a short product update...
[MOCK POST SUCCESS] Platform: Linkedin
[DONE] elapsed=0.00s
```

✅ **Phase 1 validates:** Agent generates content and executes mock post independently.

---

## Run Phase 2: Governance Layer (Standalone Mode)

**Goal:** Verify Phase 2 agent works without Kakveda (backward compatible).

```bash
python agent_app.py --platform linkedin --topic "AI growth" --no-governance
```

**Same output as Phase 1** (governance disabled).

✅ **Phase 2 validates:** Equivalent to Phase 1, but ready for Kakveda integration.

---

## Run Phase 2: With Risky Content (Standalone)

**Test how agent handles risky topics:**

```bash
python agent_app.py --platform twitter --topic exaggerated --no-governance
```

**Expected:**
```
[AGENT GENERATED CONTENT] AI tool usage grew 900% in 1 week.
[MOCK POST SUCCESS] Platform: Twitter
```

✅ **Risky content test:** Without governance, risky posts execute (as designed).

---

## Run Phase 2: With Kakveda (When Available)

**Prerequisites:** Kakveda /warn endpoint must be available at `http://localhost:8105/warn`

```bash
python agent_app.py --platform linkedin --topic "safe content"
```

**Expected output** (with governance enabled):
```
[GOVERNANCE] enabled
[KAKVEDA] preflight: action=silent confidence=0.12
[MOCK POST SUCCESS] Platform: Linkedin
```

✅ **Phase 2 governance:** Kakveda validates content before execution.

---

## Managed Agent Mode (Dashboard + Heartbeat + Event Bus)

This mode uses `KakvedaAgent` to register the agent in the dashboard, send heartbeats, and publish traces.

### Required environment variables

- `KAKVEDA_WARN_URL=http://warning-policy:8105/warn`
- `KAKVEDA_EVENT_BUS_URL=http://event-bus:8100/publish`
- `DASHBOARD_URL=http://dashboard:8110`
- `DASHBOARD_API_KEY=<project-api-key>`
- `AGENT_NAME=langchain-social-agent`
- `AGENT_APP_ID=langchain-social-agent`
- `AGENT_VERSION=1.0.0`
- `HEARTBEAT_INTERVAL=15`

### Run

```bash
python agent_app.py --platform linkedin --topic "AI growth"
```

### Expected results

- Agent appears in **Dashboard → Agents**
- `GET /health` responds on `http://localhost:8120/health` (if running locally)
- `trace.ingested` events appear in the dashboard Runs/Traces

---

## Test All Three Platforms

```bash
python agent_app.py --platform linkedin --topic "AI growth" --no-governance
python agent_app.py --platform twitter --topic "AI growth" --no-governance
python agent_app.py --platform instagram --topic "AI growth" --no-governance
```

---

## Cleanup

```bash
deactivate
rm -rf .venv __pycache__
```

---

## Demo Talking Points

| Phase | What | How | Why |
|-------|------|-----|-----|
| 1 | Agent works alone | No external calls | Proves foundation |
| 2 (no-gov) | Same agent, governance-ready | Same behavior as Phase 1 | Backward compatible |
| 2 (gov) | Kakveda guards execution | HTTP /warn call | Governance in place |
| 3 | Failure repetition | Run risky 3x | Kakveda learns & escalates |

---

## Next

- **Phase 3:** Start Kakveda and re-run Phase 2 (with governance enabled)
- See [PHASES.md](PHASES.md) for detailed testing checklist
- See [README.md](README.md) for full overview
