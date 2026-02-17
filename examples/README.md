# Integration Layer + Phased Demo Guide

**Note:** This document describes the legacy KakvedaGuard integration. The current SDK is `kakveda_sdk`; use `from kakveda_sdk import KakvedaAgent` and do not copy `kakveda_integration.py`.


This directory contains two complementary approaches to understanding and integrating Kakveda governance:

1. **Phased Demo** (`langchain-agent-demo/`) — Educational, step-by-step
2. **Integration Layer** (`kakveda_integration.py`) — Production-ready wrapper

---

## Quick Navigation

### For Learning
Start with the phased demo:
- Phase 1: Understand agent basics
- Phase 2: See governance in action
- Phase 3: Watch failure learning

```bash
cd langchain-agent-demo/
python agent_app_phase1.py --platform linkedin --topic "AI growth" --no-governance
```

### For Production Integration
Use the integration layer:

```python
from kakveda_integration import KakvedaGuard

guard = KakvedaGuard()
result = guard.guarded_execute(
    prompt=user_input,
    tool_name="my_tool",
    execute_fn=my_function
)
```

---

## File Locations

| File/Folder | Purpose |
|---|---|
| `langchain-agent-demo/` | 3-phase governance demo (educational) |
| `kakveda_integration.py` | Framework-agnostic wrapper (production) |
| `INTEGRATION.md` | Integration guide & API reference |

---

## Which Should I Use?

### Use the Phased Demo if you're:
- Learning how governance works
- Demonstrating Kakveda to stakeholders
- Testing locally without Kakveda running
- Understanding the /warn and /publish flow

### Use the Integration Layer if you're:
- Integrating with LangChain
- Integrating with FastAPI/Flask
- Integrating with a custom agent
- Building for production
- Need to wrap existing execution calls

---

## Comparison

| Aspect | Phased Demo | Integration Layer |
|--------|------------|-------------------|
| Purpose | Learning | Production |
| Code | Explicit flow | Wrapped abstraction |
| Framework | None (pure Python) | None (pure Python) |
| Setup | python-only | python + requests |
| Customization | Modify source | Configure env vars |
| Reusability | Demo only | Copy into any project |

---

## Getting Started

### Step 1: Learn with Phased Demo

```bash
cd langchain-agent-demo
. .venv/bin/activate
python agent_app_phase1.py --platform linkedin --topic "AI growth" --no-governance
```

### Step 2: Review Integration Guide

Read [INTEGRATION.md](INTEGRATION.md) to understand production patterns.

### Step 3: Use in Your Project

Copy `kakveda_integration.py` to your project and import:

```python
from kakveda_integration import KakvedaGuard
guard = KakvedaGuard()
```

### Step 4: Configure Environment

```bash
export KAKVEDA_WARN_URL=http://your-kakveda:8000/warn
export KAKVEDA_EVENT_BUS_URL=http://your-kakveda:8100/publish
export KAKVEDA_APP_ID=my-agent
export KAKVEDA_ENVIRONMENT=production
```

---

## Architecture Overview

```
┌─ Phased Demo (Educational)
│  ├─ agent_app_phase1.py  → Standalone
│  ├─ agent_app_phase2.py  → + Governance
│  └─ Shows explicit flow
│
├─ Integration Layer (Production)
│  ├─ kakveda_integration.py → KakvedaGuard class
│  └─ Abstract away complexity
│
└─ Integration Guide
   └─ INTEGRATION.md → How to use both
```

---

## Key Concepts

### Preflight Governance
Before any action, ask Kakveda: "Should we do this?"
- Returns: `silent`, `warn`, `require-approval`, or `block`
- Non-blocking: Kakveda unavailable? Configure fail-closed or fail-open

### Event Publishing
After any action, tell Kakveda what happened:
- Event types: `trace.ingested`, `failure.detected`, `approval.required`
- Non-blocking: Event bus unavailable? Logs warning, continues

### Governance Loop
```
User Action → Preflight Check → Kakveda Decision → Execute or Block → Report Event
```

---

## Next Steps

1. **Read** [INTEGRATION.md](INTEGRATION.md) for full API reference
2. **Run** Phase 1 demo to see the flow
3. **Copy** `kakveda_integration.py` into your project
4. **Wrap** your first execution call
5. **Test** against Kakveda locally or staging

---

## Support

- Demo issues? See `langchain-agent-demo/PHASES.md`
- Integration questions? See `INTEGRATION.md`
- Architecture questions? See main Kakveda [docs/](../../docs/)