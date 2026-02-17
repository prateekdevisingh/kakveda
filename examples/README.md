# Integration Layer + Phased Demo Guide

**Note:** This document describes the legacy KakvedaGuard integration (reference only). The current SDK is `kakveda_sdk`; use `from kakveda_sdk import KakvedaAgent` and do not copy `kakveda_integration.py`.


This directory contains two complementary approaches to understanding and integrating Kakveda governance:

1. **Phased Demo** (`langchain-agent-demo/`) — Educational, step-by-step
2. **SDK Integration** (`kakveda_sdk`) — Production-ready wrapper

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

### SDK Quick Integration
Use the SDK-managed wrapper in your agent:

```python
from kakveda_sdk import KakvedaAgent

agent = KakvedaAgent(capabilities=["my_tool"])
result = agent.execute(
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
| `kakveda_sdk/` | Unified SDK wrapper (production) |
| `INTEGRATION.md` | Integration guide & API reference |

---

## Which Should I Use?

### Use the Phased Demo if you're:
- Learning how governance works
- Demonstrating Kakveda to stakeholders
- Testing locally without Kakveda running
- Understanding the /warn and /publish flow

### Use the SDK Integration if you're:
- Integrating with LangChain
- Integrating with LangGraph
- Integrating with FastAPI/Flask
- Integrating with a custom agent
- Building for production
- Need to wrap existing execution calls

---

## Comparison

| Aspect | Phased Demo | SDK Integration |
|--------|------------|-----------------|
| Purpose | Learning | Production |
| Code | Explicit flow | Wrapped abstraction |
| Framework | None (pure Python) | None (pure Python) |
| Setup | python-only | python + requests |
| Customization | Modify source | Configure env vars |
| Reusability | Demo only | Reusable SDK package |

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

Use the SDK directly and wrap your execution:

```python
from kakveda_sdk import KakvedaAgent

agent = KakvedaAgent(capabilities=["my_tool"])
```

### Step 4: Configure Environment

```bash
export KAKVEDA_WARN_URL=http://your-kakveda:8105/warn
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
├─ SDK Integration (Production)
│  ├─ kakveda_sdk → KakvedaAgent + KakvedaGuard
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
3. **Use** `kakveda_sdk` in your project
4. **Wrap** your first execution call via `KakvedaAgent.execute()`
5. **Test** against Kakveda locally or staging

---

## Support

- Demo issues? See `langchain-agent-demo/PHASES.md`
- Integration questions? See `INTEGRATION.md`
- Architecture questions? See main Kakveda [docs/](../../docs/)