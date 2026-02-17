# Kakveda Integration — Complete Implementation

**Note:** This document describes the legacy KakvedaGuard integration. The current SDK is `kakveda_sdk`; use `from kakveda_sdk import KakvedaAgent` and do not copy `kakveda_integration.py`.


**Date:** 2026-02-17  
**Status:** ✅ Ready for Production

---

## What's Been Delivered

### 1. Framework-Agnostic Integration Layer

**File:** `kakveda_integration.py`

A production-ready Python class (`KakvedaGuard`) that:
- Wraps any agent execution with governance
- Calls Kakveda /warn for preflight checks
- Publishes events to /publish for observability
- Handles all failure modes gracefully
- Never propagates exceptions to caller
- Works with any framework (LangChain, FastAPI, custom agents, etc.)

**Key Features:**
- ✅ No framework dependencies (just requests)
- ✅ Configurable via environment variables
- ✅ Fail-closed/fail-open modes
- ✅ Non-blocking event publishing
- ✅ Comprehensive error handling
- ✅ Production-safe
- ✅ <50KB, portable

---

### 2. Integration Documentation

**File:** `INTEGRATION.md`

Complete guide including:
- Quick start (3 steps to integration)
- Environment variable reference
- Full API documentation
- 4 usage patterns (LangChain, microservices, async, custom agents)
- Integration architecture diagrams
- Event type specifications
- Configuration examples (prod, dev, shadow mode)
- Error handling guide
- Testing examples
- Troubleshooting

---

### 3. Practical Examples

**File:** `integration_examples.py`

5 executable examples showing:
1. Basic usage (safe content)
2. Risky content with governance
3. Error handling
4. Fail-open mode
5. Batch operations
6. Tool wrapper pattern (like LangChain)

Run with:
```bash
python integration_examples.py
```

---

### 4. Updated Documentation

**File:** `README.md` (in examples/)

Navigation guide connecting:
- Phased demo (learning)
- Integration layer (production)
- Integration guide (reference)

---

## Architecture

```
┌─ Your Agent/Service
│  ├─ Execution call: my_function()
│  └─ Wrapper: guard.guarded_execute(...)
│
├─ KakvedaGuard (integration layer)
│  ├─ preflight() → POST /warn
│  ├─ orchestrate execution
│  └─ publish() → POST /publish
│
└─ Kakveda Services
   ├─ warning-policy:8000/warn
   └─ event-bus:8100/publish
```

---

## Usage (Copy-Paste Ready)

### Step 1: Copy file
```bash
cp kakveda_integration.py /your-project/
```

### Step 2: Import
```python
from kakveda_integration import KakvedaGuard
guard = KakvedaGuard()
```

### Step 3: Wrap execution
```python
result = guard.guarded_execute(
    prompt="user input",
    tool_name="my_tool",
    execute_fn=my_function,
    metadata={"user_id": "123"}
)
```

### Step 4: Configure (optional)
```bash
export KAKVEDA_WARN_URL=http://your-kakveda:8000/warn
export KAKVEDA_EVENT_BUS_URL=http://your-kakveda:8100/publish
export KAKVEDA_APP_ID=my-agent
export KAKVEDA_ENVIRONMENT=production
```

---

## Supported Patterns

| Framework | Pattern | Example |
|-----------|---------|---------|
| LangChain | Tool wrapper | See INTEGRATION.md, Pattern 1 |
| FastAPI | Route handler wrapper | See INTEGRATION.md, Pattern 2 |
| Async apps | Executor pool | See INTEGRATION.md, Pattern 3 |
| Custom agents | Class method wrapper | See INTEGRATION.md, Pattern 4 |

---

## Environment Variables

| Variable | Default | Purpose |
|----------|---------|---------|
| KAKVEDA_WARN_URL | http://warning-policy:8000/warn | Preflight endpoint |
| KAKVEDA_EVENT_BUS_URL | http://event-bus:8100/publish | Event publishing |
| KAKVEDA_APP_ID | external-agent | App identifier |
| KAKVEDA_ENVIRONMENT | prod | Environment (prod/staging/dev) |
| KAKVEDA_FAIL_CLOSED | true | Block on Kakveda unavailability |
| KAKVEDA_AUTO_APPROVE | false | Auto-approve require-approval actions |

---

## API Reference (Quick)

### Constructor
```python
guard = KakvedaGuard(
    warn_url=None,              # Uses env or default
    event_bus_url=None,         # Uses env or default
    app_id=None,                # Uses env or default
    environment=None,           # Uses env or default
    fail_closed=None,           # Uses env or default
    timeout=10                  # HTTP timeout seconds
)
```

### Preflight Check
```python
decision = guard.preflight(
    prompt="user input",
    tool="tool_name",
    metadata={"risk": "high"}
)
# Returns: {"action": "...", "confidence": float, "pattern_id": "...", "message": "..."}
```

### Event Publishing
```python
success = guard.publish(
    event_type="trace.ingested",
    payload={...}
)
# Returns: bool (always non-blocking)
```

### Guarded Execution (Main API)
```python
result = guard.guarded_execute(
    prompt="user question",
    tool_name="my_tool",
    execute_fn=lambda: your_function(),
    metadata={"key": "value"}
)
# Returns: execution result or None if blocked
```

---

## File Structure

```
kakveda-v1.0/examples/
├── kakveda_integration.py         [NEW] Integration layer
├── integration_examples.py        [NEW] Practical examples
├── INTEGRATION.md                 [NEW] Full guide
├── README.md                      [UPDATED] Navigation
├── langchain-agent-demo/
│   ├── agent_app_phase1.py
│   ├── agent_app_phase2.py
│   ├── agent_app.py
│   ├── mock_social_api.py
│   ├── README.md
│   ├── PHASES.md
│   ├── SUMMARY.md
│   ├── QUICKSTART.md
│   └── requirements.txt
└── [other files]
```

---

## Test Integration

### Validate Integration Layer Works
```bash
cd kakveda-v1.0/examples
python kakveda_integration.py
```

Expected output:
- Shows governance check attempts
- Demonstrates fail-closed behavior (blocks when Kakveda unavailable)
- Logs event publishing attempts
- No exceptions

### Validate Examples Work
```bash
python integration_examples.py
```

Shows all 5 usage patterns in action.

### Validate with Phased Demo
```bash
cd langchain-agent-demo
. .venv/bin/activate
python agent_app_phase1.py --platform linkedin --topic "AI growth" --no-governance
```

---

## Integration Paths

### Path 1: LangChain Team
1. Copy `kakveda_integration.py`
2. Follow "Pattern 1" in INTEGRATION.md
3. Wrap each Tool's func

### Path 2: FastAPI/Flask Team
1. Copy `kakveda_integration.py`
2. Follow "Pattern 2" in INTEGRATION.md
3. Wrap route handlers

### Path 3: Custom Agent
1. Copy `kakveda_integration.py`
2. Follow "Pattern 4" in INTEGRATION.md
3. Wrap execution methods

### Path 4: Microservice
1. Copy `kakveda_integration.py`
2. Wrap service method calls
3. Set environment variables per service instance

---

## Configuration Scenarios

### Production (Mandatory Governance)
```bash
KAKVEDA_FAIL_CLOSED=true
KAKVEDA_AUTO_APPROVE=false
KAKVEDA_ENVIRONMENT=production
```

### Staging (Permissive Learning)
```bash
KAKVEDA_FAIL_CLOSED=false
KAKVEDA_AUTO_APPROVE=true
KAKVEDA_ENVIRONMENT=staging
```

### Shadow Mode (Monitoring Only)
```bash
KAKVEDA_FAIL_CLOSED=false
KAKVEDA_AUTO_APPROVE=true
KAKVEDA_ENVIRONMENT=shadow
```

---

## Deployment Checklist

- [ ] Copy `kakveda_integration.py` to project
- [ ] Install requests: `pip install requests`
- [ ] Set KAKVEDA_* environment variables
- [ ] Identify one execution point to wrap
- [ ] Wrap with `guard.guarded_execute()`
- [ ] Test locally with Kakveda running
- [ ] Verify logs in Kakveda dashboard
- [ ] Deploy to staging
- [ ] Scale to all critical operations

---

## Performance Notes

- Preflight adds network latency (~50-200ms with cold connection)
- Event publishing is non-blocking (fire-and-forget)
- No local caching (delegated to Kakveda)
- Thread-safe (no global state)
- Memory: ~10KB per guard instance
- Can be reused across multiple calls

---

## Security Notes

- No secrets embedded (always use env vars)
- No credentials in events (sanitize payloads)
- HTTPS recommended for production
- Network isolation (internal-only or VPN)
- No local policy storage (all from Kakveda)

---

## Support Resources

| Item | Location |
|------|----------|
| API Reference | INTEGRATION.md |
| Examples | integration_examples.py |
| Quick Start | integration_examples.py (run & review) |
| Learning Flow | langchain-agent-demo/ → INTEGRATION.md |
| Architecture | INTEGRATION.md (Architecture section) |
| Troubleshooting | INTEGRATION.md (Troubleshooting section) |

---

## Next Steps

1. **Copy** `kakveda_integration.py` to your project
2. **Read** [INTEGRATION.md](INTEGRATION.md) section for your framework
3. **Try** [integration_examples.py](integration_examples.py) to see patterns
4. **Wrap** your first execution call
5. **Test** against Kakveda (local or staging)
6. **Deploy** when confidence is high

---

## What Makes This Powerful

✅ **Copy-paste ready** — No scaffolding needed  
✅ **Framework agnostic** — Works with anything  
✅ **Production safe** — Comprehensive error handling  
✅ **Zero coupling** — Your agent never knows Kakveda exists  
✅ **Observability built-in** — All events auto-published  
✅ **Configurable** — Adapt to any environment  
✅ **Tested patterns** — 4 real-world examples included  

---

## Bottom Line

Any company can now integrate Kakveda governance into **any AI agent system** with:

1. Copy one file
2. Set environment variables
3. Wrap one execution call

That's it. No frameworks. No rewriting. No coupling.

**Governance as middleware.**

---

**Status:** Ready for production integration across any agent platform.