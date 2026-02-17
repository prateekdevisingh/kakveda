# Kakveda Integration Layer — Documentation

**Note:** This document describes the legacy KakvedaGuard integration. The current SDK is `kakveda_sdk`; use `from kakveda_sdk import KakvedaAgent` and do not copy `kakveda_integration.py`.


**Location:** `kakveda-v1.0/kakveda_sdk/guard.py`

A lightweight, framework-agnostic middleware for integrating any AI agent system with Kakveda without modifying the agent's core logic or adopting Kakveda-specific patterns.

---

## Core Principle

**Kakveda wraps around agents, not inside them.**

The integration layer sits between your agent's execution call and the actual operation. It:
1. Checks preflight governance (`/warn`)
2. Wraps execution
3. Publishes observability events (`/publish`)

Your agent never knows Kakveda exists.

---

## Quick Start (SDK-Managed)

### 1. Import and initialize

```python
from kakveda_sdk import KakvedaAgent

agent = KakvedaAgent(capabilities=["my_tool"])
```

### 3. Wrap your execution

```python
def my_agent_action():
    # Your actual agent code here
    return result

result = agent.execute(
    prompt=user_input,
    tool_name="my_tool",
    execute_fn=my_agent_action,
    metadata={"user_id": "123"}
)
```

Done. No framework dependencies. No agent modification.

---

## Environment Variables

Configure via environment or `.env`:

| Variable | Default | Purpose |
|----------|---------|---------|
| `KAKVEDA_WARN_URL` | `http://warning-policy:8000/warn` | Preflight endpoint |
| `KAKVEDA_EVENT_BUS_URL` | `http://event-bus:8100/publish` | Event publishing |
| `KAKVEDA_APP_ID` | `external-agent` | App identifier for tracing |
| `KAKVEDA_ENVIRONMENT` | `prod` | Environment (prod/staging/dev) |
| `KAKVEDA_FAIL_CLOSED` | `true` | Block on Kakveda unavailability |
| `KAKVEDA_AUTO_APPROVE` | `false` | Auto-approve require-approval actions |

### Example .env

```bash
KAKVEDA_WARN_URL=http://localhost:8105/warn
KAKVEDA_EVENT_BUS_URL=http://localhost:8100/publish
KAKVEDA_APP_ID=my-agent-prod
KAKVEDA_ENVIRONMENT=production
KAKVEDA_FAIL_CLOSED=true
```

---

## API Reference (Legacy Guard)

### 1. KakvedaGuard Constructor

```python
from kakveda_sdk.guard import KakvedaGuard

guard = KakvedaGuard(
    warn_url=None,              # Auto-detect from env or use default
    event_bus_url=None,         # Auto-detect from env or use default
    app_id=None,                # Auto-detect from env or use default
    environment=None,           # Auto-detect from env or use default
    fail_closed=None,           # Auto-detect from env or use default
    timeout=10,                 # HTTP request timeout (seconds)
)
```

### 2. preflight() — Governance Check

```python
decision = guard.preflight(
    prompt="user input",
    tool="tool_name",
    metadata={"risk": "high"}
)
```

**Returns:**
```python
{
    "action": "silent" | "warn" | "require-approval" | "block",
    "confidence": 0.0 to 1.0,
    "pattern_id": "string_id",
    "message": "human-readable explanation"
}
```

**What each action means:**
- `silent`: Execute normally, no logging
- `warn`: Execute but log a warning
- `require-approval`: Wait for manual approval before executing
- `block`: Do not execute, treat as policy violation

### 3. publish() — Event Publishing

```python
success = guard.publish(
    event_type="trace.ingested",
    payload={"tool": "...", "result": "..."}
)
```

**Always non-blocking.** Returns `True` if posted, `False` if failed. Does not raise exceptions.

**Event types:**
- `trace.ingested` — Execution trace with result
- `failure.detected` — Detected failure/policy block
- `approval.required` — Approval needed
- (Any custom type)

### 4. guarded_execute() — Full Orchestration

```python
result = guard.guarded_execute(
    prompt="user question",
    tool_name="my_tool",
    execute_fn=lambda: your_action(),
    metadata={"user_id": "123", "risk": "low"}
)
```

**Orchestration flow:**
1. Call `preflight()`
2. If blocked → publish failure → return `None`
3. If require-approval → check `KAKVEDA_AUTO_APPROVE` env
4. If warn → log warning message
5. Execute `execute_fn()`
6. Publish trace with result/error
7. Return execution result

**Key properties:**
- Does not propagate exceptions to caller
- Always publishes trace (success or error)
- Non-blocking event publishing
- Transparent error handling

---

## Usage Patterns

### Pattern 1: LangChain Agent Tool Wrapper

```python
from langchain.agents import Tool
from kakveda_sdk.guard import KakvedaGuard

guard = KakvedaGuard()

def wrapped_tool_func(query: str):
    def execute():
        # Your real tool logic
        return your_tool_implementation(query)
    
    return guard.guarded_execute(
        prompt=query,
        tool_name="your_tool",
        execute_fn=execute,
        metadata={"tool_version": "1.0"}
    )

tool = Tool(
    name="your_tool",
    func=wrapped_tool_func,
    description="..."
)
```

### Pattern 2: Microservice Handler

```python
from flask import Flask
from kakveda_sdk.guard import KakvedaGuard

app = Flask(__name__)
guard = KakvedaGuard()

@app.post("/api/execute")
def handle_execution():
    data = request.json
    
    result = guard.guarded_execute(
        prompt=data["input"],
        tool_name=data["tool"],
        execute_fn=lambda: execute_tool(data),
        metadata={"user_id": data.get("user_id")}
    )
    
    return {"result": result}
```

### Pattern 3: Async Wrapper (Manual)

```python
async def async_wrapped_execution(prompt, tool_name):
    # For async contexts, run guard in executor
    loop = asyncio.get_event_loop()
    result = await loop.run_in_executor(
        None,
        guard.guarded_execute,
        prompt,
        tool_name,
        your_sync_function,
        None
    )
    return result
```

### Pattern 4: Custom Agent Class

```python
class MyAgent:
    def __init__(self):
        self.guard = KakvedaGuard()
    
    def execute_action(self, user_query):
        return self.guard.guarded_execute(
            prompt=user_query,
            tool_name="agent_action",
            execute_fn=self._do_work,
            metadata={"agent": "MyAgent"}
        )
    
    def _do_work(self):
        # Your agent logic here
        return your_result
```

---

## Fail-Safe Modes

### Fail-Closed (Default)

```bash
KAKVEDA_FAIL_CLOSED=true
```

When Kakveda is unreachable → **block execution**.

Use this when Kakveda governance is mandatory (compliance, high-risk operations).

### Fail-Open

```bash
KAKVEDA_FAIL_CLOSED=false
```

When Kakveda is unreachable → **allow execution** (log warning).

Use this when Kakveda is monitoring-only and service availability is critical.

---

## Event Types & Payloads

### trace.ingested

Sent after execution (success or error).

```python
{
    "tool": "tool_name",
    "prompt": "user input",
    "result": "execution result",
    "error": null or "error message",
    "is_failure": false,
    "policy_action": "silent",
    "pattern_id": "pattern_123",
    "confidence": 0.45
}
```

### failure.detected

Sent when policy blocks execution.

```python
{
    "tool": "tool_name",
    "prompt": "user input",
    "pattern_id": "pattern_xyz",
    "reason": "policy_blocked"
}
```

### approval.required

Sent when approval is needed (and not auto-approved).

```python
{
    "tool": "tool_name",
    "prompt": "user input",
    "pattern_id": "pattern_abc"
}
```

---

## Integration with Kakveda Services

### Architecture Flow

```
Your Agent
    ↓
[KakvedaGuard wrapper]
    ├─ 1. POST /warn → warning-policy:8000
    │  (preflight check)
    │
    ├─ 2. Execute your_function()
    │
    └─ 3. POST /publish → event-bus:8100
       (trace/failure event)
         ↓
    [event-bus routes to]
    ├─ failure-classifier
    ├─ pattern-detector
    ├─ health-scoring
    └─ dashboard
```

### Network Requirements

The guard needs HTTP access to:
- `warning-policy:8000/warn` (preflight)
- `event-bus:8100/publish` (events)

Default assumes Docker network. For localhost development:

```bash
KAKVEDA_WARN_URL=http://localhost:8105/warn
KAKVEDA_EVENT_BUS_URL=http://localhost:8100/publish
```

---

## Configuration Examples

### Production (High Governance)

```bash
KAKVEDA_WARN_URL=https://kakveda-prod.company.com/warn
KAKVEDA_EVENT_BUS_URL=https://kakveda-prod.company.com/publish
KAKVEDA_APP_ID=production-agent-v1
KAKVEDA_ENVIRONMENT=production
KAKVEDA_FAIL_CLOSED=true
KAKVEDA_AUTO_APPROVE=false
```

### Development (Permissive)

```bash
KAKVEDA_WARN_URL=http://localhost:8105/warn
KAKVEDA_EVENT_BUS_URL=http://localhost:8100/publish
KAKVEDA_APP_ID=dev-agent
KAKVEDA_ENVIRONMENT=development
KAKVEDA_FAIL_CLOSED=false
KAKVEDA_AUTO_APPROVE=true
```

### Shadow Mode (Monitoring Only)

```bash
KAKVEDA_WARN_URL=http://localhost:8105/warn
KAKVEDA_EVENT_BUS_URL=http://localhost:8100/publish
KAKVEDA_APP_ID=agent-shadow
KAKVEDA_ENVIRONMENT=staging
KAKVEDA_FAIL_CLOSED=false  # Allow even if blocked
KAKVEDA_AUTO_APPROVE=true   # Approve all
```

(Hint: You'd configure preflight to always return `action: warn` instead of `block` in shadow mode)

---

## Error Handling

### Kakveda Unreachable

```python
# If KAKVEDA_FAIL_CLOSED=true (default):
#   → returns {"action": "block"}
#   → executes returns None
#   → event auto-publishes failure

# If KAKVEDA_FAIL_CLOSED=false:
#   → returns {"action": "silent"}
#   → executes normally
#   → event auto-publishes trace
```

### Execution Error

```python
# Your execute_fn raises exception:
#   → caught and logged
#   → error string published in trace.ingested
#   → guard returns None
#   → exception NOT propagated to caller
```

### Event Bus Unavailable

```python
# Failure is logged but does NOT block execution
# publish() returns False
# Caller continues without error
```

---

## Testing & Validation

### Unit Test Example

```python
import unittest
from unittest.mock import patch, MagicMock
from kakveda_sdk.guard import KakvedaGuard

class TestKakvedaGuard(unittest.TestCase):
    
    def test_preflight_silent_action(self):
        guard = KakvedaGuard()
        with patch('requests.post') as mock_post:
            mock_post.return_value.json.return_value = {
                "action": "silent",
                "confidence": 0.1,
                "pattern_id": "test",
                "message": "ok"
            }
            result = guard.preflight("test", "tool")
            assert result["action"] == "silent"
    
    def test_guarded_execute_blocked(self):
        guard = KakvedaGuard()
        mock_fn = MagicMock()
        
        with patch.object(guard, 'preflight') as mock_preflight:
            mock_preflight.return_value = {"action": "block"}
            result = guard.guarded_execute("test", "tool", mock_fn)
            assert result is None
            mock_fn.assert_not_called()
    
    def test_fail_closed_unavailable(self):
        guard = KakvedaGuard(fail_closed=True)
        with patch('requests.post', side_effect=Exception("Connection failed")):
            result = guard.preflight("test", "tool")
            assert result["action"] == "block"
```

### Manual Testing

```python
from kakveda_sdk.guard import KakvedaGuard

guard = KakvedaGuard()
```

Run the examples:

```bash
python integration_examples.py
```

---

## Troubleshooting

| Issue | Cause | Solution |
|-------|-------|----------|
| `action: block` always | `KAKVEDA_FAIL_CLOSED=true` + Kakveda unavailable | Check network / Kakveda status |
| Events not published | Event bus unreachable | Check `KAKVEDA_EVENT_BUS_URL` |
| No imports | requests not installed | `pip install requests` |
| Execution always returns None | Preflight always blocking | Check preflight logic / logs |

---

## Performance Notes

- Preflight call adds network latency (default timeout: 10s)
- Event publishing is fire-and-forget (non-blocking)
- No local caching of policies
- Pure Python, no async library required

For < 100ms latency requirement, consider:
- Redis cache for recent decisions
- Local policy fallback
- Longer timeout with async infrastructure

---

## Security Considerations

- **No secrets embedded** — Use environment variables
- **No credentials in events** — Strip sensitive data from payloads
- **HTTPS recommended** — For production Kakveda endpoints
- **Network isolation** — Kakveda should be internal-only or behind VPN
- **Rate limiting** — Externally apply rate limits on event bus

---

## Next Steps

1. **Copy the file** into your agent project
2. **Set environment variables** for your Kakveda instance
3. **Wrap one execution** to test integration
4. **Validate logs** in Kakveda dashboard
5. **Scale up** to all critical operations

Questions? See phased demo in `langchain-agent-demo/` directory.