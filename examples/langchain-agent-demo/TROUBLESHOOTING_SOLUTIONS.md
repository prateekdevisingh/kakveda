# Troubleshooting & Solutions: Kakveda Agent Integration

**Note:** This document describes the legacy KakvedaGuard integration. The current SDK is `kakveda_sdk`; use `from kakveda_sdk import KakvedaAgent` and do not copy `kakveda_integration.py`.


**Date:** 2026-02-17  
**Updated:** Post-integration fixes  
**Status:** Complete with all known fixes

---

## Overview

This document covers common issues encountered when integrating agents with Kakveda v1.0 and their solutions.

---

## Issue 1: Agent Not Visible in Kakveda Dashboard

**Symptom:**
- Agent runs successfully
- No metrics appear in Kakveda dashboard
- No runs, warnings, or patterns visible

**Root Causes:**

1. **Missing `.env` file loading** (Most Common)
2. **Incorrect Kakveda port configuration**
3. **Missing `app_id` in requests**
4. **Not publishing events to event-bus**
5. **Registration/heartbeat not running**
6. **Missing/invalid `DASHBOARD_API_KEY`**
7. **Invalid `AGENT_BASE_URL` or health endpoint**

---

## Solution 1: Load Environment Variables

### Problem
Agent uses hardcoded URLs instead of `.env` configuration.

### Fix
Add `.env` file loading at the top of your agent file:

```python
from dotenv import load_dotenv

# Load environment variables from .env
load_dotenv()
```

### Verification
Check that environment variables are loaded:
```bash
python -c "import os; from dotenv import load_dotenv; load_dotenv(); print(os.getenv('KAKVEDA_WARN_URL'))"
```

Should output: `http://localhost:8105/warn`

---

## Solution 1b: Ensure Registration + Heartbeat Are Running

### Problem
Agent runs but never registers with the dashboard, so it stays invisible under **Agents**.

### Fix
Verify your agent is using `KakvedaAgent` (it performs registration + heartbeat internally).

### Verification
Look for one of these logs:
- `registered in dashboard: agent_id=...`
- `registration via /api/agents/register ok...`

---

## Solution 1c: Validate Dashboard Auth + Base URL

### Problem
Dashboard rejects registration or health checks.

### Fix
Set these variables (example values):

```bash
DASHBOARD_URL=http://dashboard:8110
DASHBOARD_API_KEY=<project-api-key>
AGENT_BASE_URL=http://langchain-social-agent:8120
```

### Verification
Health endpoint should respond:

```bash
curl -s http://localhost:8120/health | python -m json.tool
```

---

## Solution 2: Fix Kakveda Port Configuration

### Problem
Hardcoded localhost:8000 but warning-policy actually runs on 8105.

**Error:**
```
ConnectionRefusedError: [Errno 111] Connection refused (port 8000)
```

### Fix
Update `.env` file:
```bash
KAKVEDA_WARN_URL=http://localhost:8105/warn
KAKVEDA_EVENT_BUS_URL=http://localhost:8100/publish
```

### Port Mapping Reference
| Service | Port | URL |
|---------|------|-----|
| Warning Policy | 8105 | http://localhost:8105/warn |
| Event Bus | 8100 | http://localhost:8100/publish |
| Dashboard | 8110 | http://localhost:8110 |
| Failure Classifier | 8103 | - |
| Pattern Detector | 8104 | - |
| Health Scoring | 8106 | - |
| Ingestion | 8102 | - |
| GFKB | 8101 | - |

### Verify
```bash
curl -s http://localhost:8105/warn \
  -H "Content-Type: application/json" \
  -d '{"prompt": "test", "tools": ["post_to_social"], "app_id": "phase1-demo", "env": {}}'
```

Should return: `{"action": "...", "confidence": 0.0, ...}`

---

## Solution 3: Include `app_id` in Requests

### Problem
Kakveda `/warn` endpoint rejects requests without `app_id`.

**Error:**
```json
{"detail": [{"msg": "Field required", "loc": ["body", "app_id"]}]}
```

### Fix
Update your `/warn` payload:

**Before (Wrong):**
```python
payload = {
    "prompt": prompt,
    "tools": ["post_to_social"],
    "env": {"platform": platform},
}
```

**After (Correct):**
```python
payload = {
    "prompt": prompt,
    "tools": ["post_to_social"],
    "app_id": os.getenv("KAKVEDA_APP_ID", "phase1-demo"),  # ← ADD THIS
    "env": {"platform": platform},
}
```

### Verification
Test with curl:
```bash
curl -s http://localhost:8105/warn \
  -H "Content-Type: application/json" \
  -d '{
    "prompt": "test post",
    "tools": ["post_to_social"],
    "app_id": "phase1-demo",
    "env": {"platform": "linkedin"}
  }' | python -m json.tool
```

Should return successful response with action, confidence, pattern_id

---

## Solution 4: Publish Events to Event Bus

### Problem
Agent makes governance decisions but doesn't publish events → no dashboard metrics.

**Observation:** Agent runs, shows governance decisions, but nothing in dashboard.

### Fix
Use `KakvedaAgent` (or `KakvedaGuard`) so events are published automatically after execution.

Checklist:
- Ensure `KAKVEDA_EVENT_BUS_URL` is set correctly.
- Verify the agent uses `KakvedaAgent.execute()` for tool calls.
- Check logs for `[KAKVEDA] Event publishing failed` errors.
  ### Verification
  Check event-bus accepts events:
```bash
curl -s http://localhost:8100/publish \
  -H "Content-Type: application/json" \
  -d '{
    "topic": "trace.ingested",
    "event": {
      "app_id": "phase1-demo",
      "tool": "post_to_social",
      "action": "executed"
    }
  }' | python -m json.tool
```

Should return: `{"ok": true, "delivered": 2}`

---

## Solution 5: Use Correct Event Bus Payload Format

### Problem
Event publishing fails with 422 validation error.

**Error:**
```
422 Client Error: Unprocessable Entity for url: http://localhost:8100/publish
```

### Root Cause
Event-bus expects `topic` and `event` fields, not `event_type`.

**Wrong Format:**
```json
{
  "event_type": "trace.ingested",
  "app_id": "phase1-demo",
  "timestamp": "2026-02-17T...",
  "payload": {...}
}
```

**Correct Format:**
```json
{
  "topic": "trace.ingested",
  "event": {
    "app_id": "phase1-demo",
    "timestamp": "2026-02-17T...",
    "tool": "post_to_social",
    "action": "executed"
  }
}
```

### Key Differences
- Use `topic` instead of `event_type`
- Put everything inside `event` object
- Include `app_id` inside `event`

---

## Complete Configuration Checklist

### 1. .env File

```bash
# Kakveda Service URLs
KAKVEDA_WARN_URL=http://localhost:8105/warn
KAKVEDA_EVENT_BUS_URL=http://localhost:8100/publish

# App Configuration
KAKVEDA_APP_ID=phase1-demo
KAKVEDA_ENVIRONMENT=dev

# Failure Modes
KAKVEDA_FAIL_CLOSED=false
KAKVEDA_AUTO_APPROVE=true
```

### 2. Agent Initialization

```python
from dotenv import load_dotenv
import os
from datetime import datetime, timezone
import requests

# Load .env file
load_dotenv()

class KavkedaGovernanceManager:
    def __init__(self):
        self.warn_url = os.getenv("KAKVEDA_WARN_URL")
        self.event_bus_url = os.getenv("KAKVEDA_EVENT_BUS_URL")
        self.app_id = os.getenv("KAKVEDA_APP_ID", "phase1-demo")
```

### 3. Warning Call Payload

```python
payload = {
    "prompt": prompt,
    "tools": ["post_to_social"],
    "app_id": self.app_id,
    "env": {"platform": platform},
}
response = requests.post(self.warn_url, json=payload, timeout=10)
```

### 4. Event Publishing Payload

```python
event = {
    "topic": "trace.ingested",
    "event": {
        "app_id": self.app_id,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "tool": "post_to_social",
        "action": "executed",
    }
}
requests.post(self.event_bus_url, json=event, timeout=10)
```

---

## Testing Checklist

- [ ] `.env` file exists with correct URLs
- [ ] `load_dotenv()` called in agent code
- [ ] Warning endpoint returns successful response
- [ ] Event-bus endpoint accepts events
- [ ] Agent prints `[EVENT PUBLISHED]` message
- [ ] Kakveda dashboard shows agent metrics
- [ ] Runs appear in Runs section
- [ ] Warnings appear in Warnings section
- [ ] Patterns appear in Patterns section

---

## Common Error Messages & Fixes

### Error: `ModuleNotFoundError: No module named 'kakveda_integration'`

**Fix:** Copy `kakveda_integration.py` to your agent directory:
```bash
cp ../kakveda_integration.py .
```

---

### Error: `ConnectionRefusedError: Connection refused (port:8000)`

**Fix:** Update `.env`:
```bash
KAKVEDA_WARN_URL=http://localhost:8105/warn
```

---

### Error: `422 Client Error: Unprocessable Entity`

**Fix:** Use correct event format:
```python
{"topic": "trace.ingested", "event": {...}}
```

---

### Error: `Field required` for app_id

**Fix:** Include `app_id` in warning payload:
```python
"app_id": os.getenv("KAKVEDA_APP_ID", "phase1-demo")
```

---

### Agent runs but no metrics in dashboard

**Fix:** 
1. Check `.env` file is being loaded
2. Verify events are published (look for `[EVENT PUBLISHED]` in logs)
3. Verify event-bus endpoint accepts events

---

## Verification Commands

### Check .env Loading
```bash
python -c "import os; from dotenv import load_dotenv; load_dotenv(); print('WARN_URL:', os.getenv('KAKVEDA_WARN_URL')); print('APP_ID:', os.getenv('KAKVEDA_APP_ID'))"
```

### Test Warning Endpoint
```bash
curl -X POST http://localhost:8105/warn \
  -H "Content-Type: application/json" \
  -d '{
    "prompt": "test",
    "tools": ["post_to_social"],
    "app_id": "phase1-demo",
    "env": {"platform": "linkedin"}
  }' | python -m json.tool
```

### Test Event Bus Endpoint
```bash
curl -X POST http://localhost:8100/publish \
  -H "Content-Type: application/json" \
  -d '{
    "topic": "trace.ingested",
    "event": {"app_id": "phase1-demo", "action": "test"}
  }' | python -m json.tool
```

### Run Agent and Check Output
```bash
python agent_app.py --platform linkedin --topic "test"
```

Look for:
```
[EVENT PUBLISHED] trace.ingested
```

---

## Summary of All Fixes

| Issue | Fix | File | Line(s) |
|-------|-----|------|---------|
| Missing .env loading | Add `load_dotenv()` | agent_app.py | ~10 |
| Wrong port | Change 8000 → 8105 | .env | ~1 |
| Missing app_id | Add to payload | agent_app.py | ~40 |
| No event publishing | Add `publish_event()` | agent_app.py | ~55 |
| Wrong event format | Use `topic`/`event` | agent_app.py | ~65 |

---

## Next Steps

1. **Apply all 5 fixes** to your agent
2. **Update `.env`** with correct URLs
3. **Test endpoints** with curl commands
4. **Run agent** and verify output
5. **Check dashboard** for metrics and runs

All issues are now resolved and fully documented!