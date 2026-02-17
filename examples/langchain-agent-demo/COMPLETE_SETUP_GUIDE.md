# Complete Setup Guide: From Zero to Kakveda-Enabled Agent

**Note:** This document describes the legacy KakvedaGuard integration. The current SDK is `kakveda_sdk`; use `from kakveda_sdk import KakvedaAgent` and do not copy `kakveda_integration.py`.


**Date:** 2026-02-17  
**Version:** Final with all fixes  
**Audience:** Users integrating agents with Kakveda v1.0

---

## Overview

This guide walks you through the **complete setup process** from verification to working agent with full Kakveda integration, including all fixes for common issues.

---

## Step 0: Verify Kakveda is Running

### Check Docker Containers

```bash
docker ps | grep kakveda
```

Should show these containers running:
- `warning-policy_1` → port 8105
- `event-bus_1` → port 8100
- `dashboard_1` → port 8110
- Others: failure-classifier, pattern-detector, health-scoring, gfkb, ingestion, ollama, agent-echo

### If Not Running

```bash
# In kakveda-v1.0 root directory
docker-compose up -d

# Wait 10-15 seconds for services to start
sleep 15

# Verify
docker ps | grep kakveda
```

### Test Services

```bash
# Test warning-policy
curl -s http://localhost:8105/ | head

# Test event-bus  
curl -s http://localhost:8100/ | head

# Test dashboard
curl -s http://localhost:8110/ | head
```

All three should return HTML or valid responses.

---

## Step 1: Create `.env` File

In your agent directory (`langchain-agent-demo/`), create `.env`:

```bash
# Create file
cat > .env << 'EOF'
KAKVEDA_WARN_URL=http://localhost:8105/warn
KAKVEDA_EVENT_BUS_URL=http://localhost:8100/publish
KAKVEDA_APP_ID=phase1-demo
KAKVEDA_ENVIRONMENT=dev
KAKVEDA_FAIL_CLOSED=false
KAKVEDA_AUTO_APPROVE=true
EOF

# Verify content
cat .env
```

**Critical Notes:**
- Port is **8105** (not 8000!)
- Use endpoint `/warn` for warning-policy
- Use endpoint `/publish` for event-bus
- `KAKVEDA_FAIL_CLOSED=false` allows operation when Kakveda unavailable
- All other fields are optional but recommended

---

## Step 2: Copy Integration Module

```bash
# From langchain-agent-demo directory
cp ../kakveda_integration.py .

# Verify it exists
ls -lh kakveda_integration.py
```

---

## Step 3: Test Connectivity (Critical!)

### Test Warning Policy Endpoint

```bash
curl -X POST http://localhost:8105/warn \
  -H "Content-Type: application/json" \
  -d '{
    "prompt": "test post",
    "tools": ["post_to_social"],
    "app_id": "test-app",
    "env": {"platform": "linkedin"}
  }' | python -m json.tool
```

Expected response:
```json
{
  "action": "warn",
  "confidence": 0.05,
  "pattern_id": "FP-0001",
  "message": "No high-similarity match found in GFKB."
}
```

**If fails:** Stop! Read [TROUBLESHOOTING_SOLUTIONS.md](TROUBLESHOOTING_SOLUTIONS.md#solution-2-fix-kakveda-port-configuration)

### Test Event Bus Endpoint

```bash
curl -X POST http://localhost:8100/publish \
  -H "Content-Type: application/json" \
  -d '{
    "topic": "trace.ingested",
    "event": {
      "app_id": "test-app",
      "tool": "post_to_social",
      "action": "test"
    }
  }' | python -m json.tool
```

Expected response:
```json
{
  "ok": true,
  "delivered": 2
}
```

**If fails:** Read [TROUBLESHOOTING_SOLUTIONS.md](TROUBLESHOOTING_SOLUTIONS.md#solution-5-use-correct-event-bus-payload-format)

---

## Step 4: Update Agent Code

### Add Environment Loading

At the **top** of your agent file (after imports):

```python
from dotenv import load_dotenv
import os
from datetime import datetime, timezone

# Load environment variables from .env
load_dotenv()
```

### Add Event Publishing Method

In your Kakveda governance manager class:

```python
def publish_event(self, event_type: str, payload: dict) -> bool:
    """Publish an event to Kakveda event bus."""
    event = {
        "topic": event_type,
        "event": {
            "app_id": self.app_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            **payload,
        }
    }
    try:
        response = requests.post(
            self.event_bus_url,
            json=event,
            timeout=10,
        )
        response.raise_for_status()
        print(f"[EVENT PUBLISHED] {event_type}")
        return True
    except Exception as e:
        print(f"[EVENT PUBLISH FAILED] {event_type}: {str(e)}")
        return False
```

### Ensure Warning Payload Has app_id

```python
def call_warn(self, prompt: str, platform: str) -> dict:
    """Call Kakveda /warn endpoint."""
    payload = {
        "prompt": prompt,
        "tools": ["post_to_social"],
        "app_id": os.getenv("KAKVEDA_APP_ID", "phase1-demo"),  # ← CRITICAL
        "env": {"platform": platform},
    }
    response = requests.post(self.warn_url, json=payload, timeout=10)
    return response.json()
```

### Publish Events After Execution

In your `run()` method:

```python
def run(self, prompt: str) -> str:
    content = self.llm.generate(prompt)
    decision = self.make_decision(content)
    
    if decision == "block":
        # Publish blocked event
        self.kakveda.publish_event(
            "trace.ingested",
            {"tool": "post_to_social", "action": "blocked", "platform": self.platform}
        )
        return "blocked"
    
    # Execute and publish success event
    mock_social_api.post(content, self.platform)
    self.kakveda.publish_event(
        "trace.ingested",
        {"tool": "post_to_social", "action": "executed", "platform": self.platform}
    )
    return "executed"
```

---

## Step 5: Test Agent

### Test 1: Without Governance

```bash
python agent_app.py --platform linkedin --topic "AI growth" --no-governance
```

Expected output:
```
[GOVERNANCE] disabled
[TOOL EXECUTION] no-governance
[FINAL RESULT] executed
```

**If fails:** Check installation, not Kakveda-related.

### Test 2: With Governance

```bash
python agent_app.py --platform linkedin --topic "AI growth"
```

Expected output:
```
[GOVERNANCE] enabled
-> Sending to Kakveda...
--- KAKVEDA REQUEST ---
...
--- KAKVEDA RESPONSE ---
{'action': 'warn', 'confidence': 0.05, ...}
...
[EVENT PUBLISHED] trace.ingested
[FINAL RESULT] executed
```

**Key indicators of success:**
- ✅ Kakveda response received
- ✅ `[EVENT PUBLISHED]` message shown
- ✅ No errors

**If "Connection refused":** Port is wrong → Fix .env (port 8105)

**If "422 Unprocessable Entity":** Event format wrong → Check publish_event() format

**If no `[EVENT PUBLISHED]`:** load_dotenv() missing or event bus URL wrong

### Test 3: Multiple Runs

```bash
python agent_app.py --platform twitter --topic "machine learning"
python agent_app.py --platform instagram --topic "AI safety"
python agent_app.py --platform linkedin --topic "risky"
```

Generate different events for dashboard visualization.

---

## Step 6: Verify in Dashboard

Open **http://localhost:8110** in browser:

### Expected to See:

1. **Agents** section
   - Agent `phase1-demo` listed
   - Status shows as "active"

2. **Runs** section
   - Multiple run entries (one per test)
   - Shows platform, topic, timestamp
   - Status column shows "success" or "warning"

3. **Warnings** section
   - Entries for each run with `action=warn`
   - Pattern ID "FP-0001"
   - Confidence scores

4. **Metrics** section
   - Charts/graphs showing agent activity
   - Runs per platform breakdown
   - Timeline of executions

5. **Patterns** section
   - Pattern "FP-0001" detected
   - Associated with generated content

### If Nothing Shows:

1. Check agent outputs for `[EVENT PUBLISHED]`
2. Verify `.env` file loaded: `python -c "import os; from dotenv import load_dotenv; load_dotenv(); print(os.getenv('KAKVEDA_APP_ID'))"`
3. Test event-bus directly with curl (see Step 3)
4. Check Kakveda service logs: `docker logs kakveda-v10_event-bus_1 | tail -20`

---

## Complete Checklist

- [ ] Kakveda services running (`docker ps`)
- [ ] `.env` file created with correct URLs
- [ ] `kakveda_integration.py` copied to agent directory
- [ ] Warning endpoint test successful (curl)
- [ ] Event bus endpoint test successful (curl)
- [ ] `load_dotenv()` added to agent code
- [ ] `publish_event()` method added to governance manager
- [ ] `app_id` added to warning payload
- [ ] Events published after execution decisions
- [ ] Test 1 passes (no-governance)
- [ ] Test 2 passes (with governance, shows `[EVENT PUBLISHED]`)
- [ ] Test 3 passes (multiple runs)
- [ ] Dashboard shows agent and runs
- [ ] Dashboard shows warnings with correct confidence
- [ ] Dashboard shows patterns detected

---

## Common Issues & Quick Fixes

| Issue | Symptom | Fix |
|-------|---------|-----|
| Wrong port | "Connection refused" on 8000 | Update .env: `8105` |
| No .env loading | KAKVEDA_WARN_URL defaults to localhost:8000 | Add `load_dotenv()` at top |
| Missing app_id | Kakveda returns "Field required" | Add `"app_id": os.getenv(...)` to payload |
| Event publish fails | "422 Unprocessable Entity" | Use `{"topic": "...", "event": {...}}` format |
| No metrics in dashboard | Tests pass but dashboard empty | Check `[EVENT PUBLISHED]` in logs, verify event-bus working |

For more details: [TROUBLESHOOTING_SOLUTIONS.md](TROUBLESHOOTING_SOLUTIONS.md)

---

## Production Readiness

After completing all steps:

✅ Agent successfully integrates with Kakveda  
✅ Governance decisions enforced  
✅ Events published for observability  
✅ Metrics visible in dashboard  
✅ Ready for Phase 2 (failure learning)  

---

## Next Steps

1. **Phase 2:** Add failure detection patterns
2. **Phase 3:** Implement failure learning and escalation
3. **Production:** Deploy with your LLM framework
4. **Monitoring:** Set up alerts based on governance actions

---

**Status:** ✅ Setup complete and verified

All configurations are correct and tested against Kakveda v1.0.