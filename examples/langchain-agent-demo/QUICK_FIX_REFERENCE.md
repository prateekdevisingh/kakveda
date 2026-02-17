# Quick Fix Reference Card

**Note:** This document describes the legacy KakvedaGuard integration. The current SDK is `kakveda_sdk`; use `from kakveda_sdk import KakvedaAgent` and do not copy `kakveda_integration.py`.


**When something goes wrong, use this to find the solution fast.**

---

## Error: Connection Refused (port 8000)

```
ConnectionRefusedError: ... Connection refused
... port 8000
```

**Fix:** Update `.env`
```bash
KAKVEDA_WARN_URL=http://localhost:8105/warn
```

**Verify:**
```bash
curl http://localhost:8105/warn
```

---

## Error: Field Required (app_id)

```json
{"detail": [{"msg": "Field required", "loc": ["body", "app_id"]}]}
```

**Fix:** Add to warning payload
```python
payload = {
    "prompt": prompt,
    "tools": ["post_to_social"],
    "app_id": os.getenv("KAKVEDA_APP_ID", "phase1-demo"),  # ← ADD THIS
    "env": {"platform": platform},
}
```

---

## Error: 422 Unprocessable Entity (event-bus)

```
422 Client Error: Unprocessable Entity
```

**Fix:** Use correct event format
```python
# WRONG:
{"event_type": "trace.ingested", "payload": {...}}

# RIGHT:
{"topic": "trace.ingested", "event": {...}}
```

---

## Error: ModuleNotFoundError

```
ModuleNotFoundError: No module named 'kakveda_integration'
```

**Fix:** Copy module
```bash
cp ../kakveda_integration.py .
```

---

## No Metrics in Dashboard

**Check list:**
1. Is `.env` being loaded?
   ```bash
   python -c "import os; from dotenv import load_dotenv; load_dotenv(); print(os.getenv('KAKVEDA_APP_ID'))"
   ```
   Should show: `phase1-demo`

2. Does agent show `[EVENT PUBLISHED]`?
   ```bash
   python agent_app.py --platform linkedin --topic "test"
   ```
   Look for: `[EVENT PUBLISHED] trace.ingested`

3. Test event-bus directly:
   ```bash
   curl -X POST http://localhost:8100/publish \
     -H "Content-Type: application/json" \
     -d '{"topic": "trace.ingested", "event": {"app_id": "phase1-demo", "test": true}}' \
     | python -m json.tool
   ```
   Should return: `{"ok": true, "delivered": 2}`

---

## Code Not Loading .env

**Add to top of agent file:**
```python
from dotenv import load_dotenv
load_dotenv()
```

**Verify by printing:**
```python
import os
from dotenv import load_dotenv
load_dotenv()
print("WARN_URL:", os.getenv("KAKVEDA_WARN_URL"))
print("APP_ID:", os.getenv("KAKVEDA_APP_ID"))
```

---

## Event Publishing Not Working

**Add this method:**
```python
def publish_event(self, event_type: str, payload: dict) -> bool:
    event = {
        "topic": event_type,
        "event": {
            "app_id": self.app_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            **payload,
        }
    }
    try:
        response = requests.post(self.event_bus_url, json=event, timeout=10)
        response.raise_for_status()
        return True
    except Exception as e:
        print(f"Event publish failed: {e}")
        return False
```

**Call after execution:**
```python
self.kakveda.publish_event(
    "trace.ingested",
    {"tool": "post_to_social", "action": "executed"}
)
```

---

## Port Numbers (Reference)

| Service | Port | URL |
|---------|------|-----|
| Warning Policy | **8105** | http://localhost:8105/warn |
| Event Bus | 8100 | http://localhost:8100/publish |
| Dashboard | 8110 | http://localhost:8110 |

**Most common mistake:** Using **8000** instead of **8105**

---

## .env Template

Copy this to `langchain-agent-demo/.env`:

```bash
KAKVEDA_WARN_URL=http://localhost:8105/warn
KAKVEDA_EVENT_BUS_URL=http://localhost:8100/publish
KAKVEDA_APP_ID=phase1-demo
KAKVEDA_ENVIRONMENT=dev
KAKVEDA_FAIL_CLOSED=false
KAKVEDA_AUTO_APPROVE=true
```

---

## Verification Commands

```bash
# Check Kakveda running
docker ps | grep kakveda

# Test warning-policy
curl -s http://localhost:8105/warn \
  -H "Content-Type: application/json" \
  -d '{"prompt": "test", "tools": ["post_to_social"], "app_id": "phase1-demo", "env": {}}'

# Test event-bus
curl -s http://localhost:8100/publish \
  -H "Content-Type: application/json" \
  -d '{"topic": "trace.ingested", "event": {"app_id": "phase1-demo"}}'

# Check .env loading
python -c "import os; from dotenv import load_dotenv; load_dotenv(); print(os.getenv('KAKVEDA_WARN_URL'))"

# Run agent with governance
python agent_app.py --platform linkedin --topic "test"
```

Expected success output:
```
[GOVERNANCE] enabled
-> Sending to Kakveda...
--- KAKVEDA RESPONSE ---
{'action': 'warn', ...}
...
[EVENT PUBLISHED] trace.ingested
[FINAL RESULT] executed
```

---

## For Detailed Help

- **Full setup:** See [COMPLETE_SETUP_GUIDE.md](COMPLETE_SETUP_GUIDE.md)
- **All solutions:** See [TROUBLESHOOTING_SOLUTIONS.md](TROUBLESHOOTING_SOLUTIONS.md)
- **Integration code:** See [INTEGRATION_QUICK_REFERENCE.md](INTEGRATION_QUICK_REFERENCE.md)

---

**Last Updated:** 2026-02-17  
**All 5 issues documented and fixed**