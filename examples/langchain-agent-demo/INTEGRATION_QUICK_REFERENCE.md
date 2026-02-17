# Integration Quick Reference Card

**Note:** This document describes the legacy KakvedaGuard integration. The current SDK is `kakveda_sdk`; use `from kakveda_sdk import KakvedaAgent` and do not copy `kakveda_integration.py`.


**File:** `agent_app_phase1.py`  
**Task:** Add KakvedaGuard in 4 steps  
**Time:** ~5 minutes  

---

## ⚠️ SETUP FIRST (Required!)

Before integrating code:

1. **Check Kakveda running:** `docker ps | grep kakveda`
2. **Create `.env` file:**
   ```bash
   KAKVEDA_WARN_URL=http://localhost:8105/warn
   KAKVEDA_EVENT_BUS_URL=http://localhost:8100/publish
   KAKVEDA_APP_ID=phase1-demo
   KAKVEDA_ENVIRONMENT=dev
   KAKVEDA_FAIL_CLOSED=false
   ```
3. **Copy module:** `cp ../kakveda_integration.py .`
4. **Test connection:**
   ```bash
   curl -s http://localhost:8105/warn -H "Content-Type: application/json" \
     -d '{"prompt": "test", "tools": ["post_to_social"], "app_id": "phase1-demo", "env": {}}'
   ```

If test fails → Read [TROUBLESHOOTING_SOLUTIONS.md](TROUBLESHOOTING_SOLUTIONS.md)

---

## The 4 Steps

### Step 1️⃣ Import (1 line)
```python
from kakveda_integration import KakvedaGuard
```
**Where:** After `import mock_social_api` (line 12)

---

### Step 2️⃣ Initialize (1 line)
```python
self.guard = KakvedaGuard() if governance_enabled else None
```
**Where:** In `SimpleAgent.__init__()` after `self.llm = SimpleLLM()` (line 33)

---

### Step 3️⃣ Create Helper (5 lines)
```python
def post_action():
    """Execute the actual social media post."""
    mock_social_api.post(content, self.platform)
    return "posted"
```
**Where:** In `run()` method before the `if not self.governance_enabled:` block (lines 48-52)

---

### Step 4️⃣ Guard Logic (26 lines)
Replace the old "governance" comment section with:

```python
        # Step 2b: Execute with governance
        if self.governance_enabled and self.guard:
            print("[TOOL EXECUTION] with-governance")
            print("-> Sending to Kakveda...")
            
            result = self.guard.guarded_execute(
                prompt=content,
                tool_name="post_to_social",
                execute_fn=post_action,
                metadata={"platform": self.platform}
            )
            
            if result is None:
                print("[EXECUTION DECISION] blocked by Kakveda")
                print("[FINAL RESULT] blocked")
                return "blocked"
            else:
                print("[EXECUTION DECISION] allowed")
                print("[FINAL RESULT] executed")
                return "executed"
        
        # Fallback
        print("[TOOL EXECUTION] no-governance")
        post_action()
        print("[FINAL RESULT] executed")
        return "executed"
```

**Where:** Replace lines 52-58 (the old governance else block)

---

## Verification: Run These 3 Tests

### ✅ Test 1: No Governance (Should work same as before)
```bash
python agent_app_phase1.py --platform linkedin --topic "AI growth" --no-governance
```

**Expected:** `[FINAL RESULT] executed`

---

### ✅ Test 2: With Governance (Kakveda unavailable, fail-closed)
```bash
python agent_app_phase1.py --platform linkedin --topic "AI growth"
```

**Expected:** `[FINAL RESULT] blocked`

---

### ✅ Test 3: With Governance (Fail-open mode)
```bash
KAKVEDA_FAIL_CLOSED=false python agent_app_phase1.py --platform linkedin --topic "AI growth"
```

**Expected:** `[FINAL RESULT] executed`

---

## Key Concepts in 30 Seconds

| Concept | Meaning |
|---------|---------|
| `governance_enabled` | Boolean flag to enable/disable guard |
| `self.guard` | KakvedaGuard instance (None if disabled) |
| `post_action()` | Wraps execution so guard can control it |
| `guard.guarded_execute()` | Ask guard permission, then execute if allowed |
| `result is None` | Guard blocked execution |
| `result is not None` | Guard allowed execution |

---

## Files Changed

```
agent_app_phase1.py
├── Line 13:  + 1 import
├── Line 33:  + 1 initialization
├── Lines 48-52:  + 1 helper function
└── Lines 52-85:  + 1 guard logic section
```

**Total Changes:** ~35 lines (25 added, 3 modified, 3 deleted)

---

## If Something Breaks

| Error | Fix |
|-------|-----|
| `NameError: KakvedaGuard not defined` | Check Step 1 (import added) |
| `AttributeError: guard` | Check Step 2 (init added) |
| Always blocked | Check Test 2 vs Test 3 (fail-closed mode) |
| Syntax error | Check indentation in Steps 3-4 |

---

## Detailed Docs

- **Full Guide:** `INTEGRATION_MANUAL.md` (step-by-step with explanations)
- **Code Comparison:** `BEFORE_AFTER_COMPARISON.md` (before/after visuals)
- **API Reference:** `../INTEGRATION.md` (full KakvedaGuard API)
- **Examples:** `../integration_examples.py` (4 usage patterns)

---

## Done! ✨

After completing all 4 steps + running tests, you have:
- ✅ Phase 1 agent with governance support
- ✅ Backward compatibility (--no-governance works)
- ✅ Policy enforcement (blocks when told)
- ✅ Foundation for Phase 2

**Next:** Read `PHASES.md` for Phase 2 concepts.