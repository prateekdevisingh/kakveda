# Manual Integration Guide: Adding KakvedaGuard to agent_app_phase1.py

**Note:** This document describes the legacy KakvedaGuard integration. The current SDK is `kakveda_sdk`; use `from kakveda_sdk import KakvedaAgent` and do not copy `kakveda_integration.py`.


**Date:** 2026-02-17  
**File:** `agent_app_phase1.py`  
**Goal:** Manually integrate Kakveda governance without code generation

---

## ⚠️ CRITICAL: Environment Configuration FIRST

**Before you integrate code, you MUST set up the environment correctly:**

### 1. Verify Kakveda is Running
```bash
docker ps | grep kakveda
```

You should see these running:
- `kakveda-v10_warning-policy_1` (port 8105)
- `kakveda-v10_event-bus_1` (port 8100)
- `kakveda-v10_dashboard_1` (port 8110)

### 2. Create/Update `.env` File
In `langchain-agent-demo/` folder, ensure `.env` contains:

```bash
KAKVEDA_WARN_URL=http://localhost:8105/warn
KAKVEDA_EVENT_BUS_URL=http://localhost:8100/publish
KAKVEDA_APP_ID=phase1-demo
KAKVEDA_ENVIRONMENT=dev
KAKVEDA_FAIL_CLOSED=false
```

**⚠️ IMPORTANT:** Port is **8105** NOT 8000!

### 3. Copy Integration Module
```bash
cp ../kakveda_integration.py .
```

### 4. Test Connectivity
```bash
curl -s http://localhost:8105/warn \
  -H "Content-Type: application/json" \
  -d '{"prompt": "test", "tools": ["post_to_social"], "app_id": "phase1-demo", "env": {}}' | python -m json.tool
```

If this fails, **stop and read [TROUBLESHOOTING_SOLUTIONS.md](TROUBLESHOOTING_SOLUTIONS.md)**

---

## Overview

This guide walks you through **manually integrating KakvedaGuard** into the standalone Phase 1 agent. After integration:

- Phase 1 agent works with OR without governance
- No Kakveda dependency (backward compatible)
- Easy to understand each step
- Sets up foundation for Phase 2

---

## Current State

Your `agent_app_phase1.py` has:

```python
✅ SimpleLLM class — generates content deterministically
✅ SimpleAgent class — wraps LLM and execution
✅ run() method — orchestrates agent flow
✅ main() function — CLI entry point
```

**Missing:**
```
❌ KakvedaGuard initialization
❌ Governance-wrapped execution
❌ Policy decision handling
```

---

## Step 1: Import KakvedaGuard

**Location:** Top of file (after existing imports)

**Current code (lines 1-11):**
```python
#!/usr/bin/env python3
"""Phase 1: Standalone LangChain agent with mock social API (no Kakveda)."""

import argparse
import os
import time
from typing import Optional

import requests

import mock_social_api
```

**What to do:**
Add ONE line after `import mock_social_api`:

```python
from kakveda_integration import KakvedaGuard
```

**Result:**
```python
import mock_social_api
from kakveda_integration import KakvedaGuard  # ← NEW
```

**Why:** Brings the `KakvedaGuard` class into scope so you can use it.

---

## Step 2: Initialize Guard in `__init__`

**Location:** `SimpleAgent.__init__()` method (around line 28-32)

**Current code:**
```python
class SimpleAgent:
    """Simple agent that generates content via LLM and publishes via tool."""

    def __init__(self, platform: str, governance_enabled: bool = False):
        self.platform = platform
        self.governance_enabled = governance_enabled
        self.llm = SimpleLLM()
```

**What to do:**
Add initialization ONLY if governance is enabled. Add after line 32:

```python
        self.llm = SimpleLLM()
        
        # Initialize Kakveda guard for governance-enabled mode
        self.guard = KakvedaGuard() if governance_enabled else None
```

**Result:**
```python
    def __init__(self, platform: str, governance_enabled: bool = False):
        self.platform = platform
        self.governance_enabled = governance_enabled
        self.llm = SimpleLLM()
        self.guard = KakvedaGuard() if governance_enabled else None
```

**Why:** 
- Creates guard instance only when needed
- `None` when governance disabled (no waste)
- Allows both modes in same code

---

## Step 3: Create Execution Wrapper Function

**Location:** Inside the `run()` method, create a helper function

**Before editing, understand the pattern:**

You need to wrap the execution call so Kakveda can guard it:

```
Without guard:
  mock_social_api.post(content, platform) 
  → Direct execution

With guard:
  guard.guarded_execute(
      prompt=content,
      tool_name="post_to_social",
      execute_fn=lambda: mock_social_api.post(content, platform)
  )
  → Guarded execution
```

**What to do:**

In the `run()` method, **before** the `if not self.governance_enabled:` block (around line 45), define a helper:

```python
    def run(self, prompt: str) -> str:
        """Run the agent."""
        print("[AGENT PROMPT]", prompt)

        # Step 1: LLM generates content
        content = self.llm.generate(prompt)
        print("[AGENT GENERATED CONTENT]", content)
        print("Generated Content:")
        print(f'"{content}"')

        # ← ADD HELPER FUNCTION HERE (before the if statement)
        def post_action():
            """Execute the actual social media post."""
            mock_social_api.post(content, self.platform)
            return "posted"
```

**Result structure:**
```python
        print(f'"{content}"')

        # Helper function that wraps the real execution
        def post_action():
            """Execute the actual social media post."""
            mock_social_api.post(content, self.platform)
            return "posted"

        # Step 2: Execute tool
        if not self.governance_enabled:
            # ... rest of code
```

**Why:** 
- Encapsulates the execution logic
- Can be passed to `guard.guarded_execute()`
- Keeps code clean and readable

---

## Step 4: Handle No-Governance Path (Keep AS-IS)

**Location:** Lines 46-51

**Current code:**
```python
        # Step 2: Execute tool
        if not self.governance_enabled:
            print("[TOOL EXECUTION] no-governance")
            mock_social_api.post(content, self.platform)
            print("[FINAL RESULT] executed")
            return "executed"
```

**What to do:**
✅ **Keep this EXACTLY as-is**

This path runs when governance is disabled. No changes needed.

**Why:** Tests that agent works standalone (Phase 1 goal).

---

## Step 5: Handle Governance-Enabled Path (NEW)

**Location:** Lines 52-56 (currently the "else" path)

**Current code:**
```python
        # Governance enabled (Phase 2 ready, but not used in Phase 1)
        print("[TOOL EXECUTION] governance (not called in phase 1)")
        mock_social_api.post(content, self.platform)
        print("[FINAL RESULT] executed")
        return "executed"
```

**What to do:**
Replace this entire block with governance-aware logic:

```python
        # Step 2b: Execute with governance
        if self.governance_enabled and self.guard:
            print("[TOOL EXECUTION] with-governance")
            print("-> Sending to Kakveda...")
            
            # Call guard.guarded_execute() instead of direct execution
            result = self.guard.guarded_execute(
                prompt=content,
                tool_name="post_to_social",
                execute_fn=post_action,
                metadata={"platform": self.platform}
            )
            
            # Handle the result
            if result is None:
                print("[EXECUTION DECISION] blocked by Kakveda")
                print("[FINAL RESULT] blocked")
                return "blocked"
            else:
                print("[EXECUTION DECISION] allowed")
                print("[FINAL RESULT] executed")
                return "executed"
        
        # Fallback (governance disabled)
        print("[TOOL EXECUTION] no-governance")
        post_action()
        print("[FINAL RESULT] executed")
        return "executed"
```

**Result:**
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

**Why:**
- Checks both conditions: governance enabled AND guard initialized
- Calls `guard.guarded_execute()` with proper parameters
- Handles blocked case (returns None)
- Logs governance decision visibly

---

## Step 6: Complete Modified `run()` Method

After all edits, your `run()` method should look like:

```python
    def run(self, prompt: str) -> str:
        """Run the agent."""
        print("[AGENT PROMPT]", prompt)

        # Step 1: LLM generates content
        content = self.llm.generate(prompt)
        print("[AGENT GENERATED CONTENT]", content)
        print("Generated Content:")
        print(f'"{content}"')

        # Helper function that wraps the real execution
        def post_action():
            """Execute the actual social media post."""
            mock_social_api.post(content, self.platform)
            return "posted"

        # Step 2: Execute tool
        if not self.governance_enabled:
            print("[TOOL EXECUTION] no-governance")
            post_action()
            print("[FINAL RESULT] executed")
            return "executed"

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

---

## Test: Verify Integration

### Test 1: No Governance (Backward Compatible)

```bash
python agent_app_phase1.py --platform linkedin --topic "AI growth" --no-governance
```

**Expected output:**
```
[PLATFORM] linkedin
[TOPIC] AI growth
[GOVERNANCE] disabled

[AGENT PROMPT] Write a concise social media post about AI growth.
[AGENT GENERATED CONTENT] Sharing a short product update...
Generated Content:
"Sharing a short product update and a genuine lesson learned from the last sprint."
[TOOL EXECUTION] no-governance
[MOCK POST SUCCESS] Platform: Linkedin
Content:
Sharing a short product update and a genuine lesson learned from the last sprint.
[FINAL RESULT] executed

[DONE] elapsed=0.00s
```

✅ **Success:** Same behavior as Phase 1 (no governance changes).

---

### Test 2: With Governance (Kakveda Unavailable)

```bash
python agent_app_phase1.py --platform linkedin --topic "AI growth"
```

(No `--no-governance` flag = governance enabled)

**Expected output:**
```
[PLATFORM] linkedin
[TOPIC] AI growth
[GOVERNANCE] enabled

[AGENT PROMPT] Write a concise social media post about AI growth.
[AGENT GENERATED CONTENT] Sharing a short product update...
Generated Content:
"Sharing a short product update and a genuine lesson learned from the last sprint."
[TOOL EXECUTION] with-governance
-> Sending to Kakveda...
[KAKVEDA] preflight: action=block confidence=0.00
[KAKVEDA] Execution blocked by policy
[EXECUTION DECISION] blocked by Kakveda
[FINAL RESULT] blocked

[DONE] elapsed=0.00s
```

✅ **Success:** Guard tried to check Kakveda, failed gracefully (fail-closed by default).

---

### Test 3: With Governance (Fail-Open Mode)

```bash
KAKVEDA_FAIL_CLOSED=false python agent_app_phase1.py --platform linkedin --topic "AI growth"
```

**Expected output:**
```
[PLATFORM] linkedin
[GOVERNANCE] enabled

[TOOL EXECUTION] with-governance
-> Sending to Kakveda...
[KAKVEDA] preflight: action=silent confidence=0.00
[KAKVEDA] Event publishing failed (trace.ingested): ...
[EXECUTION DECISION] allowed
[MOCK POST SUCCESS] Platform: Linkedin
[FINAL RESULT] executed

[DONE] elapsed=0.00s
```

✅ **Success:** Guard allows execution even if Kakveda unavailable.

---

## Configuration: Environment Variables

**Optional. Set these BEFORE running to customize behavior:**

```bash
# Default endpoints
export KAKVEDA_WARN_URL=http://localhost:8000/warn
export KAKVEDA_EVENT_BUS_URL=http://localhost:8100/publish

# App context
export KAKVEDA_APP_ID=phase1-demo
export KAKVEDA_ENVIRONMENT=development

# Failure modes
export KAKVEDA_FAIL_CLOSED=false        # Allow if Kakveda unavailable
export KAKVEDA_AUTO_APPROVE=true        # Auto-approve require-approval
```

Then run:
```bash
python agent_app_phase1.py --platform linkedin --topic "AI growth"
```

---

## Summary of Changes

| Component | Lines | Change | Impact |
|-----------|-------|--------|--------|
| **Import** | 1 | Add `from kakveda_integration import KakvedaGuard` | Brings guard into scope |
| **__init__** | 2 | Add `self.guard = KakvedaGuard() if governance_enabled else None` | Initializes guard conditionally |
| **run()** | +20 | Add helper function + governance logic | Wraps execution with policy check |
| **Total edits** | ~35 lines modified | 3 distinct changes | Full governance support |

---

## Understanding the Flow

### Without Governance (`--no-governance`)

```
User Input
  ↓
Agent → LLM generates content
  ↓
Execution (direct)
  ↓
mock_social_api.post() → [FINAL RESULT] executed
```

### With Governance (no flag)

```
User Input
  ↓
Agent → LLM generates content
  ↓
Kakveda Guard (preflight)
  ├─ If blocked → [FINAL RESULT] blocked (stop here)
  └─ If allowed → Execution
       ↓
       mock_social_api.post() → [FINAL RESULT] executed
       ↓
       Publish event to Kakveda
```

---

## Debugging Checklist

| Issue | Cause | Solution |
|-------|-------|----------|
| `NameError: KakvedaGuard not defined` | Import missing | Add `from kakveda_integration import KakvedaGuard` |
| `self.guard is None` | Governance disabled | Run without `--no-governance` flag |
| Always returns "blocked" | `KAKVEDA_FAIL_CLOSED=true` | Set `KAKVEDA_FAIL_CLOSED=false` to allow |
| Guard not called | Governance not enabled | Remove `--no-governance` flag or fix condition |
| Event publishing errors | Kakveda unavailable | Expected — non-blocking, falls through |

---

## Next Steps

1. **Make the edits** following Steps 1-5 above
2. **Test all three scenarios** (Tests 1, 2, 3)
3. **Verify backward compatibility** (Test 1 should work exactly as before)
4. **You're done with Phase 1 integration!**

From here:
- Phase 2 integration follows same pattern
- Phase 3 demonstrates failure learning

---

## Reference: Key Methods

### `guard.guarded_execute()`

```python
result = guard.guarded_execute(
    prompt="...",              # User input or content to evaluate
    tool_name="...",           # Name of the tool/action
    execute_fn=function,       # Callable that does the real work
    metadata={...}             # Optional context (platform, user_id, etc.)
)
```

Returns:
- Function result if allowed
- `None` if blocked

### `guard.preflight()`

(Called internally, no need to use directly)

```python
decision = guard.preflight(prompt, tool, metadata)
```

Returns: `{"action", "confidence", "pattern_id", "message"}`

### `guard.publish()`

(Called internally)

```python
guard.publish(event_type="trace.ingested", payload={...})
```

Non-blocking, always succeeds or fails silently.

---

## Validation: File Checklist

After edits:

- [ ] `from kakveda_integration import KakvedaGuard` at top
- [ ] `self.guard = KakvedaGuard() if governance_enabled else None` in `__init__`
- [ ] `def post_action():` helper function in `run()`
- [ ] `if not self.governance_enabled:` block unchanged
- [ ] `if self.governance_enabled and self.guard:` block with guard call
- [ ] Fallback logic handles all cases
- [ ] Tests 1, 2, 3 all pass

---

**Status:** Ready to integrate manually following this guide.

All edits are **safe**, **backward compatible**, and **easy to understand**.