# Before & After: Code Comparison (Legacy Reference)

**Note:** This document describes the legacy KakvedaGuard integration. The current SDK is `kakveda_sdk`; use `from kakveda_sdk import KakvedaAgent` and do not copy `kakveda_integration.py`.


**File:** `agent_app_phase1.py`  
**Purpose:** Visual guide showing exact changes for KakvedaGuard integration (legacy reference only)

---

## ✅ Recommended SDK-Managed Path

For supported integration, use `agent_app.py` with `KakvedaAgent` and skip manual guard wiring:

```python
from kakveda_sdk import KakvedaAgent
```

This legacy comparison remains for historical context.

---

## Change 1: Add Import at Top

### BEFORE
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

### AFTER
```python
#!/usr/bin/env python3
"""Phase 1: Standalone LangChain agent with mock social API (no Kakveda)."""

import argparse
import os
import time
from typing import Optional

import requests

import mock_social_api
from kakveda_sdk.guard import KakvedaGuard  # ← NEW LINE
```

### What Changed
- **1 line added** after all imports
- **What it does:** Brings the `KakvedaGuard` class into scope

---

## Change 2: Initialize Guard in `__init__`

### BEFORE
```python
class SimpleAgent:
    """Simple agent that generates content via LLM and publishes via tool."""

    def __init__(self, platform: str, governance_enabled: bool = False):
        self.platform = platform
        self.governance_enabled = governance_enabled
        self.llm = SimpleLLM()
```

### AFTER
```python
class SimpleAgent:
    """Simple agent that generates content via LLM and publishes via tool."""

    def __init__(self, platform: str, governance_enabled: bool = False):
        self.platform = platform
        self.governance_enabled = governance_enabled
        self.llm = SimpleLLM()
        self.guard = KakvedaGuard() if governance_enabled else None  # ← NEW LINE
```

### What Changed
- **1 line added** in `__init__` method
- **What it does:** Creates guard instance only when governance enabled

---

## Change 3: Complete `run()` Method Overhaul

### BEFORE
```python
    def run(self, prompt: str) -> str:
        """Run the agent."""
        print("[AGENT PROMPT]", prompt)

        # Step 1: LLM generates content
        content = self.llm.generate(prompt)
        print("[AGENT GENERATED CONTENT]", content)
        print("Generated Content:")
        print(f'"{content}"')

        # Step 2: Execute tool
        if not self.governance_enabled:
            print("[TOOL EXECUTION] no-governance")
            mock_social_api.post(content, self.platform)
            print("[FINAL RESULT] executed")
            return "executed"

        # Governance enabled (Phase 2 ready, but not used in Phase 1)
        print("[TOOL EXECUTION] governance (not called in phase 1)")
        mock_social_api.post(content, self.platform)
        print("[FINAL RESULT] executed")
        return "executed"
```

---

### AFTER
```python
    def run(self, prompt: str) -> str:
        """Run the agent."""
        print("[AGENT PROMPT]", prompt)

        # Step 1: LLM generates content
        content = self.llm.generate(prompt)
        print("[AGENT GENERATED CONTENT]", content)
        print("Generated Content:")
        print(f'"{content}"')

        # Helper function that wraps the real execution            # ← NEW
        def post_action():                                          # ← NEW
            """Execute the actual social media post."""             # ← NEW
            mock_social_api.post(content, self.platform)           # ← NEW
            return "posted"                                         # ← NEW
                                                                    # ← NEW
        # Step 2: Execute tool
        if not self.governance_enabled:
            print("[TOOL EXECUTION] no-governance")
            post_action()  # ← CHANGED (was mock_social_api.post())
            print("[FINAL RESULT] executed")
            return "executed"

        # Step 2b: Execute with governance                          # ← CHANGED
        if self.governance_enabled and self.guard:                 # ← NEW
            print("[TOOL EXECUTION] with-governance")              # ← NEW
            print("-> Sending to Kakveda...")                       # ← NEW
                                                                    # ← NEW
            result = self.guard.guarded_execute(                   # ← NEW
                prompt=content,                                     # ← NEW
                tool_name="post_to_social",                        # ← NEW
                execute_fn=post_action,                            # ← NEW
                metadata={"platform": self.platform}               # ← NEW
            )                                                       # ← NEW
                                                                    # ← NEW
            if result is None:                                      # ← NEW
                print("[EXECUTION DECISION] blocked by Kakveda")   # ← NEW
                print("[FINAL RESULT] blocked")                    # ← NEW
                return "blocked"                                    # ← NEW
            else:                                                   # ← NEW
                print("[EXECUTION DECISION] allowed")              # ← NEW
                print("[FINAL RESULT] executed")                   # ← NEW
                return "executed"                                   # ← NEW
                                                                    # ← NEW
        # Fallback                                                  # ← NEW
        print("[TOOL EXECUTION] no-governance")                    # ← NEW
        post_action()                                              # ← NEW
        print("[FINAL RESULT] executed")                           # ← NEW
        return "executed"                                          # ← NEW
```

### What Changed: Summary

| Element | Before | After | Reason |
|---------|--------|-------|--------|
| **Helper function** | ❌ None | ✅ `post_action()` | Wrappable by guard |
| **No-governance path** | Direct call | Via helper | Consistency |
| **Governance path** | Ignored | Calls `guard.guarded_execute()` | Core integration |
| **Block handling** | ❌ None | ✅ Returns `"blocked"` | Policy enforcement |
| **Fallback** | ❌ None | ✅ Via helper | Safety |

---

## Key Points

### 1. Helper Function Purpose
```python
def post_action():
    """Execute the actual social media post."""
    mock_social_api.post(content, self.platform)
    return "posted"
```

**Why:** `guard.guarded_execute()` expects a callable. This wraps the execution so the guard can:
- Call it if allowed
- Skip it if blocked

### 2. Guard Check Pattern
```python
if self.governance_enabled and self.guard:
    result = self.guard.guarded_execute(...)
    if result is None:
        return "blocked"
    else:
        return "executed"
```

**Why:** 
- Only guard if enabled AND initialized
- Returns `None` if blocked (guard's protocol)
- Distinguishes allowed vs blocked outcomes

### 3. Backward Compatibility
```python
if not self.governance_enabled:
    post_action()  # No guard involved
    return "executed"
```

**Why:** Phase 1 still works unchanged (critical for testing).

---

## Line-by-Line Changes Summary

### Change Location Map

```
File: agent_app_phase1.py

Line 13:  + from kakveda_sdk.guard import KakvedaGuard
Line 33:  + self.guard = KakvedaGuard() if governance_enabled else None
Line 48:  + def post_action():
Line 49:  + 
Line 50:  +     mock_social_api.post(content, self.platform)
Line 51:  +     return "posted"
Line 52:  + 
Line 56:  - mock_social_api.post(content, self.platform)
Line 56:  + post_action()
Line 60:  - print("[TOOL EXECUTION] governance (not called in phase 1)")
Line 61:  + if self.governance_enabled and self.guard:
Line 62:  +     print("[TOOL EXECUTION] with-governance")
Line 63:  +     print("-> Sending to Kakveda...")
Line 64:  +
Line 65:  +     result = self.guard.guarded_execute(
Line 66:  +         prompt=content,
Line 67:  +         tool_name="post_to_social",
Line 68:  +         execute_fn=post_action,
Line 69:  +         metadata={"platform": self.platform}
Line 70:  +     )
Line 71:  +
Line 72:  +     if result is None:
Line 73:  +         print("[EXECUTION DECISION] blocked by Kakveda")
Line 74:  +         print("[FINAL RESULT] blocked")
Line 75:  +         return "blocked"
Line 76:  +     else:
Line 77:  +         print("[EXECUTION DECISION] allowed")
Line 78:  +         print("[FINAL RESULT] executed")
Line 79:  +         return "executed"
Line 80:  +
Line 81:  + # Fallback
Line 82:  + print("[TOOL EXECUTION] no-governance")
Line 83:  + post_action()
Line 84:  + print("[FINAL RESULT] executed")
Line 85:  + return "executed"
```

**Total Changes:**
- New lines: ~25
- Modified lines: ~3
- Deleted lines: ~3
- **Net:** +25 lines added

---

## Test Cases: Expected Output

### Test 1: `python agent_app_phase1.py --platform linkedin --topic "AI growth" --no-governance`

```
[PLATFORM] linkedin
[TOPIC] AI growth
[GOVERNANCE] disabled

[AGENT PROMPT] Write a concise social media post about AI growth.
[AGENT GENERATED CONTENT] Sharing a short product update...
Generated Content:
"Sharing a short product update..."
[TOOL EXECUTION] no-governance              ← Uses helper
[MOCK POST SUCCESS] Platform: Linkedin        ← Executed
[FINAL RESULT] executed                       ← Success

[DONE] elapsed=0.00s
```

✅ **Verification:** Same as before (backward compatible)

---

### Test 2: `python agent_app_phase1.py --platform linkedin --topic "AI growth"` (no flag)

```
[GOVERNANCE] enabled

[AGENT GENERATED CONTENT] ...
[TOOL EXECUTION] with-governance             ← Guard active
-> Sending to Kakveda...
[EXECUTION DECISION] blocked by Kakveda      ← Guard decision
[FINAL RESULT] blocked                        ← Stopped

[DONE] elapsed=0.00s
```

✅ **Verification:** Guard called, enforcement works

---

### Test 3: `KAKVEDA_FAIL_CLOSED=false python agent_app_phase1.py --platform linkedin --topic "AI growth"`

```
[GOVERNANCE] enabled
[TOOL EXECUTION] with-governance
-> Sending to Kakveda...
[EXECUTION DECISION] allowed                  ← Fails open
[MOCK POST SUCCESS] Platform: Linkedin
[FINAL RESULT] executed

[DONE] elapsed=0.00s
```

✅ **Verification:** Continues if Kakveda unavailable

---

## Copy-Paste Reference

### Full New Import Line
```
from kakveda_sdk.guard import KakvedaGuard
```

### Full New Init Line
```
self.guard = KakvedaGuard() if governance_enabled else None
```

### Full New Helper Function
```python
        def post_action():
            """Execute the actual social media post."""
            mock_social_api.post(content, self.platform)
            return "posted"
```

### Full New Guard Logic (Replaces Old Governance Section)
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

---

## Quick Review Checklist

Before testing, verify:

- [ ] Import line added (line 13)
- [ ] Guard initialization in `__init__` (line 33)
- [ ] Helper function defined (lines 48-51)
- [ ] No-governance branch uses helper (line 56)
- [ ] Governance branch calls `guard.guarded_execute()` (lines 65-70)
- [ ] Block handling returns "blocked" (line 75)
- [ ] Fallback logic at end (lines 81-85)
- [ ] File runs without syntax errors
- [ ] All three tests pass

---

**Ready to integrate?** Follow the edits above in order, test the three scenarios, done!