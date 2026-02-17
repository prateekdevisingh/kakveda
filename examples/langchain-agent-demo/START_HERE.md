# 📦 Deliverable: Manual Integration Documentation Suite

**Note:** This document describes the legacy KakvedaGuard integration. The current SDK is `kakveda_sdk`; use `from kakveda_sdk import KakvedaAgent` and do not copy `kakveda_integration.py`.


**Date:** 2026-02-17  
**Status:** ✅ Complete with all fixes  
**Format:** Documentation (no code changes required from user)  
**Time to read:** 5-20 min (user's choice)  
**Time to complete integration:** 15-30 min  

---

## 🚨 CRITICAL: READ FIRST

**Before starting any integration, read these in order:**

1. **[COMPLETE_SETUP_GUIDE.md](COMPLETE_SETUP_GUIDE.md)** ← **START HERE**
   - ✅ Verify Kakveda running
   - ✅ Create `.env` with correct URLs
   - ✅ Test connectivity (critical!)
   - ✅ Complete setup checklist
   - ✅ Includes all fixes for common issues

2. **[TROUBLESHOOTING_SOLUTIONS.md](TROUBLESHOOTING_SOLUTIONS.md)** ← **For Any Issues**
   - 5 common problems with solutions
   - Quick error reference
   - Verification commands

**Only proceed to integration guides below after completing the setup guide.**

---

## ✅ Current Recommended Path (Managed Agent)

If your goal is **full Kakveda integration** (governance + event bus + dashboard agent visibility), use the managed agent flow in this folder:

**What is already wired:**
- `kakveda_sdk` exposes `KakvedaAgent` (guard + registration + heartbeat).
- `agent_app.py` starts a `/health` server and uses `KakvedaAgent` directly.

**What you must configure (via `.env` or environment variables):**
- `KAKVEDA_WARN_URL` (default should be `http://warning-policy:8105/warn`)
- `KAKVEDA_EVENT_BUS_URL` (default should be `http://event-bus:8100/publish`)
- `DASHBOARD_URL` (default should be `http://dashboard:8110`)
- `DASHBOARD_API_KEY` (project API key)
- `AGENT_NAME`, `AGENT_APP_ID`, `AGENT_VERSION`
- `HEARTBEAT_INTERVAL` (optional)

**Run managed agent (shows up in dashboard):**
```bash
python agent_app.py --platform linkedin --topic "AI growth"
```

**Expected results:**
- Agent appears in Kakveda dashboard under **Agents**
- `GET /health` responds on port `8120`
- `trace.ingested` events appear under Runs/Traces


---

## What You Got

**3 comprehensive guide documents** that walk you through manually integrating KakvedaGuard into `agent_app_phase1.py`:

### 1. ⚡ INTEGRATION_QUICK_REFERENCE.md (4.1 KB)
**One-page cheat sheet**
- 4 steps to integration (code ready to copy)
- 3 verification tests
- Key concepts summary
- Troubleshooting table
- File change summary

**Best for:** "Just tell me what to do" / Copy-paste enthusiasts  
**Read time:** 5 minutes

···

### 2. 📖 INTEGRATION_MANUAL.md (16 KB)
**Complete step-by-step guide with detailed explanations**
- Current state analysis
- Step 1: Import KakvedaGuard (explained)
- Step 2: Initialization (explained)
- Step 3: Create wrapper function (explained)
- Step 4: No-governance path (explained)
- Step 5: Governance-enabled path (explained)
- Step 6: Complete modified method (full code)
- 3 tests with all expected output
- Configuration environment variables
- Summary with impact analysis
- Debugging checklist
- Reference: key methods
- Validation checklist

**Best for:** Understanding every line you're adding  
**Read time:** 15-20 minutes

···

### 3. 🔍 BEFORE_AFTER_COMPARISON.md (12 KB)
**Visual side-by-side code comparison**
- Change 1: Import (before/after)
- Change 2: __init__ (before/after)
- Change 3: run() method (before/after with ~26 new lines)
- Detailed change summary table
- Key points deep-dive
- Line-by-line changes map
- Test cases with outputs
- Copy-paste reference blocks (4 complete blocks)
- Quick review checklist

**Best for:** Visual learners / Code-focused understanding  
**Read time:** 10 minutes

···

### 4. 🎯 DOCUMENTATION_INDEX.md (11 KB)
**Navigation and reference guide**
- Choose your path (quick/manual/visual)
- 4 steps at a glance (table)
- How integration works (before/after flow)
- Common questions (FAQ)
- File structure map
- Support guide

**Best for:** Deciding which doc to read / Finding answers  
**Read time:** 5 minutes

---

## File Inventory

```
langchain-agent-demo/
├── INTEGRATION_QUICK_REFERENCE.md      ← 4.1 KB (New ✨)
├── INTEGRATION_MANUAL.md               ← 16 KB (New ✨)
├── BEFORE_AFTER_COMPARISON.md          ← 12 KB (New ✨)
├── DOCUMENTATION_INDEX.md              ← 11 KB (New ✨)
├── README.md                           ← 5.3 KB (Updated)
├── PHASES.md                           ← 5.1 KB (Existing)
├── QUICKSTART.md                       ← 3.1 KB (Existing)
├── SUMMARY.md                          ← 4.7 KB (Existing)
├── agent_app_phase1.py                 (File to edit)
├── agent_app_phase2.py                 (Reference)
├── agent_app.py                        (Reference)
└── mock_social_api.py                  (Reference)
```

**New Files:** 4 markdown guides (43 KB total)

---

## How to Use

### Path 1: Impatient (5 min → Implement)
1. Read [INTEGRATION_QUICK_REFERENCE.md](INTEGRATION_QUICK_REFERENCE.md) (4 steps + tests)
2. Edit `agent_app_phase1.py` following the 4 steps
3. Run the 3 tests
4. ✅ Done

**Total time:** 15-20 min

---

### Path 2: Understanding (20 min → Implement)
1. Read [DOCUMENTATION_INDEX.md](DOCUMENTATION_INDEX.md) (overview)
2. Read [INTEGRATION_MANUAL.md](INTEGRATION_MANUAL.md) (Steps 1-5)
3. Reference [BEFORE_AFTER_COMPARISON.md](BEFORE_AFTER_COMPARISON.md) (for code comparison)
4. Edit `agent_app_phase1.py` using QUICK_REFERENCE
5. Run tests
6. ✅ Done

**Total time:** 30-40 min

---

### Path 3: Visual (10 min → Implement)
1. Read [BEFORE_AFTER_COMPARISON.md](BEFORE_AFTER_COMPARISON.md) (side-by-side diffs)
2. Use [INTEGRATION_QUICK_REFERENCE.md](INTEGRATION_QUICK_REFERENCE.md) (copy-paste code)
3. Edit file
4. Run tests
5. ✅ Done

**Total time:** 20-25 min

---

## What Gets Added to Your File

```
agent_app_phase1.py
├─ Line 12:   + from kakveda_integration import KakvedaGuard
├─ Line 33:   + self.guard = KakvedaGuard() if governance_enabled else None
├─ Lines 48-52:  + def post_action(): wrapper function
├─ Lines 56:     CHANGE mock_social_api.post() to post_action()
└─ Lines 60-85:  REPLACE governance section with guard logic
```

**Total additions:** ~35 lines  
**Changes to existing code:** Minimal  
**Backward compatibility:** ✅ Full (--no-governance works unchanged)

---

## The 3 Integration Steps at a Glance

| Step | Action | Location | Impact |
|------|--------|----------|--------|
| 1 | Add import | Top of file (line 12) | Brings KakvedaGuard into scope |
| 2 | Initialize guard | `SimpleAgent.__init__()` (line 33) | Creates guard conditionally |
| 3 | Create helper | `run()` method (lines 48-52) | Wrappable execution |
| 4 | Add guard logic | `run()` method (lines 60-85) | Governance decisions |

---

## Verification Tests

Each guide includes 3 tests to verify integration:

### ✅ Test 1: No Governance (Backward Compatible)
```bash
python agent_app_phase1.py --platform linkedin --topic "AI growth" --no-governance
```

Expected: `[FINAL RESULT] executed`

---

### ✅ Test 2: With Governance (Default: Fail-Closed)
```bash
python agent_app_phase1.py --platform linkedin --topic "AI growth"
```

Expected: `[FINAL RESULT] blocked`

---

### ✅ Test 3: With Governance (Fail-Open)
```bash
KAKVEDA_FAIL_CLOSED=false python agent_app_phase1.py --platform linkedin --topic "AI growth"
```

Expected: `[FINAL RESULT] executed`

---

## Key Features of This Documentation

✅ **Step-by-step:** Every change explained  
✅ **Copy-paste ready:** Code snippets ready to use  
✅ **Before/after:** Visual comparison of changes  
✅ **Multiple formats:** Quick reference, detailed, visual, FAQ  
✅ **Testable:** 3 verification tests included  
✅ **Debuggable:** Troubleshooting guide included  
✅ **Cross-referenced:** Links between docs  
✅ **Backward compatible:** Phase 1 works unchanged  
✅ **No framework lock-in:** Works without Kakveda running  

---

## Quick Reference: The 4 Code Changes

### Change 1: Add Import (1 line)
```python
from kakveda_integration import KakvedaGuard
```

### Change 2: Initialize Guard (1 line)
```python
self.guard = KakvedaGuard() if governance_enabled else None
```

### Change 3: Create Helper (5 lines)
```python
def post_action():
    """Execute the actual social media post."""
    mock_social_api.post(content, self.platform)
    return "posted"
```

### Change 4: Guard Logic (~26 lines)
```python
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

## Success Criteria

After following any of the guides, you'll have:

✅ `SimpleAgent.__init__()` initializes `self.guard`  
✅ `run()` method uses `guard.guarded_execute()` for governance  
✅ Execution can be blocked or allowed based on policy  
✅ Test 1 passes (backward compatible, `--no-governance` works)  
✅ Test 2 passes (governance enabled, blocks when unavailable)  
✅ Test 3 passes (governance enabled, allows when fail-open)  
✅ `agent_app_phase1.py` still runs the Phase 1 verification

---

## What These Docs Reduce

❌ **No** guessing about which line to edit  
❌ **No** confusion about imports or initialization  
❌ **No** uncertainty about before/after state  
❌ **No** difficulty understanding governance decisions  
❌ **No** fear of breaking backward compatibility  
❌ **No** mysterious test failures (all expected outputs documented)  

---

## Getting Started

1. **Choose your path** → See "How to Use" above
2. **Pick the right doc** → QUICK_REFERENCE, MANUAL, or BEFORE_AFTER
3. **Read it** → Takes 5-20 minutes
4. **Make edits** → Follow steps 1-4
5. **Run tests** → Verify all 3 pass
6. **Done!** → Integration complete ✅

---

## File Organization

All files are in: `/home/prateek/Documents/kakveda/kakveda-v1.0/examples/langchain-agent-demo/`

```
Start here:
├─ DOCUMENTATION_INDEX.md (YOU ARE HERE - navigation guide)
└─ Then choose:
   ├─ INTEGRATION_QUICK_REFERENCE.md (impatient)
   ├─ INTEGRATION_MANUAL.md (understand)
   └─ BEFORE_AFTER_COMPARISON.md (visual)
```

---

## Questions?

| Question | Answer |
|----------|--------|
| Where do I start? | Read DOCUMENTATION_INDEX.md (this file) |
| I'm impatient | Read INTEGRATION_QUICK_REFERENCE.md (5 min) |
| I want to understand | Read INTEGRATION_MANUAL.md (15-20 min) |
| I learn by seeing differences | Read BEFORE_AFTER_COMPARISON.md (10 min) |
| Tests don't pass | Check INTEGRATION_MANUAL.md → Debugging Checklist |
| I broke something | Check INTEGRATION_QUICK_REFERENCE.md → If Something Breaks |
| What about Phase 2? | Read PHASES.md in same folder |
| Want full API reference? | Read ../INTEGRATION.md |

---

## Deliverable Summary

| Item | Description | Size | Status |
|------|-------------|------|--------|
| INTEGRATION_QUICK_REFERENCE.md | One-page cheat sheet | 4.1 KB | ✅ Created |
| INTEGRATION_MANUAL.md | Step-by-step guide | 16 KB | ✅ Created |
| BEFORE_AFTER_COMPARISON.md | Visual diff guide | 12 KB | ✅ Created |
| DOCUMENTATION_INDEX.md | Navigation guide | 11 KB | ✅ Created |
| README.md | Updated with doc links | 5.3 KB | ✅ Updated |
| Code snippets | Copy-paste ready | - | ✅ Included |
| Tests | 3 verification tests | - | ✅ Documented |
| Troubleshooting | Debugging checklist | - | ✅ Included |

---

## Next Steps

1. **Read the guide** of your choice (5-20 min)
2. **Edit `agent_app_phase1.py`** following the steps (15 min)
3. **Run the 3 tests** to verify (5 min)
4. **Celebrate** 🎉 (Phase 1 integration complete!)

Then:
- Review PHASES.md for Phase 2 concepts
- Check ../INTEGRATION.md for other framework patterns
- Try ../integration_examples.py for additional patterns

---

**Status:** ✅ All documentation complete and ready to use

**Start:** Pick your path above and begin! 🚀