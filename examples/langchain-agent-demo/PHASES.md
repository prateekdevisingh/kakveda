# Phased Integration Flow

This demo is organized into three distinct phases, each validating a specific aspect of Kakveda governance integration.

## Files

| File | Purpose |
|------|---------|
| `agent_app_phase1.py` | Phase 1: Standalone agent (no Kakveda) |
| `agent_app_phase2.py` | Phase 2: Agent with governance layer |
| `agent_app.py` | Main entry point (currently Phase 2) |
| `mock_social_api.py` | Mock social media API (no real calls) |
| `requirements.txt` | Dependencies |
| `README.md` | Quick start and phase overview |

---

## Phase 1 Checkpoint: Standalone Validation

**Objective:** Prove the agent works without any external dependencies.

**Script:** `agent_app_phase1.py`

**Command:**

```bash
. .venv/bin/activate
python agent_app_phase1.py --platform linkedin --topic "AI growth" --no-governance
```

**Key behaviors:**
- LLM generates content deterministically
- Tool executes mock_social_api directly
- No HTTP calls to Kakveda
- Logs are clear and minimal

**Pass criteria:**
✅ Content generated  
✅ Mock post executed  
✅ No errors  

---

## Phase 2 Checkpoint: Governance Integration

**Objective:** Verify Kakveda governance layer works as a preflight guard.

**Script:** `agent_app_phase2.py` (or main `agent_app.py`)

**Command (standalone mode):**

```bash
python agent_app.py --platform linkedin --topic "AI growth" --no-governance
```

**Command (with governance):**

```bash
python agent_app.py --platform linkedin --topic "AI growth"
```

(Assumes Kakveda /warn is available at `http://localhost:8000/warn`)

**Key behaviors:**
- Agent generates content via LLM
- If `--no-governance`: tool executes directly (same as Phase 1)
- If governance enabled: HTTP POST to Kakveda /warn before execution
- Decision trees: silent → execute, warn → log + execute, block → reject
- All governance decisions are logged centrally

**Pass criteria:**
✅ Standalone mode works (Phase 2 backward compatible with Phase 1)  
✅ Kakveda integration makes HTTP calls  
✅ Governance decision is logged visibly  
✅ Execution follows policy decision  

---

## Phase 3 Checkpoint: Failure Observation

**Objective:** Demonstrate Kakveda failure memory and escalation over repeated runs.

**Script:** Same `agent_app.py` (Phase 2) with Kakveda running

**Commands (run in sequence):**

```bash
python agent_app.py --platform linkedin --topic risky
python agent_app.py --platform linkedin --topic risky
python agent_app.py --platform linkedin --topic risky
```

**Expected behavior (managed by Kakveda, not agent):**
- Run 1: Kakveda returns `{"action": "warn", "confidence": 0.62, "pattern_id": "stat-risk"}`
- Run 2: Kakveda returns `{"action": "warn", "confidence": 0.75, "pattern_id": "stat-risk"}`
- Run 3: Kakveda returns `{"action": "block", "confidence": 0.91, "pattern_id": "repeated-risky"}`

**Pass criteria:**
✅ Kakveda confidence increases over runs  
✅ Action escalates (warn → block)  
✅ Pattern ID captures repeated failures  
✅ Agent does NOT simulate this; Kakveda runtime handles it  

---

## Governance Decision Matrix

| Scenario | Phase 1 | Phase 2 (no-governance) | Phase 2 (with Kakveda) |
|----------|---------|----------------------|----------------------|
| Safe topic | Execute | Execute | Execute (silent) |
| Exaggerated topic | Execute | Execute | Execute (warn) or Blocked (repeated) |
| Risky topic (first) | Execute | Execute | Execute (warn) or Block (depending on policy) |
| Risky topic (repeat) | Execute | Execute | Block (Kakveda escalates) |

---

## Demo Script for Live Walkthrough

1. Start fresh environment
2. Show Phase 1 works: `python agent_app_phase1.py --platform linkedin --topic "AI growth" --no-governance`
3. Show Phase 2 with no-governance (backward compat): `python agent_app.py --platform linkedin --topic "AI growth" --no-governance`
4. Start Kakveda (optional, using mock if unavailable)
5. Show Phase 2 with governance: `python agent_app.py --platform linkedin --topic "AI growth"`
6. Show risky escalation: Run the same risky topic 3 times and observe action/confidence change

---

## Testing Checklist

### Phase 1 Standalone
- [ ] Install dependencies
- [ ] Run Phase 1 with safe topic → executes
- [ ] Run Phase 1 with risky topic → executes (no filtering)
- [ ] Logs are clear and minimal

### Phase 2 Backward Compatibility
- [ ] Run Phase 2 with `--no-governance` → same as Phase 1
- [ ] Governance flag toggled correctly

### Phase 2 Governance (if Kakveda available)
- [ ] Run with governance enabled
- [ ] HTTP POST to /warn is logged
- [ ] Kakveda response is logged
- [ ] Decision (silent/warn/block) is applied

### Phase 3 Failure Escalation
- [ ] Run same risky topic 3 times
- [ ] Confidence increases on each run
- [ ] Action changes from warn → block
- [ ] Pattern ID is consistent

---

## Architecture Summary

```
Agent → LLM generates content
    ↓
Tool (post_to_social)
    ├─ Phase 1: Direct execution
    ├─ Phase 2 (no-governance): Direct execution
    └─ Phase 2 (governance): Kakveda /warn → policy decision → execution
```

All phases share the same agent reasoning. The only difference is the execution layer.
