# Phased Governance Demo — Status & Next Steps

**Created:** 2026-02-17  
**Location:** kakveda-v1.0/examples/langchain-agent-demo/

## ✅ What's Complete

### Phase 1: Standalone Agent
- `agent_app_phase1.py` – Minimal agent with deterministic LLM and mock social API
- No external dependencies; runs offline
- **Validated:** ✅ Works independently

### Phase 2: Governance Layer
- `agent_app_phase2.py` – Same agent + Kakveda integration layer
- `agent_app.py` – Main entry point (currently Phase 2)
- Supports `--no-governance` for backward compat with Phase 1 behavior
- Supports governance-enabled mode (calls Kakveda /warn)
- **Validated:** ✅ Standalone mode works; governance structure in place

### Supporting Files
- `mock_social_api.py` – Mock social platform API (no real network calls)
- `requirements.txt` – Minimal dependencies (requests only for Phase 2)
- `README.md` – Quick start, phase overview, expected outputs
- `PHASES.md` – Detailed phase flow, testing checklist, architecture

## 📋 How to Start Phase 1 & Validate

```bash
cd kakveda-v1.0/examples/langchain-agent-demo

# Setup
python3 -m venv .venv
. .venv/bin/activate
pip install -q -r requirements.txt

# Phase 1 validation (standalone)
python agent_app_phase1.py --platform linkedin --topic "AI growth" --no-governance

# Phase 2 validation (governance-disabled, backward compat)
python agent_app.py --platform linkedin --topic "AI growth" --no-governance

# Phase 2 with risky content
python agent_app.py --platform twitter --topic exaggerated --no-governance
```

**Expected output for all three:**
```
[PLATFORM] ...
[GOVERNANCE] disabled
[AGENT GENERATED CONTENT] ...
[TOOL EXECUTION] no-governance
[MOCK POST SUCCESS] Platform: ...
[DONE] elapsed=...
```

## 🔵 Phase 3: Ready When Kakveda Runs

To activate Phase 3 (failure memory + escalation demo):

1. Start Kakveda stack in separate terminal:
   ```bash
   cd kakveda-v1.0
   docker-compose up -d
   ```

2. Run Phase 2 agent with governance enabled:
   ```bash
   python agent_app.py --platform linkedin --topic risky
   ```

   (Note: No `--no-governance` flag = Kakveda is called)

3. Run same command 2-3 more times and observe:
   - Kakveda response confidence increasing
   - Action escalating (warn → block)
   - Pattern ID captured and matched

## 🎯 Key Design Points

✅ **Agent logic is separate from governance logic**
- LLM generates content (deterministic for demos)
- Governance decides execution (via Kakveda or direct)
- Tool never calls social API directly without policy decision

✅ **Governance can be toggled without code change**
- `--no-governance` → Phase 1 behavior
- Default (no flag) → Phase 2 governance-enabled

✅ **All governance decisions are logged visibly**
- KAKVEDA REQUEST → KAKVEDA RESPONSE → FINAL DECISION
- Operator sees exactly what Kakveda decided

✅ **No real external APIs**
- Mock social media is deterministic
- Kakveda calls are visible in logs
- Reproduc ible and testable offline

## 📁 File Structure (No Changes)

```
kakveda-v1.0/examples/langchain-agent-demo/
├── agent_app_phase1.py       (Phase 1: standalone)
├── agent_app_phase2.py       (Phase 2: governance-enabled)
├── agent_app.py              (Main entry = Phase 2)
├── mock_social_api.py        (Mock API)
├── requirements.txt          (Dependencies)
├── README.md                 (Quick start)
├── PHASES.md                 (Detailed flow)
└── SUMMARY.md                (This file)
```

## 🚀 Next Steps (Optional Enhancements)

1. **Mock Kakveda in tests:** Add a test mode where `/warn` is mocked locally
2. **Phase 3 demo script:** Automate the 3-run escalation sequence
3. **Integration tests:** Add pytest for all three phases
4. **Real LangChain agent:** Replace SimpleLLM with actual LangChain agent (0-shot-react)

## ❌ What We Deliberately Did NOT Do

- ❌ No real OAuth or social media APIs
- ❌ No database (all in-memory)
- ❌ No complex LLM (deterministic stub for reproducibility)
- ❌ No external dependencies except requests
- ❌ No nested folders or unnecessary complexity

This is a **governance-focused demo**, not a full social media system.

## 👤 Demo Narrative (for presentations)

> **"Here's how we integrate an AI agent with Kakveda governance."**
>
> 1. **Phase 1:** Agent works standalone — generates content, executes.
> 2. **Phase 2:** Add governance layer — Kakveda evaluates before execution.
> 3. **Phase 3:** Kakveda learns — repeated risky patterns are escalated to blocks.
>
> The key insight: **Kakveda sits around the agent, not inside it.**
> The agent generates ideas. Kakveda controls if those ideas execute.

---

**Status:** ✅ Ready for Phase 1 & 2 demos. Phase 3 enabled when Kakveda stack runs.
