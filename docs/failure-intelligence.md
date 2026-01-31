# Failure Intelligence

Failure intelligence is the capability to detect, remember, and act on failures as **knowledge**, not just telemetry.

## What Kakveda adds (layer model)

Most stacks already have:
- LLM runtime (Ollama/OpenAI/etc.)
- tracing/logging (OpenTelemetry, logs)
- evaluation pipelines

Kakveda adds:
- a **failure knowledge base**
- **pre-flight matching** (“this failed before”) before executing
- pattern detection (recurrence, trends)
- system health scoring over time

## Pre-flight memory check

Before a run executes, Kakveda can:
1. normalize inputs
2. compute a fingerprint
3. match against known failures/patterns
4. apply policy → allow/warn/block/route

![Fig. 3 — Pre-flight matching and policy decision flow](figures/fig3_preflight_policy_flow.svg)

## Why it matters

- Reduces repeated failures in production
- Gives teams a shared memory of failure modes
- Enables preventive controls (warn/block) and safer routing
- Improves long-term system reliability (health-based management)

## Practical examples

- Prompt or tool configuration that repeatedly causes parsing errors
- Tool outages that recur (timeouts, 5xx) — detect pattern and route
- Model regressions between versions — detect rising severity in patterns

## Extensibility

Matching can be:
- deterministic (hash/fingerprint)
- rules/heuristics
- embedding similarity (optional extension)

Policy can be:
- warn-only
- warn + confirmation gate
- block high-severity failures
- route to safer model/tools
