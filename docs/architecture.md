# Architecture

Kakveda is a pipeline-centric, event-driven system that adds **failure memory** around LLM runtimes.

## High-level services

- **dashboard**: UI + scenario runner + analytics + RBAC
- **warning-policy**: pre-flight matching and policy decisioning
- **ingestion**: receives traces/spans and emits events
- **event-bus**: demo HTTP pub/sub
- **failure-classifier**: detects and classifies failures from traces
- **gfkb**: persistent failure knowledge base (failures + patterns)
- **pattern-detector**: detects recurring failures and builds patterns
- **health-scoring**: computes health metrics over time

## Pipeline view (Fig. 1)

See: `docs/figures/fig1_pipeline_architecture.svg`

![Fig. 1 — Pipeline-centric architecture for failure-intelligence](figures/fig1_pipeline_architecture.svg)

## Event flow (typical run)

1. A user triggers a run from the **dashboard** (or a client calls the API).
2. **warning-policy** fingerprints the request and checks the GFKB for previous failures.
3. The request proceeds to the **model runtime** (Ollama or deterministic stub).
4. **ingestion** records spans (inputs, outputs, tool calls, errors).
5. **event-bus** publishes an ingestion event.
6. **failure-classifier** extracts failures and writes them to **GFKB**.
7. **pattern-detector** updates patterns.
8. **health-scoring** updates the health timeline.
9. **dashboard** visualizes runs, warnings, patterns, and health.

## Storage

The dashboard defaults to SQLite for local demos. You can switch to Postgres using `DASHBOARD_DB_URL`.

## Notes

- This repository is **single-node** by default (Docker Compose).
- The architecture diagrams are logical; enterprise deployments may split services or run them with HA.
