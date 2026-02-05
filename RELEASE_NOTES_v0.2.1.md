# Release v0.2.1 — Dashboard UX, Dataset Apps, and Warning/Health Fixes

Release date: 2026-02-05

## Highlights

- Datasets: app selector now reflects real `app_id`s (e.g. `kids-app`) instead of hardcoded demo apps.
- Playground: clearer safety status (SAFE/WARNING/BLOCKED), shows "You asked" + "Answer", and links to filtered Warnings.
- Warnings: analytics and filtering hardened (including `block` actions) for external agents.
- Health: health scoring timeline wiring + chart rendering improvements.

## What changed (selected)

- Dashboard
  - Dynamic app discovery for selectors (runs/warnings/datasets).
  - Subscriptions/handlers for external events (e.g., persisted runs and child safety alerts).
  - Warnings page analytics improvements and `app_id` filtering.
  - Playground UI improvements (safety signal + prompt/answer display).
- Health scoring
  - Health endpoints and JSONL persistence/volume wiring.

## Operational notes

- If you are running with Docker Compose, rebuild only the dashboard when updating UI/templates:
  - `docker-compose rm -sf dashboard && docker-compose up -d --build --no-deps dashboard`

## Known limitations

- Drift detection is not yet a dedicated, first-class capability in this repo (see `docs/COMPARISON.md`).
