# Release Notes v1.0.2

Date: 2026-02-17

## Highlights
- Introduced `kakveda_sdk` with `KakvedaAgent` as the unified integration surface.
- Updated langchain agent demo to use the SDK (governance, events, dashboard registration).
- Added Docker and runtime scaffolding for the demo.

## Added
- New SDK package: `kakveda_sdk` (`agent.py`, `guard.py`, `registration.py`).
- Demo utilities and docs in `examples/langchain-agent-demo/`.
- Demo Dockerfile and `.dockerignore`.

## Changed
- Demo apps now call `KakvedaAgent.execute()` and use model metadata.
- Integration examples updated to show SDK usage.
- Example docs reframed to emphasize SDK-first usage and mark legacy guard steps as reference-only.
 - Legacy manual integration guides now point to `kakveda_sdk.guard.KakvedaGuard` and avoid removed helpers.

## Removed
- Legacy demo helpers `agent_registration.py` and `kakveda_integration.py` (replaced by SDK).
- Redundant event publisher helpers.

## Notes
- The legacy KakvedaGuard docs remain for reference; prefer `kakveda_sdk` for new work.
