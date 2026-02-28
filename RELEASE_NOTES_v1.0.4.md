# Release Notes v1.0.4

Date: 2026-02-28

## Highlights
- Added full Netra host observability coverage and stronger dashboard surfacing for infra + observability workflows.
- Added standalone host-install documentation for `kakveda-netra` with clear integration steps for separate machines.
- Added background runtime support for Netra so users can run without keeping a separate terminal open.

## Added
- Dedicated host install guide:
  - `docs/netra-host-install.md`
- Dashboard observability enhancements:
  - diagnostics summary block
  - SLO + error-budget summary
  - inferred service map table
  - synthetic checks table
  - incident timeline table
  - basic forecast and correlation summaries
- Metrics drill-down pages for observability and infra trends.
- Netra background daemon controls:
  - `--start`
  - `--stop`
  - `--bg-status`

## Changed
- Improved chart rendering resilience (fallback rendering when external chart script is unavailable).
- Improved card navigation to detail pages with full-card click behavior.
- Improved threshold handling and per-agent persistence behavior in infra monitoring.
- Updated documentation with:
  - “today vs tomorrow” capability narrative
  - expanded market comparison (Datadog, AppDynamics, Logz.io, and other suites)
  - explicit statement of current industry problem and Kakveda’s resolution.

## Netra Notes
- `DASHBOARD_API_KEY` remains mandatory for registration, heartbeat, and dashboard config synchronization.
- Background process state files:
  - PID: `~/.local/state/kakveda-netra/netra.pid`
  - LOG: `~/.local/state/kakveda-netra/netra.log`

## Version
- Project version set to `1.0.4`.
- CLI version set to `1.0.4`.
