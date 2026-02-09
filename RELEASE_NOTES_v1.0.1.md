# Kakveda v1.0.1 Release Notes
**Release Date:** 9 February 2026

## Overview
v1.0.1 is a patch release that fixes a startup crash on new laptops caused by a SQLite schema mismatch in the dashboard.

## Fixes
- **Dashboard SQLite migration:** Ensures `scenarios` and `scenario_runs` tables exist, and adds missing columns (`scenario_id`, `scenario_code`, `expected_behavior`, `note`).
- **Startup stability:** Prevents `sqlite3.OperationalError` when `/scenarios` queries scenario fields on older databases.

## What Changed
- **services/dashboard/db.py**
  - Added best-effort migrations for `scenarios` and `scenario_runs` tables
  - Backfills missing columns for scenario metadata

## Upgrade Notes
If you already have a running dashboard:
```bash
cd kakveda-v1.0
docker-compose restart dashboard
```
This triggers the migration on startup.

## Breaking Changes
None.

## Known Issues
None reported for this patch.
