# Kakveda v0.2.2 — Release Notes (5 Feb 2026)

This release hardens **first-time setup** and **new-machine onboarding**, especially when a user reuses an existing `data/dashboard.db`.

## Highlights

- **Demo login bootstrap repair**
  - On startup, the dashboard now *repairs* demo users when the DB already exists (reactivates `is_active`, re-verifies `is_verified`, and ensures role mappings exist).
  - Adds an opt-in recovery switch to re-apply demo passwords when needed: `DASHBOARD_BOOTSTRAP_FORCE_PASSWORDS=1`.

- **Browser-friendly admin login**
  - Keeps the promised OSS demo admin `admin@local / admin123`.
  - Adds a browser-valid alias `admin@kakveda.local / admin123` for cases where browsers block `admin@local` (email format validation).
  - Login form now uses `novalidate` to avoid client-side blocking.

- **Agents are optional (no-break defaults)**
  - Documentation clarifies that Kakveda runs fine without any external agents.
  - Recommends using Docker Compose **profiles** for optional agents to prevent compose failures when an agent folder isn’t present.

## Docs

- Adds troubleshooting guidance for “default admin login not working on a new setup” and recovery options.
- Improves README guidance for adding agents without breaking default installs.

## Key Files Changed

- `services/dashboard/app.py`
- `services/dashboard/templates/login.html`
- `README.md`
- `TROUBLESHOOTING.md`
- `docker-compose.yml`

## Upgrade Notes

- If you reused an old `data/dashboard.db` and can’t login with demo credentials, set:

  ```bash
  export DASHBOARD_BOOTSTRAP_FORCE_PASSWORDS=1
  docker-compose up -d --build dashboard
  ```

  Then login and unset the variable.

- Recommended admin login for browsers: `admin@kakveda.local / admin123`.
