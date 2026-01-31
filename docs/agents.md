# Agents (Registry + Plugin Flow)

Kakveda supports a lightweight **agent registry** similar to how MLflow / LangSmith manage “things you integrate”, while still being self-hosted.

The key idea:

- Kakveda **does not host** your agent.
- You run your agent as an HTTP service (container / VM / k8s / serverless).
- Kakveda registers the agent and can health-check it.

## ✅ Admin-only
Agent registration is **admin-only**.

- UI: `http://localhost:8110/admin/agents`
- API: `GET /api/agents` (requires admin cookie session)

## Agent contract (minimum)
### `GET /health`
Your agent must expose a `GET /health` endpoint.

- 200 OK means healthy
- any other code is treated as unhealthy

Optional (recommended):
- `GET /capabilities` → returns JSON describing what the agent can do
- `POST /invoke` → standardized “event in / events out” contract (future)

## Register an agent (UI)
Go to:

- `http://localhost:8110/admin/agents`

Fill:

- **Name**: unique (e.g. `my-agent`)
- **Base URL**: e.g. `http://agent_echo:8120` (compose service name) or `https://agent.myorg.com`
- **Capabilities / events**: comma-separated lists (optional metadata)
- **Auth**: optional

### Auth model
To avoid storing secrets in the DB, the registry stores only a **secret reference** (an env var name).

Examples:

- `auth_type=bearer`, `auth_secret_ref=MY_AGENT_TOKEN` → Kakveda sends `Authorization: Bearer <env[MY_AGENT_TOKEN]>`
- `auth_type=api_key_header`, `auth_header_name=X-API-Key`, `auth_secret_ref=MY_AGENT_KEY` → Kakveda sends `X-API-Key: <env[MY_AGENT_KEY]>`

## Local demo agent (recommended)
This repo includes a built-in demo agent service: **agent-echo**.

Start the stack (or rebuild after pulling changes):

- `python -m kakveda_cli.cli up`

Then register it in the UI with base URL:

- `http://agent-echo:8120`

## Notes
- Today the registry includes **list/register/toggle/test**.
- Full runtime invocation/orchestration is intentionally future work.
