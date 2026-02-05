# Kakveda v0.2.3 Release Notes
**Release Date:** 5 February 2026

## Overview
v0.2.3 focuses on **kids-agent integration stability** and **new-laptop onboarding reliability**. All critical setup issues have been resolved with permanent fixes.

## Key Features

### ✅ New Laptop Setup (No Problems!)
- Dashboard now automatically repairs demo users on fresh setups
- Admin login works reliably with `admin@kakveda.local` alias (avoids browser email validation blocks)
- Standalone kids-agent integrates seamlessly with Kakveda stack without port conflicts
- Comprehensive troubleshooting guide added to TROUBLESHOOTING.md

### ✅ Kids-Agent Integration
- **Network Fix**: Standalone kids-agent now properly attaches to Kakveda docker network
- **Event Publishing**: Traces now successfully flow from kids-agent → event-bus → dashboard
- **Port Conflict Resolution**: Ollama port 11434 no longer causes binding failures
- **Service Registry**: Agent health checks work reliably from dashboard

### ✅ Documentation
- Updated README with kids-agent setup instructions
- Added "new laptop" section with step-by-step integration guide
- Clarified agent networking (docker networks vs host binding)
- Enhanced TROUBLESHOOTING.md with login and agent setup recovery

## What Changed

### kakveda-v1.0
- **services/dashboard/app.py**
  - Bootstrap "repair" logic ensures demo users exist and are active
  - Optional `DASHBOARD_BOOTSTRAP_FORCE_PASSWORDS=1` env var for password reset
  - Added `admin@kakveda.local` alias alongside `admin@local`
  
- **services/dashboard/templates/login.html**
  - Added `novalidate` to form to bypass browser email validation

- **docker-compose.yml**
  - Kids-agent service now gated by `profiles: ["kids"]` (optional, non-blocking)

- **README.md & TROUBLESHOOTING.md**
  - New "New Laptop Setup" section with verified step-by-step instructions
  - Recovery guide for admin login failures on reused DBs

### kakveda-kids-agent (v0.1.1)
- **docker-compose.yml** 
  - Attaches to Kakveda's docker network (`kakveda-v10_default` external reference)
  - Ollama service renamed to `kids-ollama` (avoids name collision)
  - Removed host port binding for Ollama; uses internal network only
  - Environment variables use correct service hostnames (event-bus, dashboard)
  - Added `extra_hosts` mapping for `host.docker.internal` (Linux compatibility)

- **README.md**
  - Integration section updated with correct API key generation steps
  - Event-bus publish endpoint corrected (`POST /publish` with `{topic, event}`)
  - Note added about Ollama port conflicts and setup alongside Kakveda

## Verified Scenarios

✅ **Fresh Laptop Setup**
- Kakveda + kids-agent both start without port conflicts
- Admin login works with demo accounts
- Kids-agent events appear in Kakveda dashboard within seconds

✅ **Standalone Kids-Agent**
- Runs independently, publishes to Kakveda stack on same host
- Health checks pass from Agents page
- Auto-registration with API key works reliably

✅ **Upgrade from v0.2.2**
- No database migration required
- Existing agents and traces preserved
- Demo users automatically repaired on startup

## Breaking Changes
None. Fully backward compatible.

## Known Limitations
- Kids-agent Ollama model availability depends on host Ollama pull (or remote endpoint)
- Dashboard event-bus subscriptions reset on container restart (in-memory, non-persistent)

## Installation & Testing

### Quick Start (New Laptop)
```bash
# 1. Start Kakveda
cd kakveda-v1.0
docker-compose up -d --build

# 2. Create API key in Dashboard → Projects → API Keys

# 3. Start kids-agent
cd ../kakveda-kids-agent
export DASHBOARD_API_KEY='<key>' AUTO_REGISTER=true
docker-compose up -d --build

# 4. Verify
curl http://localhost:8120/api/ask -H 'Content-Type: application/json' \
  -d '{"question":"Hello!","child_name":"Test","child_age":5}'
# Should see a response + trace in http://localhost:8110 Runs tab
```

### Login (if blocked by browser)
- Try: `admin@kakveda.local` / `admin`
- Or force password reset: `DASHBOARD_BOOTSTRAP_FORCE_PASSWORDS=1` on startup

## Commit History
- `f85bd0f`: Fix standalone kids-agent Docker network integration
- `039f763`: Add v0.2.2 release notes (kakveda-v1.0)

## Contributors
- Prateek Chaudhary (Kakveda + Kids-Agent)

## Feedback & Issues
Report issues or feedback to project maintainers. Ensure to include:
- Docker version and OS
- Steps to reproduce
- Docker logs: `docker logs <container>`
- Database state (if login issue): presence of `/data/dashboard.db`

---

**Status**: ✅ Production Ready  
**Tested On**: Linux (Ubuntu), Docker Compose v1.29.2  
**Next**: v0.3.0 (remote agent registration, multi-project support)
