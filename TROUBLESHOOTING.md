# Kakveda Troubleshooting Guide

This guide covers common issues when running Kakveda and their solutions.

---

## Table of Contents

1. [Docker Compose Version Issues](#1-docker-compose-version-issues)
2. [CLI Issues](#2-cli-issues)
3. [Dashboard Issues](#3-dashboard-issues)
4. [Ollama Issues](#4-ollama-issues)
5. [Service Connection Issues](#5-service-connection-issues)
6. [Database Issues](#6-database-issues)

---

## 1. Docker Compose Version Issues

### Problem: `KeyError: 'ContainerConfig'` or similar errors

**Cause:** You're using an older version of Docker Compose (v1.x) that has compatibility issues.

**Solution 1: Upgrade to Docker Compose V2 (Recommended)**

```bash
# Check current version
docker compose version  # V2 style
docker-compose --version  # V1 style

# Install Docker Compose V2 (Linux)
sudo apt-get update
sudo apt-get install docker-compose-plugin

# Or manually download
DOCKER_CONFIG=${DOCKER_CONFIG:-$HOME/.docker}
mkdir -p $DOCKER_CONFIG/cli-plugins
curl -SL https://github.com/docker/compose/releases/latest/download/docker-compose-linux-x86_64 -o $DOCKER_CONFIG/cli-plugins/docker-compose
chmod +x $DOCKER_CONFIG/cli-plugins/docker-compose

# Verify
docker compose version
```

**Solution 2: Use the workaround for V1**

If you must use V1, use `down` then `up` instead of `--build` with recreate:

```bash
# Instead of:
docker-compose up --build -d

# Use:
docker-compose down --remove-orphans
docker-compose build
docker-compose up -d
```

### Problem: `docker compose` command not found

**Cause:** Docker Compose V2 not installed or not in PATH.

**Solution:**

```bash
# Use V1 style (if installed)
docker-compose up -d

# Or install V2
sudo apt-get install docker-compose-plugin
```

---

## 2. CLI Issues

### Problem: `ModuleNotFoundError: No module named 'kakveda_cli'`

**Cause:** Package not installed in editable mode.

**Solution:**

```bash
cd kakveda-v1.0
pip install -e .

# Now run
kakveda status
```

### Problem: `.env not found` error

**Cause:** You haven't initialized the environment.

**Solution:**

```bash
# Interactive setup
kakveda init

# Or init and start immediately
kakveda init --and-up
```

### Problem: CLI prompts hang or crash

**Cause:** Terminal encoding or interactive mode issues.

**Solution:**

Use Docker Compose directly:

```bash
cd kakveda-v1.0
docker-compose up -d
```

### Problem: `kakveda` command not found after pip install

**Cause:** pip scripts directory not in PATH.

**Solution:**

```bash
# Find where pip installs scripts
python -m site --user-base
# Add to PATH (add to ~/.bashrc for permanent)
export PATH="$HOME/.local/bin:$PATH"

# Or run directly
python -m kakveda_cli.cli up
```

---

## 3. Dashboard Issues

### Problem: Internal Server Error (500) after login

**Cause:** Database not initialized or template errors.

**Solution:**

```bash
# Reset the stack
kakveda reset --volumes

# Or manually
docker-compose down -v
rm -f data/*.db services/dashboard/dashboard.db
docker-compose up -d
```

### Problem: Dashboard not accessible at localhost:8110

**Cause:** Service not running or port conflict.

**Solution:**

```bash
# Check if running
docker-compose ps

# Check logs
docker-compose logs dashboard

# Check port conflict
lsof -i :8110
```

### Problem: Static files (CSS/JS) not loading

**Cause:** Volume mount issues.

**Solution:**

```bash
docker-compose down
docker-compose up -d --build dashboard
```

---

## 4. Ollama Issues

### Problem: Playground shows "stub" response instead of real LLM output

**Cause:** No model installed in Ollama container.

**Solution:**

```bash
# Pull a model inside the container
docker exec kakveda-v10_ollama_1 ollama pull llama3.2:1b

# Verify
curl http://localhost:11434/api/tags
```

### Problem: Ollama not responding

**Cause:** Container not running or port not exposed.

**Solution:**

```bash
# Check if running
docker-compose ps ollama

# Restart
docker-compose restart ollama

# Test connection
curl http://localhost:11434/api/tags
```

### Problem: Model download stuck or fails

**Cause:** Network issues or insufficient disk space.

**Solution:**

```bash
# Check disk space
df -h

# Try smaller model
docker exec kakveda-v10_ollama_1 ollama pull tinyllama

# Or use stub mode (no real LLM)
# Set in .env: MODEL_PROVIDER=stub
```

---

## 5. Service Connection Issues

### Problem: Services can't communicate with each other

**Cause:** Docker network not properly configured.

**Solution:**

```bash
# Recreate network
docker-compose down
docker network prune -f
docker-compose up -d
```

### Problem: Event bus connection refused

**Cause:** event-bus service not healthy.

**Solution:**

```bash
# Check event-bus logs
docker-compose logs event-bus

# Restart
docker-compose restart event-bus
```

---

## 6. Database Issues

### Problem: SQLite database locked

**Cause:** Multiple processes accessing the database.

**Solution:**

```bash
# Stop all services
docker-compose down

# Remove locks
rm -f data/*.db-journal

# Restart
docker-compose up -d
```

### Problem: Database schema mismatch

**Cause:** Updated code with old database.

**Solution:**

```bash
# Full reset
kakveda reset --volumes

# Or manually
rm -f data/*.db services/dashboard/dashboard.db
docker-compose up -d
```

---

## Quick Reference

### Start from scratch

```bash
cd kakveda-v1.0

# Clean start
docker-compose down -v
rm -f data/*.db
docker-compose up -d

# Pull Ollama model
docker exec kakveda-v10_ollama_1 ollama pull llama3.2:1b

# Open dashboard
xdg-open http://localhost:8110
```

### Check all services

```bash
docker-compose ps
docker-compose logs --tail=50
```

### Service URLs

| Service | URL |
|---------|-----|
| Dashboard | http://localhost:8110 |
| Event Bus | http://localhost:8100 |
| GFKB | http://localhost:8101 |
| Ingestion | http://localhost:8102 |
| Failure Classifier | http://localhost:8103 |
| Pattern Detector | http://localhost:8104 |
| Warning Policy | http://localhost:8105 |
| Health Scoring | http://localhost:8106 |
| Ollama | http://localhost:11434 |

---

## Getting Help

- **GitHub Issues**: https://github.com/prateekdevisingh/kakveda/issues
- **Documentation**: See `/docs` folder
- **Author**: Prateek Chaudhary

---

*Last updated: February 2026*
