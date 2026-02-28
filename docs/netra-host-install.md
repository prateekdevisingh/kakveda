# Netra Host Install Guide

This guide explains how to install and run `kakveda-netra` on any host machine and integrate it with `kakveda-v1.0`.

## Why Netra

`kakveda-netra` is the host-level agent that pushes:
- infra metrics (`infra.metrics`)
- observability metrics (`observability.metrics`)
- heartbeat + registration data

to your Kakveda stack.

## Prerequisites

- Python `3.11+`
- Network reachability from host to Kakveda Dashboard/Event Bus
- Dashboard API key from Kakveda UI (`Admin -> API Keys`)

## Is Dashboard API Key Mandatory?

Yes, mandatory.

It is required for:
- agent registration
- heartbeat updates
- dashboard-driven runtime config sync

Without `DASHBOARD_API_KEY`, Netra setup/run is not valid for integration.

## Install on Any Host

```bash
python3.11 -m venv ~/.venvs/netra
source ~/.venvs/netra/bin/activate
pip install -U pip
pip install "git+https://github.com/prateekdevisingh/kakveda.git#subdirectory=kakveda-aankh"
```

## Configure Once

```bash
kakveda-netra --setup
```

Config file:

```text
~/.config/kakveda-netra/config.env
```

URL rule:
- Same machine as Kakveda: `http://localhost:8110` and `http://localhost:8100/publish`
- Different machine: use reachable IP/DNS of Kakveda services (not localhost of host agent machine)

## Run Options

### Foreground

```bash
kakveda-netra --run
```

### Background (no separate terminal needed)

```bash
kakveda-netra --start
kakveda-netra --bg-status
kakveda-netra --stop
```

State files:

```text
PID: ~/.local/state/kakveda-netra/netra.pid
LOG: ~/.local/state/kakveda-netra/netra.log
```

## Auto-start on Boot (systemd)

System scope:

```bash
kakveda-netra --install-service --scope system
kakveda-netra --status --scope system
```

User scope:

```bash
kakveda-netra --install-service --scope user
loginctl enable-linger $USER
kakveda-netra --status --scope user
```

Uninstall:

```bash
kakveda-netra --uninstall-service --scope system
# or
kakveda-netra --uninstall-service --scope user
```

## Integration Verification in Kakveda

1. Open Dashboard `Agents` page and verify `netra-*` host appears.
2. Open `/infra` and verify host metrics are visible.
3. Open `/observability` and verify golden signals are visible.
4. If background mode is used, check:

```bash
kakveda-netra --bg-status
tail -f ~/.local/state/kakveda-netra/netra.log
```
