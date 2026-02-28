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

### Non-interactive config (with dashboard key)

You can skip prompts and pass values directly via CLI flags:

```bash
kakveda-netra \
  --setup \
  --dashboard-url http://localhost:8110 \
  --event-bus-url http://localhost:8100/publish \
  --dashboard-api-key "<YOUR_DASHBOARD_API_KEY>" \
  --agent-name "netra-host-01" \
  --agent-app-id "host-infra" \
  --infra-interval 5 \
  --observability-enabled true \
  --k8s-auto-map-enabled true
```

Then start:

```bash
kakveda-netra --start
```

### CLI options (most used)

Runtime/service controls:
- `--setup` interactive or flag-driven setup and save config
- `--run` foreground run
- `--start` background run
- `--stop` stop background process
- `--bg-status` show background process status
- `--install-service --scope system|user`
- `--status --scope system|user`
- `--uninstall-service --scope system|user`

Core config flags:
- `--dashboard-url`
- `--event-bus-url`
- `--dashboard-api-key` (mandatory)
- `--agent-name`, `--agent-app-id`, `--agent-version`
- `--infra-interval`, `--heartbeat-interval`
- `--observability-enabled`, `--observability-topic`, `--observability-window`
- `--k8s-auto-map-enabled`, `--k8s-auto-map-max-apps`, `--k8s-auto-map-prefix`
- `--metrics-endpoint-enabled`, `--metrics-endpoint-host`, `--metrics-endpoint-port`

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

## Kubernetes kubeconfig auto-detection

Netra auto-detects kubeconfig in this order:
1. Existing `KUBECONFIG` (if valid path)
2. `~/.kube/config`
3. `/home/$SUDO_USER/.kube/config` (when started with sudo)

So on many hosts, Kubernetes data starts working without extra setup.

Examples:

Use default auto-detect:

```bash
kakveda-netra --start
```

Use explicit kubeconfig:

```bash
export KUBECONFIG=$HOME/.kube/config
kakveda-netra --start
```

If kubeconfig is not available, Netra continues safely and Kubernetes collectors stay disabled (no crash).

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

## Why Netra is a strong integration choice

Compared to stitching multiple agents/tools, `kakveda-netra` is optimized for direct Kakveda integration:

- One native host agent for infra + observability + container + cluster signals.
- Same payload family consumed by Kakveda dashboards (`/infra`, `/observability`).
- Dashboard-controlled config sync (no repeated per-host reconfiguration loop).
- Easier governance posture with OSS/self-host deployment model.
- Native linkage with Kakveda failure intelligence pipeline (warnings + GFKB context).
