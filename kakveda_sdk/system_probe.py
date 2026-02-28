#!/usr/bin/env python3
"""High-resolution node-level infrastructure metrics probe."""

from __future__ import annotations

import asyncio
import json
import logging
import os
import platform
import socket
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from threading import Thread
from typing import Any, Callable, Optional
from urllib.parse import quote

import psutil

logger = logging.getLogger(__name__)


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _safe_float(value: Any, default: float = 0.0) -> float:
    try:
        return float(value)
    except Exception:
        return float(default)


def _safe_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except Exception:
        return int(default)


def _sanitize_name(value: str) -> str:
    return value.strip().replace('"', '\\"')


def _disk_key_candidates(device: str) -> list[str]:
    base = os.path.basename(device or "")
    if not base:
        return []
    out = [base]
    if base.startswith("nvme") and "p" in base:
        out.append(base.split("p")[0])
    elif base.startswith("mmcblk") and "p" in base:
        out.append(base.split("p")[0])
    else:
        out.append(base.rstrip("0123456789"))
    return [k for k in out if k]


def _top_with_warning(
    items: list[dict[str, Any]],
    max_items: int,
    sort_key: Callable[[dict[str, Any]], float],
    label: str,
) -> list[dict[str, Any]]:
    if len(items) <= max_items:
        return items
    logger.warning("%s cardinality exceeded (%s), sampling top %s by usage", label, len(items), max_items)
    return sorted(items, key=sort_key, reverse=True)[:max_items]


class _PrometheusHandler(BaseHTTPRequestHandler):
    probe: "SystemProbe"

    def do_GET(self) -> None:  # noqa: N802
        if self.path != "/metrics":
            self.send_response(404)
            self.end_headers()
            return
        body = self.probe.to_prometheus().encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt: str, *args: Any) -> None:
        logger.debug("metrics endpoint: " + fmt, *args)


@dataclass(slots=True)
class ProbeLimits:
    max_interfaces: int = 50
    max_containers: int = 100
    max_partitions: int = 20


class SystemProbe:
    """Collects node-level system metrics in grouped structure."""

    def __init__(self, *, limits: Optional[ProbeLimits] = None) -> None:
        self.limits = limits or ProbeLimits()
        self._last_payload: dict[str, Any] = {}
        self._docker_socket = self._detect_docker_socket()
        try:
            psutil.cpu_percent(interval=None)
            psutil.cpu_percent(interval=None, percpu=True)
        except Exception:
            pass

    @property
    def last_payload(self) -> dict[str, Any]:
        return self._last_payload

    async def collect(self, agent_id: str) -> dict[str, Any]:
        started = time.perf_counter()
        tasks = [
            self._safe_collect("cpu", self._collect_cpu),
            self._safe_collect("memory", self._collect_memory),
            self._safe_collect("disk", self._collect_disk),
            self._safe_collect("network", self._collect_network),
            self._safe_collect("process", self._collect_process),
            self._safe_collect("fd", self._collect_fd),
            self._safe_collect("system", self._collect_system),
            self._safe_collect("docker", self._collect_docker),
            self._safe_collect("temperature", self._collect_temperature),
            self._safe_collect("load", self._collect_load),
        ]
        (
            cpu,
            memory,
            disk,
            network,
            process,
            fd,
            system,
            docker,
            temperature,
            load,
        ) = await asyncio.gather(*tasks)
        duration_ms = int((time.perf_counter() - started) * 1000)
        if duration_ms > 500:
            logger.warning("system metrics collection is slow (%sms > 500ms)", duration_ms)
        infra = {
            "cpu": cpu,
            "memory": memory,
            "disk": disk,
            "network": network,
            "process": process,
            "docker": docker,
            "system": {**system, **fd, **temperature, **load},
            "collection_duration_ms": duration_ms,
        }
        payload = {"agent_id": str(agent_id), "timestamp": utc_now_iso(), "infra": infra}
        self._last_payload = payload
        return payload

    async def _safe_collect(
        self,
        name: str,
        fn: Callable[[], Any],
        default: Any = None,
    ) -> Any:
        try:
            return await asyncio.to_thread(fn)
        except Exception as exc:
            logger.exception("metrics collector failed for %s: %s", name, exc)
            if default is not None:
                return default
            if name in {"disk", "network", "docker"}:
                return []
            return {}

    def _collect_cpu(self) -> dict[str, Any]:
        freq = psutil.cpu_freq()
        times = psutil.cpu_times()
        try:
            l1, l5, l15 = os.getloadavg()
        except Exception:
            l1 = l5 = l15 = 0.0
        return {
            "cpu_percent_total": _safe_float(psutil.cpu_percent(interval=None)),
            "cpu_percent_per_core": [_safe_float(v) for v in psutil.cpu_percent(interval=None, percpu=True)],
            "cpu_count_logical": _safe_int(psutil.cpu_count(logical=True)),
            "cpu_count_physical": _safe_int(psutil.cpu_count(logical=False)),
            "cpu_freq_current": _safe_float(getattr(freq, "current", 0.0)),
            "cpu_freq_min": _safe_float(getattr(freq, "min", 0.0)),
            "cpu_freq_max": _safe_float(getattr(freq, "max", 0.0)),
            "cpu_load_1m": _safe_float(l1),
            "cpu_load_5m": _safe_float(l5),
            "cpu_load_15m": _safe_float(l15),
            "cpu_user_time": _safe_float(getattr(times, "user", 0.0)),
            "cpu_system_time": _safe_float(getattr(times, "system", 0.0)),
            "cpu_idle_time": _safe_float(getattr(times, "idle", 0.0)),
            "cpu_iowait_time": _safe_float(getattr(times, "iowait", 0.0)),
        }

    def _collect_memory(self) -> dict[str, Any]:
        vm = psutil.virtual_memory()
        sm = psutil.swap_memory()
        return {
            "memory_total_bytes": _safe_int(vm.total),
            "memory_available_bytes": _safe_int(vm.available),
            "memory_used_bytes": _safe_int(vm.used),
            "memory_free_bytes": _safe_int(vm.free),
            "memory_cached_bytes": _safe_int(getattr(vm, "cached", 0)),
            "memory_buffers_bytes": _safe_int(getattr(vm, "buffers", 0)),
            "memory_percent": _safe_float(vm.percent),
            "swap_total_bytes": _safe_int(sm.total),
            "swap_used_bytes": _safe_int(sm.used),
            "swap_free_bytes": _safe_int(sm.free),
            "swap_percent": _safe_float(sm.percent),
        }

    def _collect_disk(self) -> list[dict[str, Any]]:
        io_by_disk = psutil.disk_io_counters(perdisk=True) or {}
        partitions = psutil.disk_partitions(all=False)
        rows: list[dict[str, Any]] = []
        for part in partitions:
            mount = part.mountpoint
            if not mount:
                continue
            try:
                usage = psutil.disk_usage(mount)
            except Exception:
                continue
            counters = None
            for key in _disk_key_candidates(part.device):
                counters = io_by_disk.get(key)
                if counters:
                    break
            rows.append(
                {
                    "mountpoint": mount,
                    "disk_total_bytes": _safe_int(usage.total),
                    "disk_used_bytes": _safe_int(usage.used),
                    "disk_free_bytes": _safe_int(usage.free),
                    "disk_percent": _safe_float(usage.percent),
                    "disk_read_bytes": _safe_int(getattr(counters, "read_bytes", 0)),
                    "disk_write_bytes": _safe_int(getattr(counters, "write_bytes", 0)),
                    "disk_read_count": _safe_int(getattr(counters, "read_count", 0)),
                    "disk_write_count": _safe_int(getattr(counters, "write_count", 0)),
                    "disk_read_time": _safe_int(getattr(counters, "read_time", 0)),
                    "disk_write_time": _safe_int(getattr(counters, "write_time", 0)),
                }
            )
        return _top_with_warning(
            rows,
            self.limits.max_partitions,
            sort_key=lambda x: float(x.get("disk_used_bytes") or 0),
            label="disk partitions",
        )

    def _collect_network(self) -> list[dict[str, Any]]:
        net_io = psutil.net_io_counters(pernic=True) or {}
        iface_rows: list[dict[str, Any]] = []
        for iface, c in net_io.items():
            iface_rows.append(
                {
                    "interface": iface,
                    "net_bytes_sent": _safe_int(c.bytes_sent),
                    "net_bytes_recv": _safe_int(c.bytes_recv),
                    "net_packets_sent": _safe_int(c.packets_sent),
                    "net_packets_recv": _safe_int(c.packets_recv),
                    "net_errin": _safe_int(c.errin),
                    "net_errout": _safe_int(c.errout),
                    "net_dropin": _safe_int(c.dropin),
                    "net_dropout": _safe_int(c.dropout),
                    "net_connections_total": 0,
                    "net_listen_sockets": 0,
                }
            )
        iface_rows = _top_with_warning(
            iface_rows,
            self.limits.max_interfaces,
            sort_key=lambda x: float((x.get("net_bytes_sent") or 0) + (x.get("net_bytes_recv") or 0)),
            label="network interfaces",
        )
        iface_index = {r["interface"]: r for r in iface_rows}

        try:
            addrs = psutil.net_if_addrs()
            ip_to_iface: dict[str, str] = {}
            for iface in iface_index:
                for addr in addrs.get(iface, []):
                    if getattr(addr, "family", None) in {socket.AF_INET, socket.AF_INET6}:
                        ip = str(getattr(addr, "address", "")).split("%")[0]
                        if ip:
                            ip_to_iface[ip] = iface
            for conn in psutil.net_connections(kind="inet"):
                laddr = getattr(conn, "laddr", None)
                if not laddr:
                    continue
                ip = getattr(laddr, "ip", None)
                iface = ip_to_iface.get(str(ip or ""))
                if not iface:
                    continue
                row = iface_index[iface]
                row["net_connections_total"] = _safe_int(row["net_connections_total"]) + 1
                if str(getattr(conn, "status", "")).upper() == "LISTEN":
                    row["net_listen_sockets"] = _safe_int(row["net_listen_sockets"]) + 1
        except Exception as exc:
            logger.warning("network connection counters unavailable: %s", exc)
        return iface_rows

    def _collect_process(self) -> dict[str, Any]:
        total = 0
        running = 0
        sleeping = 0
        zombie = 0
        proc_rows: list[dict[str, Any]] = []
        for p in psutil.process_iter(["pid", "name", "status", "cpu_percent", "memory_percent", "memory_info"]):
            try:
                info = p.info
                status = str(info.get("status") or "").lower()
                total += 1
                if status == psutil.STATUS_RUNNING:
                    running += 1
                elif status in {psutil.STATUS_SLEEPING, psutil.STATUS_DISK_SLEEP}:
                    sleeping += 1
                elif status == psutil.STATUS_ZOMBIE:
                    zombie += 1
                mem_info = info.get("memory_info")
                proc_rows.append(
                    {
                        "pid": _safe_int(info.get("pid", 0)),
                        "name": str(info.get("name") or ""),
                        "cpu_percent": _safe_float(info.get("cpu_percent", 0.0)),
                        "memory_percent": _safe_float(info.get("memory_percent", 0.0)),
                        "memory_rss_bytes": _safe_int(getattr(mem_info, "rss", 0)),
                    }
                )
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue
        top_cpu = sorted(proc_rows, key=lambda x: float(x["cpu_percent"]), reverse=True)[:5]
        top_mem = sorted(proc_rows, key=lambda x: float(x["memory_percent"]), reverse=True)[:5]
        return {
            "process_total_count": total,
            "process_running_count": running,
            "process_sleeping_count": sleeping,
            "process_zombie_count": zombie,
            "top_5_cpu_processes": top_cpu,
            "top_5_memory_processes": top_mem,
        }

    def _collect_fd(self) -> dict[str, Any]:
        if platform.system().lower() != "linux":
            return {"open_file_descriptors": 0, "max_file_descriptors": 0}
        try:
            file_nr = Path("/proc/sys/fs/file-nr").read_text(encoding="utf-8").strip().split()
            file_max = Path("/proc/sys/fs/file-max").read_text(encoding="utf-8").strip()
            open_fd = _safe_int(file_nr[0] if file_nr else 0)
            max_fd = _safe_int(file_max)
            return {"open_file_descriptors": open_fd, "max_file_descriptors": max_fd}
        except Exception as exc:
            logger.warning("fd metrics unavailable: %s", exc)
            return {"open_file_descriptors": 0, "max_file_descriptors": 0}

    def _collect_system(self) -> dict[str, Any]:
        boot_ts = _safe_float(psutil.boot_time(), 0.0)
        now = time.time()
        return {
            "hostname": socket.gethostname(),
            "os_name": platform.system(),
            "os_version": platform.version(),
            "kernel_version": platform.release(),
            "uptime_seconds": _safe_int(max(0.0, now - boot_ts)),
            "boot_time_timestamp": datetime.fromtimestamp(boot_ts, tz=timezone.utc).isoformat().replace("+00:00", "Z"),
            "architecture": platform.machine(),
        }

    def _collect_load(self) -> dict[str, Any]:
        try:
            l1, l5, l15 = os.getloadavg()
        except Exception:
            l1 = l5 = l15 = 0.0
        return {
            "load_average_1m": _safe_float(l1),
            "load_average_5m": _safe_float(l5),
            "load_average_15m": _safe_float(l15),
        }

    def _collect_temperature(self) -> dict[str, Any]:
        cpu_temp = 0.0
        gpu_temp = 0.0
        try:
            sensors = psutil.sensors_temperatures(fahrenheit=False) or {}
            for _, entries in sensors.items():
                for ent in entries:
                    label = str(getattr(ent, "label", "")).lower()
                    cur = _safe_float(getattr(ent, "current", 0.0))
                    if cpu_temp <= 0.0 or any(k in label for k in ("cpu", "core", "package")):
                        cpu_temp = cur
                        if any(k in label for k in ("cpu", "package")):
                            break
                if cpu_temp > 0.0:
                    break
        except Exception:
            pass
        try:
            if os.system("command -v nvidia-smi >/dev/null 2>&1") == 0:
                import subprocess

                out = subprocess.check_output(
                    ["nvidia-smi", "--query-gpu=temperature.gpu", "--format=csv,noheader,nounits"],
                    text=True,
                    timeout=1.0,
                )
                line = (out or "").strip().splitlines()
                if line:
                    gpu_temp = _safe_float(line[0], 0.0)
        except Exception:
            pass
        return {"cpu_temperature": _safe_float(cpu_temp), "gpu_temperature": _safe_float(gpu_temp)}

    def _detect_docker_socket(self) -> Optional[str]:
        for p in ("/var/run/docker.sock", "/run/docker.sock"):
            if os.path.exists(p):
                return p
        return None

    def _docker_http_get(self, path: str) -> Optional[Any]:
        if not self._docker_socket:
            return None
        req = (
            f"GET {path} HTTP/1.1\r\n"
            "Host: localhost\r\n"
            "Accept: application/json\r\n"
            "Connection: close\r\n\r\n"
        ).encode("utf-8")
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(1.2)
        try:
            sock.connect(self._docker_socket)
            sock.sendall(req)
            data = bytearray()
            while True:
                chunk = sock.recv(65536)
                if not chunk:
                    break
                data.extend(chunk)
        finally:
            sock.close()
        raw = bytes(data)
        head, _, body = raw.partition(b"\r\n\r\n")
        status_line = head.split(b"\r\n", 1)[0].decode("utf-8", errors="ignore")
        if " 200 " not in status_line:
            return None
        try:
            return json.loads(body.decode("utf-8", errors="ignore"))
        except Exception:
            return None

    def _container_cpu_percent(self, stats: dict[str, Any]) -> float:
        cpu_stats = stats.get("cpu_stats") or {}
        precpu = stats.get("precpu_stats") or {}
        cpu_total = _safe_float(((cpu_stats.get("cpu_usage") or {}).get("total_usage", 0)))
        pre_total = _safe_float(((precpu.get("cpu_usage") or {}).get("total_usage", 0)))
        system_total = _safe_float(cpu_stats.get("system_cpu_usage", 0))
        pre_system = _safe_float(precpu.get("system_cpu_usage", 0))
        cpu_delta = cpu_total - pre_total
        system_delta = system_total - pre_system
        online_cpus = _safe_float(cpu_stats.get("online_cpus") or 1.0, 1.0)
        if cpu_delta <= 0 or system_delta <= 0:
            return 0.0
        return float((cpu_delta / system_delta) * online_cpus * 100.0)

    def _container_net_io(self, stats: dict[str, Any]) -> dict[str, int]:
        networks = stats.get("networks") or {}
        rx = 0
        tx = 0
        for _, n in networks.items():
            rx += _safe_int((n or {}).get("rx_bytes", 0))
            tx += _safe_int((n or {}).get("tx_bytes", 0))
        return {"rx_bytes": rx, "tx_bytes": tx}

    def _container_block_io(self, stats: dict[str, Any]) -> dict[str, int]:
        blkio = stats.get("blkio_stats") or {}
        svc = blkio.get("io_service_bytes_recursive") or []
        read_b = 0
        write_b = 0
        for ent in svc:
            op = str((ent or {}).get("op", "")).lower()
            val = _safe_int((ent or {}).get("value", 0))
            if op == "read":
                read_b += val
            elif op == "write":
                write_b += val
        return {"read_bytes": read_b, "write_bytes": write_b}

    def _collect_docker(self) -> list[dict[str, Any]]:
        if not self._docker_socket:
            return []
        containers = self._docker_http_get("/containers/json?all=1")
        if not isinstance(containers, list):
            return []
        rows: list[dict[str, Any]] = []
        for c in containers:
            cid = str((c or {}).get("Id", ""))
            if not cid:
                continue
            inspect = self._docker_http_get(f"/containers/{quote(cid)}/json") or {}
            stats = self._docker_http_get(f"/containers/{quote(cid)}/stats?stream=0") or {}
            name = str((c or {}).get("Names", ["unknown"])[0]).lstrip("/") or "unknown"
            mem_stats = stats.get("memory_stats") or {}
            rows.append(
                {
                    "container_name": name,
                    "container_cpu_percent": _safe_float(self._container_cpu_percent(stats)),
                    "container_memory_usage": _safe_int(mem_stats.get("usage", 0)),
                    "container_memory_limit": _safe_int(mem_stats.get("limit", 0)),
                    "container_net_io": self._container_net_io(stats),
                    "container_block_io": self._container_block_io(stats),
                    "container_restart_count": _safe_int((inspect.get("RestartCount", 0))),
                    "container_status": str((inspect.get("State") or {}).get("Status") or (c or {}).get("State") or ""),
                }
            )
        return _top_with_warning(
            rows,
            self.limits.max_containers,
            sort_key=lambda x: float(
                (x.get("container_memory_usage") or 0) + int(float(x.get("container_cpu_percent") or 0.0) * 1000000.0)
            ),
            label="docker containers",
        )

    def _prom_line(self, metric: str, value: Any, labels: Optional[dict[str, str]] = None) -> str:
        label_str = ""
        if labels:
            parts = [f'{k}="{_sanitize_name(v)}"' for k, v in labels.items()]
            label_str = "{" + ",".join(parts) + "}"
        return f"{metric}{label_str} {value}"

    def to_prometheus(self) -> str:
        p = self._last_payload
        if not p:
            return "# no metrics collected yet\n"
        infra = p.get("infra") or {}
        cpu = infra.get("cpu") or {}
        mem = infra.get("memory") or {}
        lines = [
            self._prom_line("cpu_percent_total", _safe_float(cpu.get("cpu_percent_total", 0.0))),
            self._prom_line("memory_used_bytes", _safe_int(mem.get("memory_used_bytes", 0))),
        ]
        for d in infra.get("disk") or []:
            lines.append(
                self._prom_line(
                    "disk_used_bytes",
                    _safe_int(d.get("disk_used_bytes", 0)),
                    labels={"mount": str(d.get("mountpoint", ""))},
                )
            )
        return "\n".join(lines) + "\n"

    def start_metrics_endpoint(self, host: str = "0.0.0.0", port: int = 9320) -> Thread:
        handler = type("ProbeHandler", (_PrometheusHandler,), {})
        handler.probe = self
        server = ThreadingHTTPServer((host, int(port)), handler)

        def _serve() -> None:
            logger.info("metrics endpoint listening on http://%s:%s/metrics", host, port)
            try:
                server.serve_forever()
            except Exception as exc:
                logger.warning("metrics endpoint stopped: %s", exc)

        t = Thread(target=_serve, name="kakveda-metrics-endpoint", daemon=True)
        t.start()
        return t


class SystemProbeEngine:
    """Periodic non-blocking async collection engine."""

    def __init__(
        self,
        *,
        agent_id: str,
        interval_sec: int = 5,
        on_payload: Optional[Callable[[dict[str, Any]], Any]] = None,
        probe: Optional[SystemProbe] = None,
    ) -> None:
        self.agent_id = str(agent_id)
        self.interval_sec = max(1, int(interval_sec))
        self.on_payload = on_payload
        self.probe = probe or SystemProbe()
        self._thread: Optional[Thread] = None

    async def _run_loop(self) -> None:
        while True:
            try:
                payload = await self.probe.collect(self.agent_id)
                if self.on_payload:
                    result = self.on_payload(payload)
                    if asyncio.iscoroutine(result):
                        await result
            except Exception as exc:
                logger.exception("system probe loop error: %s", exc)
            await asyncio.sleep(self.interval_sec)

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return

        def _runner() -> None:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            loop.run_until_complete(self._run_loop())

        self._thread = Thread(target=_runner, name="kakveda-system-probe", daemon=True)
        self._thread.start()
