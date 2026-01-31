from __future__ import annotations

import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import List, Tuple


@dataclass(frozen=True)
class ComposePlan:
    compose_files: List[str]


def detect_compose_binary() -> List[str]:
    """Return docker compose command as argv prefix.

    Prefer `docker compose` (plugin). Fallback to `docker-compose`.
    """

    # Prefer the Docker Compose plugin (`docker compose`) when available.
    # On some systems, `docker` exists but the compose plugin is missing.
    if shutil.which("docker") is not None and shutil.which("docker-compose") is None:
        # If docker exists, check whether the compose subcommand works.
        try:
            probe = subprocess.run(
                ["docker", "compose", "version"],
                capture_output=True,
                text=True,
            )
            if probe.returncode == 0:
                return ["docker", "compose"]
        except Exception:
            pass

    if shutil.which("docker") is not None:
        # Even if docker exists, `docker compose` might not. Prefer legacy binary if present.
        try:
            probe = subprocess.run(
                ["docker", "compose", "version"],
                capture_output=True,
                text=True,
            )
            if probe.returncode == 0:
                return ["docker", "compose"]
        except Exception:
            pass

    if shutil.which("docker-compose") is not None:
        return ["docker-compose"]

    return []


def plan_compose(repo_root: Path, use_prod: bool) -> ComposePlan:
    files = ["docker-compose.yml"]
    if use_prod:
        files = ["docker-compose.prod.yml"]

    # Validate those files exist.
    for f in files:
        if not (repo_root / f).exists():
            raise FileNotFoundError(f"Missing compose file: {f}")

    return ComposePlan(compose_files=files)


def run_compose_up(repo_root: Path, plan: ComposePlan) -> None:
    cmd_prefix = detect_compose_binary()
    if not cmd_prefix:
        raise RuntimeError(
            "Docker Compose not found. Install Docker Desktop / docker engine + compose plugin."
        )

    args = cmd_prefix + ["-f", plan.compose_files[0], "up", "-d", "--build"]

    # Use subprocess with cwd at repo_root so relative paths work.
    proc = subprocess.run(args, cwd=str(repo_root))
    if proc.returncode != 0:
        raise RuntimeError("docker compose up failed")


def run_compose_ps_quiet(repo_root: Path, plan: ComposePlan) -> str:
    """Like `run_compose_ps`, but doesn't print extra errors; returns stdout."""
    cmd_prefix = detect_compose_binary()
    if not cmd_prefix:
        raise RuntimeError(
            "Docker Compose not found. Install Docker Desktop / docker engine + compose plugin."
        )

    args = cmd_prefix + ["-f", plan.compose_files[0], "ps"]
    proc = subprocess.run(args, cwd=str(repo_root), capture_output=True, text=True)
    if proc.returncode != 0:
        raise RuntimeError("docker compose ps failed")
    return proc.stdout


def get_compose_logs(
    repo_root: Path, plan: ComposePlan, service: str, tail: int = 200
) -> Tuple[int, str, str]:
    """Fetch logs for a service. Returns (returncode, stdout, stderr)."""
    cmd_prefix = detect_compose_binary()
    if not cmd_prefix:
        return (1, "", "Docker Compose not found")

    args = cmd_prefix + ["-f", plan.compose_files[0], "logs", "--tail", str(tail), service]
    proc = subprocess.run(args, cwd=str(repo_root), capture_output=True, text=True)
    return (proc.returncode, proc.stdout, proc.stderr)


def run_compose_down(repo_root: Path, plan: ComposePlan, remove_volumes: bool = False) -> None:
    cmd_prefix = detect_compose_binary()
    if not cmd_prefix:
        raise RuntimeError(
            "Docker Compose not found. Install Docker Desktop / docker engine + compose plugin."
        )

    args = cmd_prefix + ["-f", plan.compose_files[0], "down"]
    if remove_volumes:
        args.append("-v")

    proc = subprocess.run(args, cwd=str(repo_root))
    if proc.returncode != 0:
        raise RuntimeError("docker compose down failed")


def run_compose_ps(repo_root: Path, plan: ComposePlan) -> str:
    cmd_prefix = detect_compose_binary()
    if not cmd_prefix:
        raise RuntimeError(
            "Docker Compose not found. Install Docker Desktop / docker engine + compose plugin."
        )

    args = cmd_prefix + ["-f", plan.compose_files[0], "ps"]
    proc = subprocess.run(args, cwd=str(repo_root), capture_output=True, text=True)
    if proc.returncode != 0:
        raise RuntimeError("docker compose ps failed")
    return proc.stdout
