from __future__ import annotations

import argparse
import os
import sys
from glob import glob
from pathlib import Path

from .compose import (
    get_compose_logs,
    plan_compose,
    run_compose_down,
    run_compose_ps,
    run_compose_ps_quiet,
    run_compose_up,
)
from .config import SetupAnswers, env_dict_from_answers, write_env_file
from .prompts import collect_answers

__version__ = "1.0.0"

BANNER = """
╔═══════════════════════════════════════════════════════════╗
║                                                           ║
║   ██╗  ██╗ █████╗ ██╗  ██╗██╗   ██╗███████╗██████╗  █████╗ ║
║   ██║ ██╔╝██╔══██╗██║ ██╔╝██║   ██║██╔════╝██╔══██╗██╔══██╗║
║   █████╔╝ ███████║█████╔╝ ██║   ██║█████╗  ██║  ██║███████║║
║   ██╔═██╗ ██╔══██║██╔═██╗ ╚██╗ ██╔╝██╔══╝  ██║  ██║██╔══██║║
║   ██║  ██╗██║  ██║██║  ██╗ ╚████╔╝ ███████╗██████╔╝██║  ██║║
║   ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝  ╚═══╝  ╚══════╝╚═════╝ ╚═╝  ╚═╝║
║                                                           ║
║   LLM Failure Intelligence Platform                       ║
║   Version: {version}                                          ║
║   Author: Prateek Chaudhary                               ║
║   https://kakveda.com                                     ║
║                                                           ║
╚═══════════════════════════════════════════════════════════╝
""".format(version=__version__)


def _repo_root_from_cwd() -> Path:
    # Works when user runs `kakveda` inside the repo.
    return Path(os.getcwd()).resolve()


def cmd_init(args: argparse.Namespace) -> int:
    repo_root = _repo_root_from_cwd()
    env_path = repo_root / ".env"

    if env_path.exists() and not args.force:
        print(".env already exists. Use --force to overwrite.")
        return 2

    raw = collect_answers()

    answers = SetupAnswers(
        dashboard_db_url=raw.dashboard_db_url,
        dashboard_jwt_secret=raw.dashboard_jwt_secret,
        redis_url=raw.redis_url,
        otel_enabled=raw.otel_enabled,
        otel_exporter_otlp_endpoint=raw.otel_exporter_otlp_endpoint,
        model_provider=raw.model_provider,
        model_api_key=raw.model_api_key,
        model_base_url=raw.model_base_url,
        model_name=raw.model_name,
        use_prod_compose=raw.use_prod_compose,
    )

    env = env_dict_from_answers(answers)
    write_env_file(env_path, env)

    print(f"\nWrote {env_path}")
    print("Tip: commit .env.example, but do NOT commit .env")

    # Optional convenience: start the stack right after writing .env.
    if getattr(args, "and_up", False):
        plan = plan_compose(repo_root, use_prod=answers.use_prod_compose)
        print("\nStarting Kakveda with Docker Compose...")
        run_compose_up(repo_root, plan)
        print("\n✅ Kakveda is starting.")
        print("Dashboard: http://localhost:8110")

    # UX hint for users who try `start`
    if not getattr(args, "and_up", False):
        print("\nNext: run `kakveda up` (or `python -m kakveda_cli.cli up`) to start the stack.")
    return 0


def cmd_up(args: argparse.Namespace) -> int:
    repo_root = _repo_root_from_cwd()

    # If .env missing, offer to run init.
    if not (repo_root / ".env").exists() and not args.no_init:
        print(".env not found. Starting interactive setup...")
        rc = cmd_init(argparse.Namespace(force=False))
        if rc != 0:
            return rc

    plan = plan_compose(repo_root, use_prod=args.prod)
    print("\nStarting Kakveda with Docker Compose...")
    run_compose_up(repo_root, plan)

    # Quick post-start sanity check. Common failure mode: dashboard crashes early.
    try:
        ps_out = run_compose_ps_quiet(repo_root, plan)
        if "dashboard" not in ps_out:
            # Could be a crash or compose v1 formatting mismatch. Fetch logs to help.
            rc, out, err = get_compose_logs(repo_root, plan, "dashboard", tail=120)
            print("\n⚠️  Dashboard does not appear to be running yet.")
            if rc == 0 and (out.strip() or err.strip()):
                print("\nLast dashboard logs:\n")
                print(out.strip() or err.strip())
            print("\nTry: `kakveda status` and then `kakveda down` + `kakveda up` after fixing the error.")
            return 1
    except Exception:
        # Don't fail the command just because the check couldn't run.
        pass

    print("\n✅ Kakveda is starting.")
    print("Dashboard: http://localhost:8110")
    return 0


def _remove_local_db_files(repo_root: Path) -> None:
    data_dir = repo_root / "data"
    if not data_dir.exists() or not data_dir.is_dir():
        return

    patterns = ["*.db", "*.sqlite", "*.sqlite3"]
    for pat in patterns:
        for p in data_dir.glob(pat):
            try:
                p.unlink()
                print(f"Removed local DB: {p}")
            except FileNotFoundError:
                pass


def cmd_down(args: argparse.Namespace) -> int:
    repo_root = _repo_root_from_cwd()
    plan = plan_compose(repo_root, use_prod=args.prod)
    print("Stopping Kakveda stack...")
    run_compose_down(repo_root, plan, remove_volumes=args.volumes)
    print("✅ Stopped.")
    return 0


def cmd_status(args: argparse.Namespace) -> int:
    repo_root = _repo_root_from_cwd()
    plan = plan_compose(repo_root, use_prod=args.prod)
    print(run_compose_ps(repo_root, plan))

    # Convenience URLs
    print("URLs (default ports):")
    print("- Dashboard: http://localhost:8110")
    print("- Event bus: http://localhost:8100")
    print("- GFKB: http://localhost:8101")
    print("- Ingestion: http://localhost:8102")
    print("- Failure classifier: http://localhost:8103")
    print("- Pattern detector: http://localhost:8104")
    print("- Warning policy: http://localhost:8105")
    print("- Health scoring: http://localhost:8106")
    print("- Ollama (optional): http://localhost:11434")
    return 0


def cmd_reset(args: argparse.Namespace) -> int:
    repo_root = _repo_root_from_cwd()
    plan = plan_compose(repo_root, use_prod=args.prod)

    print("Stopping Kakveda stack (for clean reset)...")
    # Bring it down first so sqlite files aren't locked.
    run_compose_down(repo_root, plan, remove_volumes=args.volumes)

    print("Cleaning local runtime data...")
    _remove_local_db_files(repo_root)

    print("✅ Reset complete.")
    if args.volumes:
        print("Note: docker volumes removed (-v).")
    return 0


def cmd_logs(args: argparse.Namespace) -> int:
    """Show logs from services."""
    repo_root = _repo_root_from_cwd()
    plan = plan_compose(repo_root, use_prod=args.prod)
    
    service = args.service if args.service else None
    tail = args.tail if args.tail else 100
    
    rc, out, err = get_compose_logs(repo_root, plan, service, tail=tail)
    
    if out:
        print(out)
    if err:
        print(err, file=sys.stderr)
    
    return rc


def cmd_version(args: argparse.Namespace) -> int:
    """Show version and info."""
    print(BANNER)
    return 0


def cmd_doctor(args: argparse.Namespace) -> int:
    """Check system requirements and diagnose issues."""
    import shutil
    import subprocess
    
    print("🔍 Kakveda Doctor - System Check\n")
    print("=" * 50)
    
    issues = []
    
    # Check Docker
    print("\n📦 Docker:")
    docker_path = shutil.which("docker")
    if docker_path:
        try:
            result = subprocess.run(["docker", "--version"], capture_output=True, text=True)
            print(f"   ✅ Docker: {result.stdout.strip()}")
        except Exception as e:
            print(f"   ❌ Docker error: {e}")
            issues.append("Docker not working properly")
    else:
        print("   ❌ Docker not found")
        issues.append("Docker not installed")
    
    # Check Docker Compose
    print("\n🐳 Docker Compose:")
    try:
        # Try V2 first
        result = subprocess.run(["docker", "compose", "version"], capture_output=True, text=True)
        if result.returncode == 0:
            print(f"   ✅ Docker Compose V2: {result.stdout.strip()}")
        else:
            raise Exception("V2 not available")
    except Exception:
        try:
            # Try V1
            result = subprocess.run(["docker-compose", "--version"], capture_output=True, text=True)
            version_str = result.stdout.strip()
            print(f"   ⚠️  Docker Compose V1: {version_str}")
            print("   💡 Tip: Upgrade to V2 for better compatibility")
            print("      See: TROUBLESHOOTING.md for upgrade instructions")
        except Exception:
            print("   ❌ Docker Compose not found")
            issues.append("Docker Compose not installed")
    
    # Check Python
    print("\n🐍 Python:")
    print(f"   ✅ Python: {sys.version}")
    
    # Check .env
    print("\n📄 Configuration:")
    repo_root = _repo_root_from_cwd()
    env_path = repo_root / ".env"
    if env_path.exists():
        print(f"   ✅ .env file found: {env_path}")
    else:
        print("   ⚠️  .env file not found")
        print("   💡 Run: kakveda init")
    
    # Check if services are running
    print("\n🚀 Services:")
    try:
        plan = plan_compose(repo_root, use_prod=False)
        ps_out = run_compose_ps_quiet(repo_root, plan)
        if ps_out.strip():
            running = [line for line in ps_out.strip().split('\n') if line.strip()]
            print(f"   ✅ {len(running)} container(s) running")
        else:
            print("   ⚠️  No containers running")
            print("   💡 Run: kakveda up")
    except Exception as e:
        print(f"   ⚠️  Could not check services: {e}")
    
    # Summary
    print("\n" + "=" * 50)
    if issues:
        print(f"\n❌ Found {len(issues)} issue(s):")
        for issue in issues:
            print(f"   • {issue}")
        print("\n📖 See TROUBLESHOOTING.md for solutions")
        return 1
    else:
        print("\n✅ All checks passed! Kakveda is ready.")
        return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="kakveda",
        description="Kakveda – LLM Failure Intelligence Platform CLI",
        epilog="Author: Prateek Chaudhary | https://kakveda.com"
    )
    p.add_argument("-v", "--version", action="store_true", help="Show version info")
    sub = p.add_subparsers(dest="cmd")

    p_init = sub.add_parser("init", help="Create a .env file interactively")
    p_init.add_argument("--force", action="store_true", help="Overwrite existing .env")
    p_init.add_argument(
        "--and-up",
        action="store_true",
        help="After writing .env, also run docker compose up",
    )
    p_init.set_defaults(func=cmd_init)

    p_up = sub.add_parser("up", help="Run docker compose up (and create .env if missing)")
    p_up.add_argument(
        "--prod",
        action="store_true",
        help="Use docker-compose.prod.yml (production-like example)",
    )
    p_up.add_argument(
        "--no-init",
        action="store_true",
        help="Do not prompt for .env creation if missing",
    )
    p_up.set_defaults(func=cmd_up)

    p_down = sub.add_parser("down", help="Stop the Kakveda stack")
    p_down.add_argument(
        "--prod",
        action="store_true",
        help="Use docker-compose.prod.yml (production-like example)",
    )
    p_down.add_argument(
        "--volumes",
        action="store_true",
        help="Also remove docker volumes (docker compose down -v)",
    )
    p_down.set_defaults(func=cmd_down)

    p_status = sub.add_parser("status", help="Show running containers and URLs")
    p_status.add_argument(
        "--prod",
        action="store_true",
        help="Use docker-compose.prod.yml (production-like example)",
    )
    p_status.set_defaults(func=cmd_status)

    p_reset = sub.add_parser(
        "reset",
        help="Stop stack and remove local DB/runtime data for a clean demo",
    )
    p_reset.add_argument(
        "--prod",
        action="store_true",
        help="Use docker-compose.prod.yml (production-like example)",
    )
    p_reset.add_argument(
        "--volumes",
        action="store_true",
        help="Also remove docker volumes (docker compose down -v)",
    )
    p_reset.set_defaults(func=cmd_reset)

    # Logs command
    p_logs = sub.add_parser("logs", help="Show logs from services")
    p_logs.add_argument(
        "service",
        nargs="?",
        default=None,
        help="Service name (e.g., dashboard, gfkb). If omitted, shows all logs",
    )
    p_logs.add_argument(
        "--tail",
        type=int,
        default=100,
        help="Number of log lines to show (default: 100)",
    )
    p_logs.add_argument(
        "--prod",
        action="store_true",
        help="Use docker-compose.prod.yml",
    )
    p_logs.set_defaults(func=cmd_logs)

    # Doctor command
    p_doctor = sub.add_parser("doctor", help="Check system requirements and diagnose issues")
    p_doctor.set_defaults(func=cmd_doctor)

    # Version command
    p_version = sub.add_parser("version", help="Show version info")
    p_version.set_defaults(func=cmd_version)

    return p


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    ns = parser.parse_args(argv)
    
    # Handle -v/--version flag
    if getattr(ns, 'version', False):
        print(BANNER)
        return 0
    
    # If no command given, show help
    if not ns.cmd:
        print(BANNER)
        parser.print_help()
        return 0
    
    return int(ns.func(ns))


if __name__ == "__main__":
    raise SystemExit(main())
