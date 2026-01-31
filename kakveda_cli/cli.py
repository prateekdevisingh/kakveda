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


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="kakveda", description="Kakveda setup + run CLI")
    sub = p.add_subparsers(dest="cmd", required=True)

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

    return p


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    ns = parser.parse_args(argv)
    return int(ns.func(ns))


if __name__ == "__main__":
    raise SystemExit(main())
