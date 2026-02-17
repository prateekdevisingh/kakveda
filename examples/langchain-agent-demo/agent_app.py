#!/usr/bin/env python3
"""Managed external agent demo: governance + events + dashboard registration."""

from __future__ import annotations

import argparse
import json
import os
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any, Optional

from dotenv import load_dotenv

import mock_social_api
from kakveda_sdk import KakvedaAgent


load_dotenv()


def _env(name: str, default: str) -> str:
    v = os.getenv(name)
    return v if (v is not None and str(v).strip() != "") else default


AGENT_NAME = _env("AGENT_NAME", "langchain-social-agent")
AGENT_APP_ID = _env("AGENT_APP_ID", "langchain-social-agent")
AGENT_VERSION = _env("AGENT_VERSION", "1.0.0")
MODEL_NAME = _env("MODEL_NAME", "demo-llm")


class SimpleLLM:
    """Simple LLM stub for governance demos."""

    def generate(self, prompt: str) -> str:
        lower = prompt.lower()
        if "risky" in lower or "exaggerated" in lower:
            return "AI tool usage grew 900% in 1 week."
        return "Sharing a short product update and a genuine lesson learned from the last sprint."


class SimpleAgent:
    """Simple agent with optional Kakveda governance."""

    def __init__(self, platform: str, governance_enabled: bool = True):
        self.platform = platform
        self.governance_enabled = governance_enabled
        self.llm = SimpleLLM()
        self.sdk = KakvedaAgent(capabilities=["post_to_social"]) if governance_enabled else None

    def run(self, prompt: str) -> str:
        print("[AGENT PROMPT]", prompt)
        content = self.llm.generate(prompt)
        print("[AGENT GENERATED CONTENT]", content)
        print("Generated Content:")
        print(f'"{content}"')

        def post_action() -> str:
            mock_social_api.post(content, self.platform)
            return "executed"

        # Execution flow (clean):
        # Agent -> preflight (/warn) -> decision -> execute -> publish trace.ingested
        if not self.governance_enabled:
            print("[TOOL EXECUTION] no-governance")
            return post_action()

        result = self.sdk.execute(
            prompt=content,
            tool_name="post_to_social",
            execute_fn=post_action,
            metadata={
                "platform": self.platform,
                "agent_name": AGENT_NAME,
                "agent_version": AGENT_VERSION,
                "user_prompt": prompt,
            },
            model_name=MODEL_NAME,
        )
        return "blocked" if result is None else str(result)


def _start_health_server() -> None:
    """Expose /health so dashboard can test this agent."""
    port = 8120

    class Handler(BaseHTTPRequestHandler):
        def _send(self, status: int, obj: dict[str, Any]) -> None:
            body = json.dumps(obj).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):  # noqa: N802
            if self.path.rstrip("/") == "/health":
                self._send(
                    200,
                    {
                        "ok": True,
                        "agent_name": AGENT_NAME,
                        "app_id": AGENT_APP_ID,
                        "version": AGENT_VERSION,
                        "status": "online",
                    },
                )
                return
            self._send(404, {"ok": False, "error": "not found"})

        def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
            # keep demo output clean
            return

    srv = HTTPServer(("0.0.0.0", port), Handler)
    t = threading.Thread(target=srv.serve_forever, name="health-server", daemon=True)
    t.start()
    print(f"[AGENT] health server listening on :{port} (GET /health)")


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--platform",
        default="linkedin",
        choices=["linkedin", "twitter", "instagram"],
    )
    parser.add_argument("--topic", default="AI growth")
    parser.add_argument("--no-governance", action="store_true")
    parser.add_argument(
        "--run-once",
        action="store_true",
        help="Run one execution then exit (default is to keep running for heartbeats).",
    )
    args = parser.parse_args(argv)

    print("[AGENT_NAME]", AGENT_NAME)
    print("[AGENT_APP_ID]", AGENT_APP_ID)
    print("[AGENT_VERSION]", AGENT_VERSION)
    print("[MODEL_NAME]", MODEL_NAME)
    print("[PLATFORM]", args.platform)
    print("[TOPIC]", args.topic)
    print("[GOVERNANCE]", "disabled" if args.no_governance else "enabled")
    print()

    # Startup flow: health server -> init agent -> run.
    _start_health_server()

    prompt = f"Write a concise social media post about {args.topic}."
    if args.topic.lower() in {"risky", "exaggerated"}:
        prompt = "Write a concise social media post with an exaggerated statistic: 900% in 1 week."

    agent = SimpleAgent(args.platform, governance_enabled=not args.no_governance)
    started = time.time()
    result = agent.run(prompt)
    print()
    print("[RESULT]", result)
    print("[DONE]", f"elapsed={time.time() - started:.2f}s")

    if args.run_once:
        return 0

    # Keep container alive so heartbeats continue.
    while True:
        time.sleep(3600)


if __name__ == "__main__":
    raise SystemExit(main())
