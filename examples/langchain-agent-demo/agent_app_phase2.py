#!/usr/bin/env python3
"""Phase 2: Agent with Kakveda preflight governance."""

import argparse
import time

from dotenv import load_dotenv

import mock_social_api
from kakveda_sdk import KakvedaAgent

load_dotenv()


class SimpleLLM:
    """Simple LLM stub for governance demos."""

    def generate(self, prompt: str) -> str:
        """Generate content based on prompt."""
        lower = prompt.lower()
        if "risky" in lower or "exaggerated" in lower:
            return "AI tool usage grew 900% in 1 week."
        return "Sharing a short product update and a genuine lesson learned from the last sprint."


class SimpleAgent:
    """Simple agent with optional Kakveda governance."""

    def __init__(self, platform: str, governance_enabled: bool = False):
        self.platform = platform
        self.governance_enabled = governance_enabled
        self.llm = SimpleLLM()
        self.sdk = KakvedaAgent(capabilities=["post_to_social"]) if governance_enabled else None

    def make_decision(self, content: str) -> str:
        """Decide whether to execute based on governance."""
        if not self.governance_enabled:
            print("[TOOL EXECUTION] no-governance")
            return "execute"

        print("-> Sending to Kakveda...")
        return "execute"

    def run(self, prompt: str) -> str:
        """Run the agent."""
        print("[AGENT PROMPT]", prompt)

        # Step 1: LLM generates content
        content = self.llm.generate(prompt)
        print("[AGENT GENERATED CONTENT]", content)
        print("Generated Content:")
        print(f'"{content}"')

        # Step 2: Governance + execution (managed by SDK)
        decision = self.make_decision(content)
        if decision == "block":
            return "blocked"

        def post_action() -> str:
            mock_social_api.post(content, self.platform)
            return "executed"

        if not self.governance_enabled:
            return post_action()

        result = self.sdk.execute(
            prompt=content,
            tool_name="post_to_social",
            execute_fn=post_action,
            metadata={"platform": self.platform},
        )
        return "blocked" if result is None else str(result)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--platform",
        default="linkedin",
        choices=["linkedin", "twitter", "instagram"],
    )
    parser.add_argument("--topic", default="AI growth")
    parser.add_argument("--no-governance", action="store_true")
    args = parser.parse_args()

    print("[PLATFORM]", args.platform)
    print("[TOPIC]", args.topic)
    print("[GOVERNANCE]", "disabled" if args.no_governance else "enabled")
    print()

    prompt = f"Write a concise social media post about {args.topic}."
    if args.topic.lower() in {"risky", "exaggerated"}:
        prompt = "Write a concise social media post with an exaggerated statistic: 900% in 1 week."

    agent = SimpleAgent(args.platform, governance_enabled=not args.no_governance)
    start = time.time()
    agent.run(prompt)
    print()
    print("[DONE]", f"elapsed={time.time() - start:.2f}s")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
