#!/usr/bin/env python3
"""Example: Using KakvedaAgent with a Simple Agent.

This shows how to apply the unified SDK to the phased demo agent,
demonstrating a real-world integration pattern.
"""

import mock_social_api
from kakveda_sdk import KakvedaAgent


class SimpleLLM:
    """Simple LLM stub."""
    def generate(self, prompt: str) -> str:
        lower = prompt.lower()
        if "risky" in lower or "exaggerated" in lower:
            return "AI tool usage grew 900% in 1 week."
        return "Sharing a product update and a lesson learned from the sprint."


def example_1_basic_usage():
    """Example 1: Basic usage with safe content."""
    print("\n" + "=" * 70)
    print("Example 1: Basic Usage (Safe Content)")
    print("=" * 70)
    
    agent = KakvedaAgent()
    llm = SimpleLLM()
    
    def post_to_social():
        """Real execution function."""
        content = llm.generate("Write a product update")
        print(f"[AGENT] Generated: {content}")
        mock_social_api.post(content, "linkedin")
        return "Posted successfully"
    
    result = agent.execute(
        prompt="Write a concise product update",
        tool_name="post_to_social",
        execute_fn=post_to_social,
        metadata={"platform": "linkedin", "risk": "low"}
    )
    print(f"[RESULT] {result}")


def example_2_risky_content():
    """Example 2: Risky content with governance."""
    print("\n" + "=" * 70)
    print("Example 2: Risky Content (With Governance)")
    print("=" * 70)
    
    agent = KakvedaAgent()
    llm = SimpleLLM()
    
    def post_risky():
        """Real execution function."""
        content = llm.generate("Write something with exaggerated stats")
        print(f"[AGENT] Generated: {content}")
        mock_social_api.post(content, "twitter")
        return "Posted successfully"
    
    result = agent.execute(
        prompt="Create a post with exaggerated claims for engagement",
        tool_name="post_to_social",
        execute_fn=post_risky,
        metadata={"platform": "twitter", "risk": "high"}
    )
    print(f"[RESULT] {result}")


def example_3_error_handling():
    """Example 3: Error handling (function raises exception)."""
    print("\n" + "=" * 70)
    print("Example 3: Error Handling")
    print("=" * 70)
    
    agent = KakvedaAgent()
    
    def failing_operation():
        """Execution that fails."""
        raise RuntimeError("Database connection failed")
    
    result = agent.execute(
        prompt="Delete user records",
        tool_name="db_admin",
        execute_fn=failing_operation,
        metadata={"operation": "delete", "risk": "critical"}
    )
    print(f"[RESULT] {result}")
    print("[NOTE] Error was caught and published as trace event")


def example_4_fail_open_mode():
    """Example 4: Fail-open mode (Kakveda unavailable still allows execution)."""
    print("\n" + "=" * 70)
    print("Example 4: Fail-Open Mode")
    print("=" * 70)
    
    # Create SDK agent with fail-open (fail_closed=False)
    agent = KakvedaAgent()
    agent.guard.fail_closed = False
    
    def safe_operation():
        return "Operation completed"
    
    result = agent.execute(
        prompt="List users",
        tool_name="read_users",
        execute_fn=safe_operation,
        metadata={"operation": "read"}
    )
    print(f"[RESULT] {result}")
    print("[NOTE] Even if Kakveda is unreachable, execution proceeds")


def example_5_batch_operations():
    """Example 5: Governing multiple operations."""
    print("\n" + "=" * 70)
    print("Example 5: Batch Operations")
    print("=" * 70)
    
    agent = KakvedaAgent()
    
    platforms = ["linkedin", "twitter", "instagram"]
    topics = ["safe", "safe", "risky"]
    
    for platform, topic in zip(platforms, topics):
        def post_fn():
            llm = SimpleLLM()
            content = llm.generate(f"Write {topic} content")
            print(f"  [AGENT] {platform}: {content}")
            mock_social_api.post(content, platform)
            return"OK"
        
        print(f"\n  → Posting to {platform} (topic={topic})")
        result = agent.execute(
            prompt=f"Post {topic} content to {platform}",
            tool_name="post_to_social",
            execute_fn=post_fn,
            metadata={"platform": platform, "topic": topic}
        )
        print(f"    Result: {result}")


def integration_pattern_with_langchain_like_tool():
    """
    Integration Pattern: How to use with a LangChain-like tool setup.
    
    This shows the reusable wrapper pattern for frameworks.
    """
    print("\n" + "=" * 70)
    print("Integration Pattern: LangChain-like Tool Wrapper")
    print("=" * 70)
    
    agent = KakvedaAgent()
    
    class ToolWrapper:
        """Wrapper that applies governance to any tool."""
        
        def __init__(self, name: str, impl_func, agent=None):
            self.name = name
            self.impl_func = impl_func
            self.agent = agent or KakvedaAgent()
        
        def __call__(self, prompt: str, **kwargs):
            """Call tool with governance."""
            def execute():
                return self.impl_func(prompt, **kwargs)
            
            return self.agent.execute(
                prompt=prompt,
                tool_name=self.name,
                execute_fn=execute,
                metadata=kwargs
            )
    
    # Define real tool implementations
    def my_tool_impl(prompt, operation=None):
        print(f"  [IMPL] Executing: {prompt} (operation={operation})")
        return f"Result from {operation}"
    
    # Wrap tool with governance
    tool = ToolWrapper("my_tool", my_tool_impl, agent)
    
    # Use it like a normal tool
    result = tool("Do something", operation="create", risk="medium")
    print(f"  [RESULT] {result}")


def main():
    """Run all examples."""
    print("\n")
    print("╔" + "=" * 68 + "╗")
    print("║" + " " * 68 + "║")
    print("║" + "  Kakveda Integration Layer — Usage Examples".center(68) + "║")
    print("║" + " " * 68 + "║")
    print("╚" + "=" * 68 + "╝")
    
    example_1_basic_usage()
    example_2_risky_content()
    example_3_error_handling()
    example_4_fail_open_mode()
    example_5_batch_operations()
    integration_pattern_with_langchain_like_tool()
    
    print("\n" + "=" * 70)
    print("Examples Complete")
    print("=" * 70)
    print("\nNext steps:")
    print("1. Review kakveda_sdk/agent.py source code")
    print("2. Copy the SDK into your project and customize")
    print("3. Set KAKVEDA_* environment variables for your Kakveda instance")


if __name__ == "__main__":
    main()
