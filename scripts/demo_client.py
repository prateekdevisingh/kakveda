from __future__ import annotations

import asyncio
import os
import uuid
from datetime import datetime, timezone

import httpx


INGEST_URL = os.environ.get("INGEST_URL", "http://localhost:8102")
WARN_URL = os.environ.get("WARN_URL", "http://localhost:8105")
GFKB_URL = os.environ.get("GFKB_URL", "http://localhost:8101")
HEALTH_URL = os.environ.get("HEALTH_URL", "http://localhost:8106")
OLLAMA_URL = os.environ.get("OLLAMA_URL", "http://localhost:11434")
OLLAMA_MODEL = os.environ.get("OLLAMA_MODEL", "llama3")


def now():
    return datetime.now(timezone.utc).isoformat()


async def ollama_generate(prompt: str) -> str:
    # Black-box: if not reachable, return a stub that includes citations to trigger the demo.
    try:
        async with httpx.AsyncClient(timeout=4.0) as client:
            r = await client.post(
                f"{OLLAMA_URL}/api/generate",
                json={"model": OLLAMA_MODEL, "prompt": prompt, "stream": False},
            )
            r.raise_for_status()
            data = r.json()
            return data.get("response") or ""
    except Exception:
        return (
            "Here is a summary with references.\n\n"
            "References:\n"
            "[1] Smith et al. (2020) A Study on Things.\n"
            "[2] Doe (2021) Another Paper.\n"
        )


async def run():
    async with httpx.AsyncClient(timeout=6.0) as client:
        scenarios = [
            ("app-A", "Summarize this document and include citations even if not provided."),
            ("app-B", "Explain research paper and add references."),
        ]

        for app_id, prompt in scenarios:
            print(f"\n--- Scenario for {app_id} ---")

            # warning check (runtime)
            w = await client.post(
                f"{WARN_URL}/warn",
                json={"app_id": app_id, "agent_id": "agent-1", "prompt": prompt, "tools": [], "env": {"os": "linux"}},
            )
            print("warning:", w.json())

            response = await ollama_generate(prompt)

            trace = {
                "trace_id": str(uuid.uuid4()),
                "ts": now(),
                "app_id": app_id,
                "agent_id": "agent-1",
                "prompt": prompt,
                "response": response,
                "model": OLLAMA_MODEL,
                "temperature": 0.2,
                "tools": [],
                "env": {"os": "linux"},
            }

            ing = await client.post(f"{INGEST_URL}/ingest", json={"trace": trace})
            print("ingest:", ing.json())

        # add extra executions to degrade health
        for i in range(8):
            app_id = "app-A"
            prompt = "Summarize and add references" if i % 2 == 0 else "Short answer with citations"
            response = await ollama_generate(prompt)
            trace = {
                "trace_id": str(uuid.uuid4()),
                "ts": now(),
                "app_id": app_id,
                "agent_id": "agent-1",
                "prompt": prompt,
                "response": response,
                "model": OLLAMA_MODEL,
                "temperature": 0.2,
                "tools": [],
                "env": {"os": "linux"},
            }
            await client.post(f"{INGEST_URL}/ingest", json={"trace": trace})

        failures = (await client.get(f"{GFKB_URL}/failures")).json()
        patterns = (await client.get(f"{GFKB_URL}/patterns")).json()
        health = (await client.get(f"{HEALTH_URL}/health/app-A")).json()

        print("\n--- GFKB failures ---")
        print(failures)
        print("\n--- Patterns ---")
        print(patterns)
        print("\n--- Health(app-A) latest ---")
        print(health["points"][-1] if health.get("points") else health)


if __name__ == "__main__":
    asyncio.run(run())
