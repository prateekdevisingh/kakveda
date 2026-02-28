#!/usr/bin/env python3
"""One-shot node metrics collector test."""

from __future__ import annotations

import asyncio
import json
import os

from kakveda_sdk.system_probe import ProbeLimits, SystemProbe


async def main() -> None:
    limits = ProbeLimits(
        max_interfaces=int(os.getenv("INFRA_MAX_INTERFACES", "50")),
        max_containers=int(os.getenv("INFRA_MAX_CONTAINERS", "100")),
        max_partitions=int(os.getenv("INFRA_MAX_PARTITIONS", "20")),
    )
    probe = SystemProbe(limits=limits)
    payload = await probe.collect(agent_id=os.getenv("AGENT_NAME", "host-01"))
    print(json.dumps(payload, indent=2, sort_keys=False))


if __name__ == "__main__":
    asyncio.run(main())
