"""Exercise independent MCP sessions concurrently and report responsiveness."""

from __future__ import annotations

import argparse
import asyncio
import json
import time
from datetime import timedelta
from typing import Any

import httpx
from mcp import ClientSession
from mcp.client.streamable_http import streamable_http_client


def contains_tool_error(value: Any) -> bool:
    """Detect fail-closed errors even when MCP returns them as JSON text."""
    if isinstance(value, dict):
        if value.get("status") == "error" or value.get("isError") is True:
            return True
        return any(contains_tool_error(item) for item in value.values())
    if isinstance(value, list):
        return any(contains_tool_error(item) for item in value)
    if not isinstance(value, str):
        return False

    stripped = value.strip()
    if stripped.startswith(("{", "[")):
        try:
            return contains_tool_error(json.loads(stripped))
        except json.JSONDecodeError:
            pass
    lowered = value.casefold()
    return any(
        marker in lowered
        for marker in ("server_busy", "output blocked", "sanitization failed")
    )


async def run_user(
    user_id: int,
    *,
    url: str,
    issue_id: str,
    request_timeout: float,
    start: asyncio.Event,
    initialized: asyncio.Queue[dict[str, Any]],
) -> dict[str, Any]:
    timeout = httpx.Timeout(connect=3, read=request_timeout, write=10, pool=5)
    initialized_sent = False
    called_at: float | None = None
    try:
        async with httpx.AsyncClient(timeout=timeout) as http_client:
            async with streamable_http_client(url, http_client=http_client) as streams:
                read, write, _ = streams
                async with ClientSession(read, write) as session:
                    initialized_at = time.monotonic()
                    await session.initialize()
                    initialization_seconds = time.monotonic() - initialized_at
                    await initialized.put(
                        {
                            "user": user_id,
                            "initializationSeconds": initialization_seconds,
                        }
                    )
                    initialized_sent = True
                    await start.wait()

                    called_at = time.monotonic()
                    response = await session.call_tool(
                        "get_issue",
                        {"issue_id": issue_id},
                        read_timeout_seconds=timedelta(seconds=request_timeout),
                    )
                    duration_seconds = time.monotonic() - called_at
                    body = response.model_dump(mode="json")
                    return {
                        "user": user_id,
                        "durationSeconds": round(duration_seconds, 3),
                        "success": not contains_tool_error(body),
                        "isError": response.isError,
                    }
    except Exception as exc:
        if not initialized_sent:
            await initialized.put(
                {"user": user_id, "initializationError": type(exc).__name__}
            )
        return {
            "user": user_id,
            "durationSeconds": (
                round(time.monotonic() - called_at, 3) if called_at else None
            ),
            "success": False,
            "error": f"{type(exc).__name__}: {exc}",
        }


async def probe_new_session(url: str) -> float:
    """Verify that initialize remains responsive while tools are running."""
    await asyncio.sleep(0.1)
    timeout = httpx.Timeout(connect=2, read=5, write=5, pool=2)
    async with httpx.AsyncClient(timeout=timeout) as http_client:
        async with streamable_http_client(url, http_client=http_client) as streams:
            read, write, _ = streams
            async with ClientSession(read, write) as session:
                started_at = time.monotonic()
                await session.initialize()
                initialization_seconds = time.monotonic() - started_at
                # Complete one ordinary request before closing so the probe
                # follows a normal client lifecycle and does not manufacture
                # a disconnect race in the MCP SDK's transport logs.
                await session.list_tools()
                return initialization_seconds


async def probe_health(url: str, finished: asyncio.Event) -> dict[str, Any]:
    health_url = url.removesuffix("/mcp") + "/healthz"
    latencies = []
    failures = 0
    async with httpx.AsyncClient(timeout=2) as client:
        while not finished.is_set():
            started_at = time.monotonic()
            try:
                response = await client.get(health_url)
                response.raise_for_status()
                latencies.append(time.monotonic() - started_at)
            except httpx.HTTPError:
                failures += 1
            await asyncio.sleep(0.1)
    return {
        "samples": len(latencies),
        "failures": failures,
        "maxLatencySeconds": round(max(latencies, default=0), 3),
    }


async def run(args: argparse.Namespace) -> None:
    start = asyncio.Event()
    finished = asyncio.Event()
    initialized: asyncio.Queue[dict[str, Any]] = asyncio.Queue()
    users = [
        asyncio.create_task(
            run_user(
                user_id,
                url=args.url,
                issue_id=args.issue,
                request_timeout=args.request_timeout,
                start=start,
                initialized=initialized,
            )
        )
        for user_id in range(1, args.users + 1)
    ]

    initialization = [await initialized.get() for _ in users]
    health_task = asyncio.create_task(probe_health(args.url, finished))
    start.set()
    protocol_probe = asyncio.create_task(probe_new_session(args.url))
    results = await asyncio.gather(*users)
    protocol_latency = await protocol_probe
    finished.set()
    health = await health_task

    report = {
        "users": args.users,
        "successful": sum(result["success"] for result in results),
        "initializationMaxSeconds": round(
            max(
                (
                    item["initializationSeconds"]
                    for item in initialization
                    if "initializationSeconds" in item
                ),
                default=0,
            ),
            3,
        ),
        "initializationFailures": sum(
            "initializationError" in item for item in initialization
        ),
        "initializeDuringLoadSeconds": round(protocol_latency, 3),
        "health": health,
        "requests": results,
    }
    print(json.dumps(report, ensure_ascii=False, indent=2))
    if report["successful"] != args.users or health["failures"]:
        raise SystemExit(1)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("issue", help="Read-only YouTrack issue ID")
    parser.add_argument("--url", default="http://127.0.0.1:8001/mcp")
    parser.add_argument("--users", type=int, default=8)
    parser.add_argument("--request-timeout", type=float, default=130)
    args = parser.parse_args()
    if args.users < 1:
        parser.error("--users must be positive")
    if args.request_timeout <= 0:
        parser.error("--request-timeout must be positive")
    asyncio.run(run(args))


if __name__ == "__main__":
    main()
