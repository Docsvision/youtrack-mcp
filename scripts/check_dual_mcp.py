"""Compare local sanitized and plain MCP results without sending them to a model."""

from __future__ import annotations

import argparse
import asyncio
import json
from pathlib import Path
from typing import Any

from mcp import ClientSession
from mcp.client.streamable_http import streamable_http_client


def expand_json_strings(value: Any) -> Any:
    """Recursively decode strings that contain JSON objects or arrays."""
    if isinstance(value, dict):
        return {key: expand_json_strings(item) for key, item in value.items()}
    if isinstance(value, list):
        return [expand_json_strings(item) for item in value]
    if not isinstance(value, str):
        return value

    stripped = value.strip()
    if not stripped.startswith(("{", "[")):
        return value
    try:
        decoded = json.loads(value)
    except json.JSONDecodeError:
        return value
    return expand_json_strings(decoded)


async def call_tools(url: str, issue_id: str) -> dict[str, Any]:
    """Call the protected read-only issue tools on one MCP endpoint."""
    results: dict[str, Any] = {}
    async with streamable_http_client(url) as (read, write, _):
        async with ClientSession(read, write) as session:
            await session.initialize()
            for tool_name in ("get_issue", "get_issue_comments", "get_issue_links"):
                response = await session.call_tool(tool_name, {"issue_id": issue_id})
                results[tool_name] = response.model_dump(mode="json")
    return results


async def run(args: argparse.Namespace) -> None:
    sanitized, plain = await asyncio.gather(
        call_tools(args.sanitized_url, args.issue),
        call_tools(args.plain_url, args.issue),
    )
    output_dir = Path(args.output_dir).resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    files = {
        output_dir / f"{args.issue}-sanitized.json": sanitized,
        output_dir / f"{args.issue}-plain.json": plain,
    }
    for path, payload in files.items():
        path.write_text(
            json.dumps(expand_json_strings(payload), ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        print(path)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("issue", help="YouTrack issue ID, for example SUP-14337")
    parser.add_argument(
        "--sanitized-url",
        default="http://127.0.0.1:8001/mcp",
    )
    parser.add_argument(
        "--plain-url",
        default="http://127.0.0.1:8002/mcp",
    )
    parser.add_argument("--output-dir", default="work/mcp-comparison")
    asyncio.run(run(parser.parse_args()))


if __name__ == "__main__":
    main()
