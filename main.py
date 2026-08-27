#!/usr/bin/env python3
"""
YouTrack MCP Server - A Model Context Protocol server for JetBrains YouTrack.
Uses FastMCP directly for stdio, SSE, and Streamable HTTP transport support.
"""

import logging
import os
import sys
from urllib.parse import urlsplit, urlunsplit

import httpx
from mcp.server.fastmcp import FastMCP
from starlette.requests import Request
from starlette.responses import JSONResponse

from youtrack_mcp.config import config
from youtrack_mcp.tool_execution import ToolExecutionPool, make_async_tool
from youtrack_mcp.tools.loader import load_all_tools
from youtrack_mcp.version import __version__ as APP_VERSION

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[logging.StreamHandler(sys.stderr)],
)
logger = logging.getLogger(__name__)


def create_server(host: str = "0.0.0.0", port: int = 8000) -> FastMCP:
    """Create and configure the FastMCP server with all tools registered."""
    mcp = FastMCP(
        config.MCP_SERVER_NAME,
        instructions=config.MCP_SERVER_DESCRIPTION,
        host=host,
        port=port,
    )

    tool_pool = ToolExecutionPool(
        max_concurrency=config.TOOL_MAX_CONCURRENCY,
        max_pending=config.TOOL_MAX_PENDING,
        queue_timeout_seconds=config.TOOL_QUEUE_TIMEOUT,
    )

    # Tool implementations use blocking HTTP clients. Keep that work outside
    # the protocol event loop so initialize, ping, and discovery stay responsive.
    tools = load_all_tools()
    for name, func in tools.items():
        mcp.add_tool(make_async_tool(func, tool_pool), name=name)

    @mcp.custom_route("/healthz", methods=["GET"])
    async def healthz(_: Request) -> JSONResponse:
        return JSONResponse({"status": "ok"})

    @mcp.custom_route("/readyz", methods=["GET"])
    async def readyz(_: Request) -> JSONResponse:
        details: dict[str, object] = {"toolPool": tool_pool.snapshot()}
        ready = tool_pool.ready

        if config.SANITIZER_REQUIRED and config.SANITIZER_URL:
            parsed = urlsplit(config.SANITIZER_URL)
            health_url = urlunsplit((parsed.scheme, parsed.netloc, "/ready", "", ""))
            try:
                async with httpx.AsyncClient(
                    timeout=httpx.Timeout(2.0, connect=1.0)
                ) as client:
                    response = await client.get(health_url)
                    response.raise_for_status()
                details["sanitizer"] = "ok"
            except (httpx.HTTPError, ValueError) as exc:
                logger.warning("Sanitizer readiness check failed: %s", exc)
                details["sanitizer"] = "unavailable"
                ready = False

        details["status"] = "ready" if ready else "not-ready"
        return JSONResponse(details, status_code=200 if ready else 503)

    logger.info(f"Registered {len(tools)} tools with FastMCP")
    return mcp


def main():
    """Run the MCP server."""
    import argparse

    parser = argparse.ArgumentParser(description="YouTrack MCP Server")
    parser.add_argument(
        "--transport",
        choices=["stdio", "sse", "streamable-http"],
        default=None,
        help="Transport mode (default: from TRANSPORT env var, fallback stdio)",
    )
    parser.add_argument("--host", default="0.0.0.0", help="Host for SSE transport")
    parser.add_argument("--port", type=int, default=None, help="Port for SSE transport")
    parser.add_argument("--version", action="store_true", help="Show version and exit")
    parser.add_argument(
        "--log-level",
        default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
    )
    args = parser.parse_args()

    if args.version:
        print(f"YouTrack MCP Server v{APP_VERSION}")
        sys.exit(0)

    logging.getLogger().setLevel(getattr(logging, args.log_level))

    # Determine transport: CLI arg > env var > default stdio
    transport = args.transport or os.getenv("TRANSPORT", "stdio")
    port = args.port or int(os.getenv("PORT", "8000"))

    logger.info(f"Starting YouTrack MCP Server v{APP_VERSION} [{transport}]")

    mcp = create_server(host=args.host, port=port)
    mcp.run(transport=transport)


if __name__ == "__main__":
    main()
