"""Non-blocking, bounded execution for synchronous MCP tools."""

from __future__ import annotations

import asyncio
import inspect
import json
import logging
import time
from functools import partial, wraps
from typing import Any, Callable

import anyio

logger = logging.getLogger(__name__)


class ToolExecutionPool:
    """Run blocking tool functions without blocking the MCP event loop."""

    def __init__(
        self,
        *,
        max_concurrency: int,
        max_pending: int,
        queue_timeout_seconds: float,
    ) -> None:
        if max_concurrency < 1:
            raise ValueError("max_concurrency must be at least 1")
        if max_pending < max_concurrency:
            raise ValueError("max_pending must be at least max_concurrency")
        if queue_timeout_seconds <= 0:
            raise ValueError("queue_timeout_seconds must be positive")

        self.max_concurrency = max_concurrency
        self.max_pending = max_pending
        self.queue_timeout_seconds = queue_timeout_seconds
        self._slots = asyncio.Semaphore(max_concurrency)
        # AnyIO otherwise uses its process-wide thread limiter (40 by
        # default). Each blocking worker can establish a per-thread requests
        # connection pool in the YouTrack clients, so letting the executor
        # rotate through dozens of threads can exhaust the container's FD
        # limit even though the MCP pool admits only a few tools at once.
        self._thread_limiter = anyio.CapacityLimiter(max_concurrency)
        self._state_lock = asyncio.Lock()
        self._pending = 0
        self._active = 0

    @property
    def pending(self) -> int:
        return self._pending

    @property
    def active(self) -> int:
        return self._active

    @property
    def ready(self) -> bool:
        return self._pending < self.max_pending

    def snapshot(self) -> dict[str, int | bool]:
        return {
            "active": self._active,
            "pending": self._pending,
            "maxConcurrency": self.max_concurrency,
            "maxPending": self.max_pending,
            "ready": self.ready,
        }

    @staticmethod
    def _error(code: str, message: str) -> str:
        return json.dumps(
            {"status": "error", "code": code, "error": message},
            ensure_ascii=False,
        )

    async def run(
        self,
        tool_name: str,
        func: Callable[..., Any],
        *args: Any,
        **kwargs: Any,
    ) -> Any:
        async with self._state_lock:
            if self._pending >= self.max_pending:
                logger.warning(
                    "Rejected tool '%s': execution pool is full (%d pending)",
                    tool_name,
                    self._pending,
                )
                return self._error(
                    "server_busy",
                    "Tool execution capacity is temporarily exhausted",
                )
            self._pending += 1

        admitted_at = time.monotonic()
        acquired = False
        try:
            try:
                await asyncio.wait_for(
                    self._slots.acquire(), timeout=self.queue_timeout_seconds
                )
                acquired = True
            except TimeoutError:
                logger.warning(
                    "Rejected tool '%s': queue wait exceeded %.1fs",
                    tool_name,
                    self.queue_timeout_seconds,
                )
                return self._error(
                    "server_busy",
                    "Tool execution queue wait timed out",
                )

            async with self._state_lock:
                self._active += 1

            queue_seconds = time.monotonic() - admitted_at
            started_at = time.monotonic()
            try:
                result = await anyio.to_thread.run_sync(
                    partial(func, *args, **kwargs),
                    abandon_on_cancel=False,
                    limiter=self._thread_limiter,
                )
            finally:
                duration_seconds = time.monotonic() - started_at
                logger.info(
                    "Tool '%s' completed: queue=%.3fs duration=%.3fs",
                    tool_name,
                    queue_seconds,
                    duration_seconds,
                )
                async with self._state_lock:
                    self._active -= 1
            return result
        finally:
            if acquired:
                self._slots.release()
            async with self._state_lock:
                self._pending -= 1


def make_async_tool(
    func: Callable[..., Any], pool: ToolExecutionPool
) -> Callable[..., Any]:
    """Expose a synchronous tool as an async FastMCP-compatible callable."""

    @wraps(func)
    async def async_tool(*args: Any, **kwargs: Any) -> Any:
        return await pool.run(func.__name__, func, *args, **kwargs)

    async_tool.__signature__ = inspect.signature(func)  # type: ignore[attr-defined]
    return async_tool
