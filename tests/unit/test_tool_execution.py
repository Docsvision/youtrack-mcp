"""Tests for bounded, non-blocking MCP tool execution."""

import asyncio
import inspect
import json
import threading
import time

import pytest

from youtrack_mcp.tool_execution import ToolExecutionPool, make_async_tool


@pytest.mark.unit
def test_blocking_tool_does_not_block_event_loop():
    async def scenario():
        pool = ToolExecutionPool(
            max_concurrency=1,
            max_pending=2,
            queue_timeout_seconds=1,
        )

        def slow_tool() -> str:
            time.sleep(0.15)
            return "done"

        task = asyncio.create_task(pool.run("slow_tool", slow_tool))
        started = time.monotonic()
        await asyncio.sleep(0.02)
        event_loop_delay = time.monotonic() - started

        assert event_loop_delay < 0.1
        assert await task == "done"

    asyncio.run(scenario())


@pytest.mark.unit
def test_execution_pool_rejects_work_beyond_pending_limit():
    async def scenario():
        pool = ToolExecutionPool(
            max_concurrency=1,
            max_pending=2,
            queue_timeout_seconds=0.05,
        )
        release = threading.Event()
        started = threading.Event()

        def blocking_tool() -> str:
            started.set()
            release.wait(timeout=1)
            return "done"

        first = asyncio.create_task(pool.run("first", blocking_tool))
        while not started.is_set():
            await asyncio.sleep(0.005)
        second = asyncio.create_task(pool.run("second", lambda: "second"))
        await asyncio.sleep(0)

        rejected = json.loads(await pool.run("third", lambda: "third"))
        assert rejected["code"] == "server_busy"

        release.set()
        assert await first == "done"
        queued_result = await second
        if queued_result != "second":
            assert json.loads(queued_result)["code"] == "server_busy"

    asyncio.run(scenario())


@pytest.mark.unit
def test_execution_pool_limits_worker_threads_to_configured_concurrency(monkeypatch):
    observed_limiters = []

    async def fake_run_sync(func, *, abandon_on_cancel, limiter):
        observed_limiters.append(limiter)
        return func()

    monkeypatch.setattr(
        "youtrack_mcp.tool_execution.anyio.to_thread.run_sync", fake_run_sync
    )
    pool = ToolExecutionPool(
        max_concurrency=3,
        max_pending=3,
        queue_timeout_seconds=1,
    )

    assert asyncio.run(pool.run("tool", lambda: "done")) == "done"
    assert observed_limiters == [pool._thread_limiter]
    assert pool._thread_limiter.total_tokens == 3


@pytest.mark.unit
def test_async_tool_preserves_schema_signature():
    def original(issue_id: str, include_comments: bool = False) -> dict:
        return {"id": issue_id, "includeComments": include_comments}

    pool = ToolExecutionPool(
        max_concurrency=1,
        max_pending=1,
        queue_timeout_seconds=1,
    )
    wrapped = make_async_tool(original, pool)

    assert inspect.iscoroutinefunction(wrapped)
    assert inspect.signature(wrapped) == inspect.signature(original)
    assert asyncio.run(wrapped("DEMO-1")) == {
        "id": "DEMO-1",
        "includeComments": False,
    }
