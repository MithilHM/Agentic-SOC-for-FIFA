"""Regression test for the WebSocket Redis connection-pool leak.

Bug (fixed): the ``/api/ws/incidents`` handler creates a pubsub — which checks
a dedicated connection out of the redis pool — and, on disconnect, originally
only called ``unsubscribe()``. ``unsubscribe()`` leaves that connection checked
out forever; only ``aclose()`` returns it to the pool. After ~100 reconnects
the default pool (100) was exhausted and every API call 500'd. The fix added
``aclose()``, now living in the ``_close_pubsub`` helper the WS handler calls in
its ``finally`` block.

Why not drive the endpoint through ``TestClient``? Starlette's in-process
websocket disconnect cancels the handler coroutine cleanly, and the async
``pub.listen()`` generator's cancellation cleanup happens to return the
connection even without ``aclose()`` — so ``TestClient`` cannot reproduce the
leak that real (uvicorn) network disconnects cause. This test therefore drives
the handler's *actual cleanup code* (``server._close_pubsub``) directly, across
N subscribe→cleanup cycles, and asserts the pool does not grow unbounded. If
someone removes ``aclose()`` from ``_close_pubsub`` this fails (verified:
without it, 25 cycles leak 25 connections).

Requires a reachable Redis (present on the compose network); skipped otherwise.
"""
import asyncio
import os

import pytest

redis_sync = pytest.importorskip("redis")
pytest.importorskip("fastapi")

_REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379")


def _redis_reachable() -> bool:
    try:
        c = redis_sync.from_url(_REDIS_URL, socket_connect_timeout=2)
        c.ping()
        c.close()
        return True
    except Exception:
        return False


pytestmark = pytest.mark.skipif(not _redis_reachable(),
                                reason="Redis not reachable at REDIS_URL")


def _total_created(pool) -> int:
    avail = getattr(pool, "_available_connections", []) or []
    in_use = getattr(pool, "_in_use_connections", set()) or set()
    return len(avail) + len(in_use)


def test_ws_cleanup_does_not_leak_pool_connections():
    import redis.asyncio as aioredis
    from api import server

    N = 25

    async def _run():
        R = aioredis.from_url(_REDIS_URL)
        pool = R.connection_pool
        try:
            for _ in range(N):
                pub = R.pubsub()
                await pub.subscribe("incidents.live")
                # Exercise the exact cleanup the WS handler runs on disconnect.
                await server._close_pubsub(pub)
            return _total_created(pool)
        finally:
            await R.aclose()

    total = asyncio.run(_run())
    # Fixed: connections are returned and reused -> ~1. Buggy: grows to N.
    assert total <= 3, (
        f"pool grew to {total} connections over {N} reconnect cleanups; "
        f"WebSocket connection-pool leak regression"
    )
