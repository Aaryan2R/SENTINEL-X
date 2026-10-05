"""SENTINEL-X Stream Publisher.

Publishes FlowRecords to Redis streams (src_ip and dst_ip shards).
ARC-5: dual-stream sharding.
ARC-6: abstraction prep — publisher interface separate from Redis impl.
PY-4: async Redis calls.
"""

from __future__ import annotations

from typing import Protocol

import structlog
from redis.asyncio import Redis as AsyncRedis  # noqa: TC002

from sentinel.common.schemas import FlowRecord  # noqa: TC001
from sentinel.normaliser import (
    flow_to_stream_entry,
    stream_key_for_dst,
    stream_key_for_src,
)

logger = structlog.get_logger()

# Bounded streams: approximate max length (ARC-5, back-pressure)
DEFAULT_MAX_STREAM_LEN = 100_000


class StreamPublisher(Protocol):
    """Bus interface abstraction (ARC-6). Redis can be swapped later."""

    async def publish(self, flow: FlowRecord) -> None:
        """Publish a flow to both src and dst streams."""
        ...


class RedisStreamPublisher:
    """Publishes FlowRecords to Redis streams.

    PY-4: fully async.
    ARC-5: publishes to both src_ip and dst_ip sharded streams.
    """

    def __init__(
        self,
        redis: AsyncRedis,
        maxlen: int = DEFAULT_MAX_STREAM_LEN,
    ) -> None:
        self._redis = redis
        self._maxlen = maxlen

    async def publish(self, flow: FlowRecord) -> None:
        """Publish a flow to both src and dst streams (ARC-5)."""
        entry = flow_to_stream_entry(flow)

        src_key = stream_key_for_src(flow)
        dst_key = stream_key_for_dst(flow)

        # XADD with approximate maxlen for bounded streams
        await self._redis.xadd(
            src_key,
            entry,  # type: ignore[arg-type]
            maxlen=self._maxlen,
            approximate=True,
        )
        await self._redis.xadd(
            dst_key,
            entry,  # type: ignore[arg-type]
            maxlen=self._maxlen,
            approximate=True,
        )

        logger.debug(
            "published_flow",
            uid=flow.uid,
            src_key=src_key,
            dst_key=dst_key,
            seq=flow.seq,
        )

    async def publish_batch(self, flows: list[FlowRecord]) -> int:
        """Publish multiple flows. Returns count of successfully published."""
        published = 0
        for flow in flows:
            try:
                await self.publish(flow)
                published += 1
            except Exception:
                logger.exception("publish_failed", uid=flow.uid)
        return published
