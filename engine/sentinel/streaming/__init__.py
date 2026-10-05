"""SENTINEL-X Stream Layer (T-012).

Bounded Redis streams, consumer groups, shard assignment, dead-letter stream.
Architecture.md section 7.

FR-03: Stream-based pipeline.
ARC-5: Shard by src_ip (primary), dst_ip (secondary).
DAT-5: Dead-letter for malformed input.
PY-4: Async-only Redis calls.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

import structlog

if TYPE_CHECKING:
    from redis.asyncio import Redis as AsyncRedis

logger = structlog.get_logger()

# Stream configuration
DEFAULT_MAX_STREAM_LEN = 100_000  # Approximate trim (back-pressure)
DEAD_LETTER_STREAM = "dead:flows"
DEAD_LETTER_COUNTER = "dead:flows:count"
CONSUMER_GROUP = "sentinel"


class StreamManager:
    """Manages Redis streams: consumer groups, reading, dead-letter.

    Each worker claims a set of shard keys. Workers in the same consumer
    group get non-overlapping messages (each flow processed once).
    """

    def __init__(
        self,
        redis: AsyncRedis,
        group: str = CONSUMER_GROUP,
        maxlen: int = DEFAULT_MAX_STREAM_LEN,
    ) -> None:
        self._redis = redis
        self._group = group
        self._maxlen = maxlen

    async def ensure_group(self, stream_key: str) -> None:
        """Create consumer group if it doesn't exist.

        Uses MKSTREAM to create the stream if absent.
        """
        try:
            await self._redis.xgroup_create(
                stream_key,
                self._group,
                id="0",
                mkstream=True,
            )
            logger.info("group_created", stream=stream_key, group=self._group)
        except Exception as exc:
            # BUSYGROUP = group already exists (expected on restart)
            if "BUSYGROUP" in str(exc):
                logger.debug("group_exists", stream=stream_key, group=self._group)
            else:
                raise

    async def read(
        self,
        stream_keys: list[str],
        consumer: str,
        count: int = 100,
        block_ms: int = 1000,
    ) -> list[tuple[str, str, dict[str, str]]]:
        """Read from multiple streams via consumer group.

        Returns list of (stream_key, message_id, fields) tuples.
        Uses XREADGROUP with blocking.
        """
        streams = dict.fromkeys(stream_keys, ">")
        result = await self._redis.xreadgroup(
            self._group,
            consumer,
            streams,  # type: ignore[arg-type]
            count=count,
            block=block_ms,
        )

        if not result:
            return []

        messages: list[tuple[str, str, dict[str, str]]] = []
        for item in result:
            stream_key_raw = item[0]
            entries = item[1]
            sk = (
                stream_key_raw.decode()
                if isinstance(stream_key_raw, bytes)
                else str(stream_key_raw)
            )
            for entry in entries:  # type: ignore[union-attr]
                msg_id_raw = entry[0]
                fields_raw = entry[1]
                mid = msg_id_raw.decode() if isinstance(msg_id_raw, bytes) else str(msg_id_raw)
                decoded_fields: dict[str, str] = {}
                if hasattr(fields_raw, "items"):
                    for k, v in fields_raw.items():
                        dk = k.decode() if isinstance(k, bytes) else str(k)
                        dv = v.decode() if isinstance(v, bytes) else str(v)
                        decoded_fields[dk] = dv
                messages.append((sk, mid, decoded_fields))

        return messages

    async def ack(self, stream_key: str, *message_ids: str) -> int:
        """Acknowledge processed messages."""
        result: int = await self._redis.xack(stream_key, self._group, *message_ids)
        return result

    async def dead_letter(self, data: str, reason: str) -> None:
        """Send malformed input to dead-letter stream (DAT-5).

        Never stops the pipeline on bad input.
        """
        await self._redis.xadd(
            DEAD_LETTER_STREAM,
            {"data": data, "reason": reason},
            maxlen=self._maxlen,
            approximate=True,
        )
        await self._redis.incr(DEAD_LETTER_COUNTER)
        logger.warning("dead_letter", reason=reason, data_preview=data[:100])

    async def get_dead_letter_count(self) -> int:
        """Get count of dead-lettered messages."""
        val = await self._redis.get(DEAD_LETTER_COUNTER)
        return int(val) if val else 0

    async def stream_info(self, stream_key: str) -> dict[str, Any]:
        """Get stream info (length, groups, etc.)."""
        try:
            info = await self._redis.xinfo_stream(stream_key)
            return dict(info) if info else {}
        except Exception:
            return {}

    async def consumer_lag(self, stream_key: str) -> int:
        """Get approximate consumer lag (pending messages).

        Lag feeds the shedding controller (architecture.md section 7).
        """
        try:
            groups = await self._redis.xinfo_groups(stream_key)
            if groups:
                return sum(int(g.get("lag", 0) or g.get("pending", 0)) for g in groups)
        except Exception:
            logger.debug("consumer_lag_unavailable", stream=stream_key)
        return 0

    async def trim(self, stream_key: str) -> None:
        """Trim stream to maxlen (back-pressure)."""
        await self._redis.xtrim(stream_key, maxlen=self._maxlen, approximate=True)


def shard_keys_for_worker(
    total_shards: int,
    worker_id: int,
    stream_prefix: str = "flows:src",
    total_workers: int | None = None,
) -> list[str]:
    """Compute which shard keys a worker owns.

    Deterministic assignment: worker_id owns shards where
    shard_index % total_workers == worker_id.
    Each worker owns all state for its sources (no locks per ARC-5).
    """
    # Shard keys are hex prefixes of the MD5 hash
    # With 256 possible first-byte values, we use the first hex char (16 shards)
    all_shards = [f"{stream_prefix}:{i:01x}" for i in range(total_shards)]
    workers = total_workers if total_workers is not None else total_shards
    if workers < 1 or worker_id < 0 or worker_id >= workers:
        raise ValueError("worker_id must be in [0, total_workers)")
    return [s for i, s in enumerate(all_shards) if i % workers == worker_id]
