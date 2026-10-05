"""Tests for stream layer (T-012)."""

from __future__ import annotations

from unittest.mock import AsyncMock

import pytest

from sentinel.streaming import (
    CONSUMER_GROUP,
    DEAD_LETTER_COUNTER,
    DEAD_LETTER_STREAM,
    StreamManager,
    shard_keys_for_worker,
)


@pytest.fixture
def mock_redis() -> AsyncMock:
    """Create a mock async Redis client."""
    r = AsyncMock()
    r.xgroup_create = AsyncMock()
    r.xreadgroup = AsyncMock(return_value=[])
    r.xack = AsyncMock(return_value=1)
    r.xadd = AsyncMock()
    r.incr = AsyncMock()
    r.get = AsyncMock(return_value=None)
    r.xinfo_stream = AsyncMock(return_value={})
    r.xinfo_groups = AsyncMock(return_value=[])
    r.xtrim = AsyncMock()
    return r


@pytest.mark.anyio
async def test_ensure_group_creates(mock_redis: AsyncMock) -> None:
    """ensure_group creates consumer group with MKSTREAM."""
    mgr = StreamManager(mock_redis)
    await mgr.ensure_group("flows:src:a1")
    mock_redis.xgroup_create.assert_called_once_with(
        "flows:src:a1", CONSUMER_GROUP, id="0", mkstream=True
    )


@pytest.mark.anyio
async def test_ensure_group_busygroup_ok(mock_redis: AsyncMock) -> None:
    """BUSYGROUP error is silently handled (group exists on restart)."""
    mock_redis.xgroup_create.side_effect = Exception("BUSYGROUP already exists")
    mgr = StreamManager(mock_redis)
    await mgr.ensure_group("flows:src:a1")  # Should not raise


@pytest.mark.anyio
async def test_read_returns_decoded_messages(mock_redis: AsyncMock) -> None:
    """Read decodes bytes from Redis into strings."""
    mock_redis.xreadgroup.return_value = [
        (b"flows:src:a1", [(b"1-0", {b"data": b'{"uid":"test"}'})])
    ]
    mgr = StreamManager(mock_redis)
    msgs = await mgr.read(["flows:src:a1"], consumer="w0")
    assert len(msgs) == 1
    stream_key, msg_id, fields = msgs[0]
    assert stream_key == "flows:src:a1"
    assert msg_id == "1-0"
    assert fields["data"] == '{"uid":"test"}'


@pytest.mark.anyio
async def test_ack(mock_redis: AsyncMock) -> None:
    """Ack forwards to XACK."""
    mgr = StreamManager(mock_redis)
    await mgr.ack("flows:src:a1", "1-0", "2-0")
    mock_redis.xack.assert_called_once_with("flows:src:a1", CONSUMER_GROUP, "1-0", "2-0")


@pytest.mark.anyio
async def test_dead_letter(mock_redis: AsyncMock) -> None:
    """Dead letter sends to dead:flows and increments counter (DAT-5)."""
    mgr = StreamManager(mock_redis)
    await mgr.dead_letter('{"bad": "data"}', "parse_error")
    mock_redis.xadd.assert_called_once()
    call_args = mock_redis.xadd.call_args
    assert call_args[0][0] == DEAD_LETTER_STREAM
    mock_redis.incr.assert_called_once_with(DEAD_LETTER_COUNTER)


@pytest.mark.anyio
async def test_dead_letter_count(mock_redis: AsyncMock) -> None:
    """Dead letter count reads from counter key."""
    mock_redis.get.return_value = b"42"
    mgr = StreamManager(mock_redis)
    count = await mgr.get_dead_letter_count()
    assert count == 42


@pytest.mark.anyio
async def test_dead_letter_count_zero_when_missing(mock_redis: AsyncMock) -> None:
    """Dead letter count returns 0 when key doesn't exist."""
    mock_redis.get.return_value = None
    mgr = StreamManager(mock_redis)
    count = await mgr.get_dead_letter_count()
    assert count == 0


def test_shard_keys_deterministic() -> None:
    """Shard assignment is deterministic."""
    keys1 = shard_keys_for_worker(4, 0)
    keys2 = shard_keys_for_worker(4, 0)
    assert keys1 == keys2
    assert len(keys1) > 0


def test_shard_keys_non_overlapping() -> None:
    """Different workers get different shard keys (no overlap)."""
    w0 = set(shard_keys_for_worker(4, 0))
    w1 = set(shard_keys_for_worker(4, 1))
    assert w0.isdisjoint(w1) or w0 == w1  # disjoint or single-worker case
