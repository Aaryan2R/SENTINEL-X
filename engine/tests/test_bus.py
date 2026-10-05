"""Tests for bus interface abstraction (T-013, ARC-6)."""

from __future__ import annotations

from sentinel.bus import BusAdmin, BusConsumer, BusPublisher
from sentinel.normaliser.publisher import RedisStreamPublisher
from sentinel.streaming import StreamManager


def test_redis_publisher_satisfies_bus_publisher() -> None:
    """RedisStreamPublisher implements BusPublisher protocol."""
    assert issubclass(RedisStreamPublisher, BusPublisher)


def test_stream_manager_satisfies_bus_consumer() -> None:
    """StreamManager implements BusConsumer protocol."""
    assert issubclass(StreamManager, BusConsumer)


def test_stream_manager_satisfies_bus_admin() -> None:
    """StreamManager implements BusAdmin protocol."""
    assert issubclass(StreamManager, BusAdmin)
