"""SENTINEL-X Bus Interface Abstraction (T-013, ARC-6).

Protocols defining the bus interface so Redis can be swapped later.
Implementations: RedisStreamPublisher (publisher.py), StreamManager (streaming/).
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Protocol, runtime_checkable

if TYPE_CHECKING:
    from sentinel.common.schemas import FlowRecord


@runtime_checkable
class BusPublisher(Protocol):
    """Publish flows to the bus (ARC-6).

    Current impl: RedisStreamPublisher.
    """

    async def publish(self, flow: FlowRecord) -> None:
        """Publish a single flow."""
        ...

    async def publish_batch(self, flows: list[FlowRecord]) -> int:
        """Publish multiple flows. Returns count of successful publishes."""
        ...


@runtime_checkable
class BusConsumer(Protocol):
    """Consume flows from the bus (ARC-6).

    Current impl: StreamManager.
    """

    async def ensure_group(self, stream_key: str) -> None:
        """Ensure consumer group exists."""
        ...

    async def read(
        self,
        stream_keys: list[str],
        consumer: str,
        count: int = 100,
        block_ms: int = 1000,
    ) -> list[tuple[str, str, dict[str, str]]]:
        """Read messages from streams."""
        ...

    async def ack(self, stream_key: str, *message_ids: str) -> int:
        """Acknowledge processed messages."""
        ...

    async def dead_letter(self, data: str, reason: str) -> None:
        """Send malformed input to dead-letter."""
        ...


@runtime_checkable
class BusAdmin(Protocol):
    """Administrative bus operations (ARC-6)."""

    async def stream_info(self, stream_key: str) -> dict[str, Any]:
        """Get stream metadata."""
        ...

    async def consumer_lag(self, stream_key: str) -> int:
        """Get consumer lag for shedding decisions."""
        ...

    async def trim(self, stream_key: str) -> None:
        """Trim stream for back-pressure."""
        ...
