"""Event-time, bounded window aggregation.

Flows first enter one-second buckets.  Rollups are materialised by merging
those buckets for 10 seconds, 5 minutes, 1 hour, and 24 hours.  A watermark
(``max_event_time - allowed_lateness``) closes old buckets.  An event arriving
behind the watermark is not discarded: it is folded into the current bucket
and marked late, making data loss visible while keeping state bounded.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from math import floor
from typing import TYPE_CHECKING

from sentinel.features.sketches import CountMinSketch, HyperLogLog

if TYPE_CHECKING:
    from sentinel.common.schemas import FlowRecord

ROLLUP_WINDOWS = (10, 300, 3_600, 86_400)


@dataclass
class WindowAggregate:
    start: float
    end: float
    count: int = 0
    bytes: int = 0
    late_events: int = 0
    unique_ports: HyperLogLog = field(default_factory=HyperLogLog)
    unique_hosts: HyperLogLog = field(default_factory=HyperLogLog)
    destinations: CountMinSketch = field(default_factory=CountMinSketch)

    def add(self, flow: FlowRecord, late: bool = False) -> None:
        self.count += 1
        self.bytes += max(0, flow.orig_bytes or 0) + max(0, flow.resp_bytes or 0)
        self.unique_ports.add(flow.dst_port)
        self.unique_hosts.add(flow.dst_ip)
        self.destinations.add(flow.dst_ip)
        self.late_events += int(late)

    def merge(self, other: WindowAggregate) -> WindowAggregate:
        return WindowAggregate(
            min(self.start, other.start),
            max(self.end, other.end),
            self.count + other.count,
            self.bytes + other.bytes,
            self.late_events + other.late_events,
            self.unique_ports.merge(other.unique_ports),
            self.unique_hosts.merge(other.unique_hosts),
            self.destinations.merge(other.destinations),
        )

    @property
    def estimated_unique_ports(self) -> int:
        return self.unique_ports.count()

    @property
    def estimated_unique_hosts(self) -> int:
        return self.unique_hosts.count()


class WindowAggregator:
    """Bounded per-entity event-time aggregator."""

    def __init__(self, allowed_lateness: float = 5.0, bucket_seconds: int = 1) -> None:
        if allowed_lateness < 0 or bucket_seconds < 1:
            raise ValueError("allowed_lateness must be non-negative and bucket_seconds positive")
        self.allowed_lateness = allowed_lateness
        self.bucket_seconds = bucket_seconds
        self.max_event_time: float | None = None
        self._buckets: dict[str, dict[float, WindowAggregate]] = {}
        self._closed: set[tuple[str, float]] = set()

    @property
    def watermark(self) -> float | None:
        if self.max_event_time is None:
            return None
        return self.max_event_time - self.allowed_lateness

    def add(self, flow: FlowRecord) -> bool:
        """Add a flow; return ``True`` when it was beyond allowed lateness."""
        self.max_event_time = max(self.max_event_time or flow.ts_start, flow.ts_start)
        bucket = floor(flow.ts_start / self.bucket_seconds) * self.bucket_seconds
        entity_buckets = self._buckets.setdefault(flow.src_ip, {})
        late = (flow.src_ip, bucket) in self._closed or (
            self.watermark is not None and flow.ts_start < self.watermark
        )
        if late:
            bucket = (
                floor((self.max_event_time or flow.ts_start) / self.bucket_seconds)
                * self.bucket_seconds
            )
        aggregate = entity_buckets.setdefault(
            bucket, WindowAggregate(bucket, bucket + self.bucket_seconds)
        )
        aggregate.add(flow, late)
        self._close_old_buckets()
        return late

    def _close_old_buckets(self) -> None:
        if self.watermark is None:
            return
        for entity, buckets in self._buckets.items():
            for bucket in buckets:
                if bucket + self.bucket_seconds <= self.watermark:
                    self._closed.add((entity, bucket))

    def snapshot(
        self, entity: str, window_seconds: int, end: float | None = None
    ) -> WindowAggregate:
        """Return a rollup ending at ``end`` (or the current watermark)."""
        if window_seconds not in ROLLUP_WINDOWS:
            raise ValueError(f"window_seconds must be one of {ROLLUP_WINDOWS}")
        entity_buckets = self._buckets.get(entity, {})
        if end is None:
            end = (self.max_event_time or 0) + self.bucket_seconds
        start = end - window_seconds
        result = WindowAggregate(start, end)
        for bucket, aggregate in entity_buckets.items():
            if bucket < end and bucket + self.bucket_seconds > start:
                result = result.merge(aggregate) if result.count else aggregate
        return result

    def entities(self) -> tuple[str, ...]:
        return tuple(self._buckets)
