from __future__ import annotations

from unittest.mock import AsyncMock

import pytest

from sentinel.common import FlowRecord
from sentinel.detector import DetectionWorker
from sentinel.features import CUSUM, CountMinSketch, HyperLogLog
from sentinel.features.windows import WindowAggregator
from sentinel.streaming import StreamManager


def flow(ts: float, uid: str = "x") -> FlowRecord:
    return FlowRecord(
        uid=uid,
        seq=int(ts),
        ts_start=ts,
        src_ip="1.1.1.1",
        src_port=1,
        dst_ip="2.2.2.2",
        dst_port=443,
        proto="tcp",
    )


def test_sketches_are_bounded_and_mergeable() -> None:
    left, right = HyperLogLog(6), HyperLogLog(6)
    left.update(["a", "b", "a"])
    right.update(["b", "c"])
    assert left.merge(right).count() == 3
    cms = CountMinSketch(32, 3)
    cms.add("dst", 4)
    assert cms.estimate("dst") >= 4


def test_cusum_detects_positive_shift() -> None:
    detector = CUSUM(drift=0, threshold=3)
    assert not detector.update(1, 1)
    assert detector.update(4, 1)


def test_event_time_lateness_rolls_up() -> None:
    agg = WindowAggregator(allowed_lateness=2)
    agg.add(flow(10))
    agg.add(flow(15))
    assert agg.add(flow(10.5))
    assert agg.snapshot("1.1.1.1", 10).late_events == 1


@pytest.mark.anyio
async def test_worker_isolates_bad_message() -> None:
    manager = AsyncMock(spec=StreamManager)
    manager.read.return_value = [
        ("flows:src:0", "1-0", {"data": flow(1).model_dump_json()}),
        ("flows:src:0", "2-0", {"data": "not-json"}),
    ]
    manager.ensure_group.return_value = None
    worker = DetectionWorker(manager, total_shards=1)
    await worker.run_once()
    assert worker.stats.processed == 1
    assert worker.stats.dead_lettered == 1
    assert manager.ack.await_count == 2
