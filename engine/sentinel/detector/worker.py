"""Async detection worker runtime (T-018).

Workers own deterministic stream shards, read bounded batches, and isolate
decode/detection failures to one entity.  A successfully handled (including
dead-lettered) message is acknowledged exactly once.
"""

from __future__ import annotations

import asyncio
import json
from dataclasses import dataclass

import structlog

from sentinel.common.schemas import FlowRecord
from sentinel.detector.core import DetectorEngine
from sentinel.streaming import StreamManager, shard_keys_for_worker

logger = structlog.get_logger()


@dataclass
class WorkerStats:
    read: int = 0
    processed: int = 0
    failed: int = 0
    dead_lettered: int = 0
    signals: int = 0


class DetectionWorker:
    """One async worker; create one instance per process."""

    def __init__(
        self,
        streams: StreamManager,
        detector: DetectorEngine | None = None,
        *,
        worker_id: int = 0,
        total_workers: int = 1,
        total_shards: int = 16,
        batch_size: int = 100,
        block_ms: int = 1_000,
    ) -> None:
        if worker_id < 0 or total_workers < 1 or worker_id >= total_workers:
            raise ValueError("worker_id must be in [0, total_workers)")
        self.streams = streams
        self.detector = detector or DetectorEngine()
        self.worker_id = worker_id
        self.consumer = f"detector-{worker_id}"
        self.stream_keys = shard_keys_for_worker(
            total_shards, worker_id, total_workers=total_workers
        )
        self.batch_size, self.block_ms = batch_size, block_ms
        self.stats = WorkerStats()

    async def setup(self) -> None:
        for stream in self.stream_keys:
            await self.streams.ensure_group(stream)

    async def run_once(self) -> int:
        messages = await self.streams.read(
            self.stream_keys, self.consumer, self.batch_size, self.block_ms
        )
        self.stats.read += len(messages)
        for stream, message_id, fields in messages:
            await self._process_one(stream, message_id, fields)
        return len(messages)

    async def _process_one(self, stream: str, message_id: str, fields: dict[str, str]) -> None:
        raw = fields.get("data", "")
        try:
            flow = FlowRecord.model_validate_json(raw)
        except (ValueError, TypeError, json.JSONDecodeError) as exc:
            self.stats.failed += 1
            self.stats.dead_lettered += 1
            await self.streams.dead_letter(raw, f"flow_decode:{type(exc).__name__}")
            await self.streams.ack(stream, message_id)
            return
        try:
            signals = self.detector.evaluate(flow)
            self.stats.signals += len(signals)
            self.stats.processed += 1
        except Exception as exc:  # isolate one entity/flow from the batch
            self.stats.failed += 1
            logger.exception("detection_failed", entity=flow.src_ip, error=str(exc))
        finally:
            await self.streams.ack(stream, message_id)

    async def run(self, stop: asyncio.Event | None = None) -> None:
        """Run until ``stop`` is set; cancellation propagates cleanly."""
        await self.setup()
        stop = stop or asyncio.Event()
        while not stop.is_set():
            await self.run_once()


async def run_detection_worker(
    streams: StreamManager,
    *,
    worker_id: int = 0,
    total_workers: int = 1,
    stop: asyncio.Event | None = None,
) -> None:
    """Small process-entry-compatible helper."""
    await DetectionWorker(streams, worker_id=worker_id, total_workers=total_workers).run(stop)
