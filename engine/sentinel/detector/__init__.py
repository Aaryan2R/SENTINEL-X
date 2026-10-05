"""Detector protocol and registry exports."""

from sentinel.detector.core import DetectorEngine
from sentinel.detector.worker import DetectionWorker, WorkerStats, run_detection_worker

__all__ = ["DetectionWorker", "DetectorEngine", "WorkerStats", "run_detection_worker"]
