"""Persistence ports and offline-safe adapters for the API.

The demo deliberately has no database requirement.  When ``DATABASE_URL`` is
configured the API can use the small PostgreSQL adapter; otherwise all writes
remain in a bounded in-memory repository.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any, Protocol

from sentinel.common import Alert, FlowRecord

if TYPE_CHECKING:
    from collections.abc import Sequence


@dataclass(frozen=True)
class IncidentRecord:
    incident_id: str
    first_seen: datetime
    last_seen: datetime
    source_ip: str
    status: str = "open"


@dataclass(frozen=True)
class SampleRecord:
    sample_id: str
    captured_at: datetime
    payload: dict[str, Any]


class Repository(Protocol):
    def save_sample(self, flow: FlowRecord) -> None: ...

    def save_alert(self, alert: Alert) -> None: ...

    def list_alerts(self, limit: int) -> list[Alert]: ...

    def get_alert(self, alert_id: str) -> Alert | None: ...

    def list_samples(self, limit: int) -> list[SampleRecord]: ...

    def list_incidents(self, limit: int) -> list[IncidentRecord]: ...

    def clear(self) -> None: ...


class InMemoryRepository:
    """Bounded repository used by local demos and tests."""

    def __init__(self, max_items: int = 1000) -> None:
        self.max_items = max_items
        self.samples: list[SampleRecord] = []
        self.alerts: list[Alert] = []
        self.incidents: dict[str, IncidentRecord] = {}

    def save_sample(self, flow: FlowRecord) -> None:
        self.samples.append(
            SampleRecord(
                sample_id=flow.uid,
                captured_at=datetime.fromtimestamp(flow.ts_start, tz=UTC),
                payload=flow.model_dump(mode="json"),
            )
        )
        del self.samples[: -self.max_items]

    def save_alert(self, alert: Alert) -> None:
        self.alerts.append(alert)
        del self.alerts[: -self.max_items]
        if alert.incident_id:
            existing = self.incidents.get(alert.incident_id)
            timestamp = alert.timestamp.astimezone(UTC)
            self.incidents[alert.incident_id] = IncidentRecord(
                incident_id=alert.incident_id,
                first_seen=existing.first_seen if existing else timestamp,
                last_seen=max(existing.last_seen, timestamp) if existing else timestamp,
                source_ip=alert.source_ip,
            )

    def list_alerts(self, limit: int) -> list[Alert]:
        return list(reversed(self.alerts[-limit:]))

    def get_alert(self, alert_id: str) -> Alert | None:
        return next((alert for alert in self.alerts if alert.alert_id == alert_id), None)

    def list_samples(self, limit: int) -> list[SampleRecord]:
        return list(reversed(self.samples[-limit:]))

    def list_incidents(self, limit: int) -> list[IncidentRecord]:
        return list(reversed(list(self.incidents.values())[-limit:]))

    def clear(self) -> None:
        self.samples.clear()
        self.alerts.clear()
        self.incidents.clear()


class PostgresRepository:
    """Tiny synchronous adapter; psycopg is optional and imported on demand."""

    def __init__(self, url: str) -> None:
        try:
            import psycopg  # type: ignore[import-not-found]
        except ImportError as exc:
            raise RuntimeError("psycopg is required when DATABASE_URL is configured") from exc
        self._connection = psycopg.connect(url, autocommit=True)

    def save_sample(self, flow: FlowRecord) -> None:
        with self._connection.cursor() as cursor:
            cursor.execute(
                "INSERT INTO samples (sample_id, captured_at, payload) VALUES (%s, %s, %s) "
                "ON CONFLICT (sample_id) DO NOTHING",
                (
                    flow.uid,
                    datetime.fromtimestamp(flow.ts_start, tz=UTC),
                    flow.model_dump(mode="json"),
                ),
            )

    def save_alert(self, alert: Alert) -> None:
        with self._connection.cursor() as cursor:
            if alert.incident_id:
                cursor.execute(
                    "INSERT INTO incidents (incident_id, source_ip, first_seen, last_seen) "
                    "VALUES (%s, %s, %s, %s) ON CONFLICT (incident_id) DO UPDATE "
                    "SET last_seen = GREATEST(incidents.last_seen, EXCLUDED.last_seen)",
                    (alert.incident_id, alert.source_ip, alert.timestamp, alert.timestamp),
                )
            cursor.execute(
                "INSERT INTO alerts (alert_id, incident_id, timestamp, source_ip, destination_ip, "
                "destination_port, threat_class, severity, confidence, payload) "
                "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s) "
                "ON CONFLICT (alert_id) DO NOTHING",
                (
                    alert.alert_id,
                    alert.incident_id,
                    alert.timestamp,
                    alert.source_ip,
                    alert.destination_ip,
                    alert.destination_port,
                    alert.threat_class,
                    alert.severity,
                    alert.confidence,
                    alert.model_dump(mode="json"),
                ),
            )

    def list_alerts(self, limit: int) -> list[Alert]:
        with self._connection.cursor() as cursor:
            cursor.execute("SELECT payload FROM alerts ORDER BY timestamp DESC LIMIT %s", (limit,))
            return [Alert.model_validate(row[0]) for row in cursor.fetchall()]

    def get_alert(self, alert_id: str) -> Alert | None:
        with self._connection.cursor() as cursor:
            cursor.execute("SELECT payload FROM alerts WHERE alert_id = %s", (alert_id,))
            row = cursor.fetchone()
            return Alert.model_validate(row[0]) if row else None

    def list_samples(self, limit: int) -> list[SampleRecord]:
        with self._connection.cursor() as cursor:
            cursor.execute(
                "SELECT sample_id, captured_at, payload FROM samples "
                "ORDER BY captured_at DESC LIMIT %s",
                (limit,),
            )
            return [
                SampleRecord(sample_id=row[0], captured_at=row[1], payload=row[2])
                for row in cursor.fetchall()
            ]

    def list_incidents(self, limit: int) -> list[IncidentRecord]:
        with self._connection.cursor() as cursor:
            cursor.execute(
                "SELECT incident_id, first_seen, last_seen, source_ip, status "
                "FROM incidents ORDER BY last_seen DESC LIMIT %s",
                (limit,),
            )
            return [
                IncidentRecord(
                    incident_id=row[0],
                    first_seen=row[1],
                    last_seen=row[2],
                    source_ip=str(row[3]),
                    status=row[4],
                )
                for row in cursor.fetchall()
            ]

    def clear(self) -> None:
        with self._connection.cursor() as cursor:
            cursor.execute("TRUNCATE alerts, incidents, samples")


def create_repository() -> Repository:
    """Select PostgreSQL only when explicitly configured, otherwise stay offline."""
    url = os.getenv("DATABASE_URL")
    if url:
        try:
            return PostgresRepository(url)
        except (OSError, RuntimeError):
            pass
    return InMemoryRepository()


def records(values: Sequence[IncidentRecord | SampleRecord]) -> list[dict[str, Any]]:
    """Serialize repository records for API responses."""
    return [
        {
            key: value.isoformat() if isinstance(value, datetime) else value
            for key, value in item.__dict__.items()
        }
        for item in values
    ]
