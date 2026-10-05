from datetime import UTC, datetime
from typing import Any

from sentinel.common import Alert, AlertExplanation, Severity
from sentinel.storage import InMemoryRepository, create_repository, records


def _alert(alert_id: str = "a-1") -> Alert:
    return Alert(
        alert_id=alert_id,
        incident_id="incident-1",
        timestamp=datetime.now(UTC),
        source_ip="192.0.2.1",
        destination_ip="198.51.100.1",
        threat_class="PORT_SCAN",
        attack_technique="T1046",
        severity=Severity.HIGH,
        confidence=0.95,
        visibility_health=1.0,
        evidence={"ports": [22, 23]},
        explanation=[AlertExplanation(signal="ports", contribution=0.95)],
        detector_version="scan@1",
        evidence_hash="a" * 64,
        prev_hash="0" * 64,
    )


def test_in_memory_repository_persists_alert_and_incident() -> None:
    repository = InMemoryRepository()
    repository.save_alert(_alert())

    stored = repository.get_alert("a-1")
    assert stored is not None
    assert stored.alert_id == "a-1"
    incidents = repository.list_incidents(10)
    assert incidents[0].incident_id == "incident-1"
    assert records(incidents)[0]["status"] == "open"


def test_repository_factory_is_offline_by_default(monkeypatch: Any) -> None:
    monkeypatch.delenv("DATABASE_URL", raising=False)
    assert isinstance(create_repository(), InMemoryRepository)
