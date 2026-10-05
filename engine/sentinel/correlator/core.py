"""Phase 1 signal correlation and tamper-evident alert construction."""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from uuid import uuid4

from sentinel.common.schemas import Alert, AlertExplanation, Signal, severity_from_score


class Correlator:
    def __init__(self) -> None:
        self._seen: set[tuple[str, str, tuple[float, float]]] = set()
        self._previous_hash = "0" * 64

    def correlate(self, signals: list[Signal], visibility_health: float = 1.0) -> list[Alert]:
        alerts: list[Alert] = []
        for signal in signals:
            key = (signal.entity, signal.threat_class, signal.window)
            if key in self._seen:
                continue
            self._seen.add(key)
            evidence = {"signal": signal.evidence, "window": signal.window}
            canonical = json.dumps(evidence, sort_keys=True, separators=(",", ":"))
            evidence_hash = hashlib.sha256(f"{canonical}{self._previous_hash}".encode()).hexdigest()
            alert = Alert(
                alert_id=str(uuid4()),
                incident_id=f"incident-{signal.entity}",
                timestamp=datetime.now(UTC),
                source_ip=signal.entity,
                destination_ip=str(signal.evidence.get("target", signal.entity)),
                destination_port=None,
                threat_class=signal.threat_class,
                attack_technique=signal.attack_technique,
                kill_chain_stage="reconnaissance" if "SCAN" in signal.threat_class else "impact",
                severity=severity_from_score(signal.score * visibility_health),
                confidence=round(signal.score * visibility_health, 4),
                visibility_health=visibility_health,
                evidence=evidence,
                explanation=[
                    AlertExplanation(
                        signal=item.name,
                        contribution=item.value,
                        details=f"{item.name.replace('_', ' ')} contributed to the score",
                    )
                    for item in signal.contributions
                ],
                detector_version=signal.detector,
                evidence_hash=evidence_hash,
                prev_hash=self._previous_hash,
            )
            self._previous_hash = evidence_hash
            alerts.append(alert)
        return alerts
