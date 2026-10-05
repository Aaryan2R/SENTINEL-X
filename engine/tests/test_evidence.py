from datetime import UTC, datetime

from sentinel.common import Alert, AlertExplanation, Severity
from sentinel.correlator import verify_alert_chain


def _alert(alert_id: str, evidence_hash: str, prev_hash: str) -> Alert:
    return Alert(
        alert_id=alert_id,
        timestamp=datetime.now(UTC),
        source_ip="192.0.2.1",
        destination_ip="198.51.100.1",
        threat_class="PORT_SCAN",
        attack_technique="T1046",
        severity=Severity.HIGH,
        confidence=0.9,
        visibility_health=1.0,
        evidence={"signal": {"unique_ports": 20}, "window": [1.0, 2.0]},
        explanation=[AlertExplanation(signal="ports", contribution=0.9)],
        detector_version="scan@1",
        evidence_hash=evidence_hash,
        prev_hash=prev_hash,
    )


def test_correlator_chain_verifies_and_detects_tampering() -> None:
    from sentinel.common import CorrelationGroup, Signal, SignalContribution
    from sentinel.correlator import Correlator

    signal = Signal(
        entity="192.0.2.1",
        threat_class="PORT_SCAN",
        score=0.9,
        group=CorrelationGroup.SCAN,
        evidence={"unique_ports": 20, "target": "198.51.100.1"},
        contributions=[SignalContribution(name="ports", value=0.9)],
        window=(1.0, 2.0),
        detector="scan@1",
        attack_technique="T1046",
    )
    alert = Correlator().correlate([signal])[0]
    assert verify_alert_chain([alert])["valid"] is True
    tampered = alert.model_copy(
        update={"evidence": {"signal": {"unique_ports": 999}, "window": [1.0, 2.0]}}
    )
    assert verify_alert_chain([tampered])["valid"] is False
