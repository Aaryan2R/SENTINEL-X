from sentinel.common import FlowRecord
from sentinel.correlator import Correlator
from sentinel.detector import DetectorEngine


def _flow(index: int, *, port: int, state: str = "SF", query: str | None = None) -> FlowRecord:
    return FlowRecord(
        uid=f"phase1-{index}",
        seq=index,
        ts_start=100 + index / 10,
        src_ip="192.168.1.100",
        src_port=40000 + index,
        dst_ip="10.0.0.1",
        dst_port=port,
        proto="tcp",
        conn_state=state,
        history="S",
        dns_query=query,
    )


def test_scan_signal_is_deduplicated_into_hashed_alert() -> None:
    detector = DetectorEngine()
    correlator = Correlator()
    alerts = []
    for index in range(25):
        alerts.extend(correlator.correlate(detector.evaluate(_flow(index, port=1000 + index))))
    scan_alerts = [alert for alert in alerts if alert.threat_class == "PORT_SCAN"]
    assert len(scan_alerts) == 1
    assert len(scan_alerts[0].evidence_hash) == 64
    assert scan_alerts[0].evidence["signal"]["unique_ports"] >= 20


def test_dga_rule_requires_suspicious_domain() -> None:
    detector = DetectorEngine()
    signals = detector.evaluate(_flow(1, port=53, query="a91k2m7q4z8x.example"))
    assert any(signal.threat_class == "DGA" for signal in signals)


def test_benign_flow_has_no_signal() -> None:
    detector = DetectorEngine()
    assert detector.evaluate(_flow(1, port=443, query="api.example.com")) == []
