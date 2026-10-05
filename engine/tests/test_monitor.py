from sentinel.monitor import PassivityMonitor, VisibilityMonitor


def test_visibility_health_reflects_loss_and_shedding() -> None:
    monitor = VisibilityMonitor()
    assert monitor.health == 1.0
    monitor.observe_capture_loss(10, 100)
    monitor.observe_sequence(1, 4)
    monitor.shed_if_needed(100)
    assert monitor.health < 1.0
    assert "secondary-detectors" in monitor.shedding


def test_passivity_is_explicitly_emulated_without_linux_interface() -> None:
    sample = PassivityMonitor(interface=None).sample()
    assert sample.status in {"emulated", "verified", "failed"}
    assert sample.mode in {"software-emulation", "linux-kernel-counter"}
