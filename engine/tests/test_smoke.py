"""Smoke test to verify tooling works."""


def test_import() -> None:
    """Verify the sentinel package is importable."""
    import sentinel

    assert sentinel is not None
