from pathlib import Path

from sentinel.features.baseline import load_model, predict, save_model, train_centroids


def test_metadata_baseline_trains_predicts_and_rejects_tampering(tmp_path: Path) -> None:
    benign = {
        "proto": "tcp",
        "dst_port": 443,
        "duration": 1,
        "orig_bytes": 500,
        "resp_bytes": 2000,
        "orig_pkts": 5,
        "resp_pkts": 8,
    }
    scan = {
        "proto": "tcp",
        "dst_port": 22,
        "conn_state": "S0",
        "duration": 0,
        "orig_bytes": 64,
        "resp_bytes": 0,
        "orig_pkts": 1,
        "resp_pkts": 0,
    }
    model = train_centroids([(benign, "benign"), (scan, "port_scan")])
    path = tmp_path / "model.json"
    save_model(model, path)
    loaded = load_model(path)
    assert predict(loaded, scan)["label"] == "port_scan"
    path.write_text(path.read_text().replace('"port_scan"', '"tampered"'), encoding="utf-8")
    try:
        load_model(path)
    except ValueError as error:
        assert "integrity" in str(error)
    else:
        raise AssertionError("tampered model was accepted")
