"""Small signed-by-hash JSON baseline model for metadata-only experiments."""

from __future__ import annotations

import hashlib
import json
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pathlib import Path
    from typing import Any

from sentinel.features.flow import FEATURE_NAMES, standardised_distance, vector


def train_centroids(rows: list[tuple[dict[str, Any], str]]) -> dict[str, Any]:
    if not rows:
        raise ValueError("training data is empty")
    labels = sorted({label for _, label in rows})
    classes: dict[str, Any] = {}
    for label in labels:
        vectors = [vector(flow) for flow, row_label in rows if row_label == label]
        means = [
            sum(values[index] for values in vectors) / len(vectors)
            for index in range(len(FEATURE_NAMES))
        ]
        scales = []
        for index, mean in enumerate(means):
            variance = sum((values[index] - mean) ** 2 for values in vectors) / len(vectors)
            scales.append(max(1e-6, variance**0.5))
        classes[label] = {"count": len(vectors), "mean": means, "scale": scales}
    model = {
        "schema_version": "1.0",
        "model_type": "metadata_centroid",
        "feature_names": list(FEATURE_NAMES),
        "classes": classes,
    }
    model["model_sha256"] = _digest(model)
    return model


def predict(model: dict[str, Any], flow: dict[str, Any]) -> dict[str, Any]:
    values = vector(flow)
    distances = {
        label: standardised_distance(values, item["mean"], item["scale"])
        for label, item in model["classes"].items()
    }
    label, distance = min(distances.items(), key=lambda item: item[1])
    confidence = 1.0 / (1.0 + distance)
    return {"label": label, "confidence": round(confidence, 6), "distance": round(distance, 6)}


def save_model(model: dict[str, Any], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(model, indent=2) + "\n", encoding="utf-8")


def load_model(path: Path) -> dict[str, Any]:
    model: dict[str, Any] = json.loads(path.read_text(encoding="utf-8"))
    expected = model.pop("model_sha256", None)
    if expected != _digest(model):
        raise ValueError(f"model integrity check failed: {path}")
    model["model_sha256"] = expected
    return model


def _digest(model: dict[str, Any]) -> str:
    canonical = json.dumps(model, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode()).hexdigest()
