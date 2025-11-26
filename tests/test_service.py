from __future__ import annotations

from app.service import classify_url, normalize_url


def test_normalize_url_adds_scheme():
    url = "example.com"
    normalized = normalize_url(url)
    assert normalized.startswith("https://")


def test_classify_url_returns_expected_keys():
    result = classify_url("https://example.com")
    assert result["verdict"] in {"benign", "malicious", "unknown"}
    assert 0 <= result["confidence"] <= 100
    assert set(result.keys()) == {
        "input_url",
        "normalized_url",
        "verdict",
        "confidence",
        "method",
        "reasons",
        "class_probabilities",
    }
