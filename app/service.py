from __future__ import annotations

import re
from typing import Dict, List
from urllib.parse import urlparse

import pandas as pd

from .features import extract_url_features
from .model import get_model

ALLOWED_SCHEMES = ("http", "https")
VERDICT_MAP = {0: "benign", 1: "malicious"}


def normalize_url(url: str) -> str:
    cleaned = (url or "").strip()
    if not cleaned:
        raise ValueError("URL must not be empty")
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", cleaned):
        cleaned = f"https://{cleaned}"
    parsed = urlparse(cleaned)
    if parsed.scheme.lower() not in ALLOWED_SCHEMES:
        raise ValueError("Only HTTP and HTTPS URLs are supported")
    return cleaned


def _build_probability_map(class_labels: List[int], proba_row: List[float]) -> Dict[str, float]:
    return {
        VERDICT_MAP.get(int(label), str(label)): float(probability)
        for label, probability in zip(class_labels, proba_row)
    }


def _build_reasons(features: Dict[str, float | int | str], verdict: str) -> List[str]:
    reasons: List[str] = []
    if features.get("IsDomainIP"):
        reasons.append("Domain resolves to a raw IP address")
    if features.get("HasObfuscation"):
        reasons.append("URL contains obfuscation characters")
    if features.get("HasExternalFormSubmit"):
        reasons.append("Forms submit to an external domain")
    if features.get("HasPasswordField"):
        reasons.append("Page contains password input fields")
    if features.get("NoOfExternalRef", 0) and features.get("NoOfSelfRef", 0) == 0:
        reasons.append("High number of external links")
    if features.get("HasSocialNet"):
        reasons.append("Page references social media platforms")
    if features.get("NoOfPopup", 0):
        reasons.append("Page contains popup elements")
    if features.get("Bank"):
        reasons.append("Bank-related keywords detected")
    if features.get("Pay"):
        reasons.append("Payment keywords detected")
    if features.get("Crypto"):
        reasons.append("Cryptocurrency keywords detected")

    if not reasons:
        if verdict == "malicious":
            reasons.append("Model flagged the URL as risky based on overall pattern")
        else:
            reasons.append("No high-risk heuristics detected")
    return reasons


def classify_url(url: str) -> Dict[str, object]:
    normalized = normalize_url(url)
    model = get_model()
    feature_order = getattr(model, "feature_names_in_", None)
    if feature_order is None:
        raise RuntimeError("Model is missing feature names metadata")

    features = extract_url_features(normalized)
    row = [features.get(name, 0) for name in feature_order]
    frame = pd.DataFrame([row], columns=feature_order)

    prediction = int(model.predict(frame)[0])
    probabilities = model.predict_proba(frame)[0]
    classes = getattr(model, "classes_", [0, 1])

    verdict = VERDICT_MAP.get(prediction, "unknown")
    confidence = int(round(max(probabilities) * 100))
    class_probabilities = _build_probability_map(list(classes), list(probabilities))
    reasons = _build_reasons(features, verdict)

    return {
        "input_url": url,
        "normalized_url": normalized,
        "verdict": verdict,
        "confidence": confidence,
        "method": "ml",
        "reasons": reasons,
        "class_probabilities": class_probabilities,
    }


def get_model_summary() -> Dict[str, object]:
    model = get_model()
    feature_order = getattr(model, "feature_names_in_", [])
    estimator = getattr(model, "steps", [])[-1][1] if getattr(model, "steps", []) else model
    estimator_name = estimator.__class__.__name__
    return {
        "estimator": estimator_name,
        "feature_count": len(feature_order),
        "features": list(feature_order),
    }
