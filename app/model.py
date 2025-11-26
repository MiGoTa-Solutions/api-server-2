from __future__ import annotations

from functools import lru_cache
from pathlib import Path

import joblib
import sklearn.compose._column_transformer as column_transformer

MODEL_FILENAME = "phishing_detector.pkl"
MODEL_PATH = Path(__file__).resolve().parent.parent / MODEL_FILENAME


def _ensure_remainder_cols() -> None:
    if hasattr(column_transformer, "_RemainderColsList"):
        return

    class _RemainderColsList(list):
        pass

    column_transformer._RemainderColsList = _RemainderColsList  # type: ignore[attr-defined]


@lru_cache(maxsize=1)
def get_model():
    _ensure_remainder_cols()
    if not MODEL_PATH.exists():
        raise FileNotFoundError(f"Model file not found at {MODEL_PATH}")
    return joblib.load(MODEL_PATH)
