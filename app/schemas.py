from __future__ import annotations

from typing import Dict, List, Literal

from pydantic import BaseModel, Field, field_validator


class URLScanRequest(BaseModel):
    url: str = Field(..., description="URL to scan")

    @field_validator("url")
    @classmethod
    def _trim_and_validate(cls, value: str) -> str:
        if not value or not value.strip():
            raise ValueError("URL must not be empty")
        return value.strip()


class URLScanResponse(BaseModel):
    url: str
    normalized_url: str
    verdict: Literal["benign", "malicious", "unknown"]
    confidence: int = Field(ge=0, le=100)
    method: Literal["ml"]
    reasons: List[str]
    class_probabilities: Dict[str, float]


class BatchScanRequest(BaseModel):
    urls: List[str]

    @field_validator("urls")
    @classmethod
    def _validate_urls(cls, value: List[str]) -> List[str]:
        cleaned = [item.strip() for item in value if item and item.strip()]
        if not cleaned:
            raise ValueError("At least one URL is required")
        if len(cleaned) > 100:
            raise ValueError("Batch size cannot exceed 100 URLs")
        return cleaned


class BatchScanResponseItem(BaseModel):
    url: str
    verdict: Literal["benign", "malicious", "unknown"]
    confidence: int
    method: Literal["ml"]


class BatchScanResponse(BaseModel):
    results: List[BatchScanResponseItem]
    total: int
