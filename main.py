from __future__ import annotations

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware

from app.schemas import (
    BatchScanRequest,
    BatchScanResponse,
    BatchScanResponseItem,
    URLScanRequest,
    URLScanResponse,
)
from app.service import classify_url, get_model_summary

app = FastAPI(
    title="URL Risk Classification API",
    description="FastAPI wrapper around a scikit-learn phishing detector",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/")
def root():
    summary = get_model_summary()
    return {
        "status": "online",
        "service": app.title,
        "version": app.version,
        "estimator": summary.get("estimator"),
        "feature_count": summary.get("feature_count"),
        "endpoints": {
            "health": "GET /health",
            "scan": "POST /api/scan",
            "batch": "POST /api/batch-scan",
        },
    }


@app.get("/health")
def health():
    summary = get_model_summary()
    return {
        "status": "healthy",
        "model": summary,
    }


@app.post("/api/scan", response_model=URLScanResponse)
def scan_url(payload: URLScanRequest):
    try:
        result = classify_url(payload.url)
        return URLScanResponse(
            url=result["input_url"],
            normalized_url=result["normalized_url"],
            verdict=result["verdict"],
            confidence=result["confidence"],
            method=result["method"],
            reasons=result["reasons"],
            class_probabilities=result["class_probabilities"],
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:  # pragma: no cover - safety net
        raise HTTPException(status_code=500, detail="Failed to classify URL") from exc


@app.post("/api/batch-scan", response_model=BatchScanResponse)
def batch_scan(payload: BatchScanRequest):
    results = []
    for url in payload.urls:
        try:
            result = classify_url(url)
            results.append(
                BatchScanResponseItem(
                    url=result["input_url"],
                    verdict=result["verdict"],
                    confidence=result["confidence"],
                    method=result["method"],
                )
            )
        except ValueError:
            results.append(
                BatchScanResponseItem(
                    url=url,
                    verdict="unknown",
                    confidence=0,
                    method="ml",
                )
            )
        except Exception:
            results.append(
                BatchScanResponseItem(
                    url=url,
                    verdict="unknown",
                    confidence=0,
                    method="ml",
                )
            )
    return BatchScanResponse(results=results, total=len(results))


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=False)
