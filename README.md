# URL Risk Classification API

This project packages the phishing detector pipeline from `phishing_detector.pkl` behind a FastAPI service that can be deployed to Render. It mirrors the structure of the existing `api-server` project so you can publish it to GitHub and wire it up to Render with minimal effort.

## Features

- REST API to classify a single URL (`POST /api/scan`)
- Batch endpoint for up to 100 URLs (`POST /api/batch-scan`)
- Health and metadata endpoints (`GET /`, `GET /health`)
- Simple CLI helper (`python file.py`) for quick local checks
- Compatible with Render via `render.yaml`

## Getting Started

```bash
python -m venv .venv
.venv\Scripts\activate  # Windows
pip install -r requirements.txt
uvicorn main:app --host 0.0.0.0 --port 8000
```

Once running locally you can scan a URL:

```bash
curl -X POST http://localhost:8000/api/scan -H "Content-Type: application/json" -d '{"url": "https://example.com"}'
```

## Render Deployment

1. Push this folder to a new GitHub repository.
2. Create a new **Web Service** on Render and connect the repository.
3. Render will use `render.yaml` to install dependencies and start the server.

## Tests

```bash
pytest
```

## Environment

- Python 3.11+
- FastAPI 0.115
- scikit-learn 1.6.1 (matches the version used to train the pipeline)
