"""Local FastAPI service for RansomTrace AI investigation history.
Run with: uvicorn backend.api:app --reload --host 127.0.0.1 --port 8000
"""
from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from src.storage import connection_status, list_runs, search_events, get_run

app = FastAPI(title="RansomTrace AI Local API", version="1.0.0", description="Local API for saved investigations and evidence search.")
app.add_middleware(CORSMiddleware, allow_origins=["http://localhost:8501", "http://127.0.0.1:8501"], allow_credentials=True, allow_methods=["GET"], allow_headers=["*"])

@app.get("/health")
def health():
    status = connection_status()
    return {"service": "RansomTrace AI API", **status}

@app.get("/api/runs")
def runs(limit: int = Query(default=50, ge=1, le=500)):
    if not connection_status()["connected"]:
        raise HTTPException(status_code=503, detail="MongoDB is unavailable. Start local MongoDB and retry.")
    return {"items": list_runs(limit=limit)}

@app.get("/api/runs/{run_id}")
def run_detail(run_id: str):
    if not connection_status()["connected"]:
        raise HTTPException(status_code=503, detail="MongoDB is unavailable.")
    result = get_run(run_id)
    if result is None:
        raise HTTPException(status_code=404, detail="Investigation not found.")
    return result

@app.get("/api/evidence/search")
def evidence_search(q: str = "", run_id: str | None = None, limit: int = Query(default=100, ge=1, le=1000)):
    if not connection_status()["connected"]:
        raise HTTPException(status_code=503, detail="MongoDB is unavailable.")
    return {"items": search_events(q, run_id=run_id, limit=limit)}
