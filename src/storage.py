"""MongoDB persistence for analysis history and searchable event evidence.

The UI remains usable when MongoDB is unavailable; in that case it reports the
connection status and keeps the current analysis in Streamlit session state.
"""
from __future__ import annotations
import os
from pathlib import Path
try:
    from dotenv import load_dotenv
    load_dotenv(Path(__file__).resolve().parents[1] / ".env")
except ImportError:
    pass
from datetime import datetime, timezone
from typing import Any

try:
    from pymongo import MongoClient, DESCENDING, TEXT
    from pymongo.errors import PyMongoError
except ImportError:  # optional during source-only development
    MongoClient = None
    DESCENDING = -1
    TEXT = "text"
    PyMongoError = Exception

MONGODB_URI = os.getenv("MONGODB_URI", "mongodb://localhost:27017")
MONGODB_DATABASE = os.getenv("MONGODB_DATABASE", "ransomtrace_ai")
_client = None


def _db():
    global _client
    if MongoClient is None:
        raise RuntimeError("pymongo is not installed. Run: pip install -r requirements.txt")
    if _client is None:
        _client = MongoClient(MONGODB_URI, serverSelectionTimeoutMS=1200, connectTimeoutMS=1200)
    _client.admin.command("ping")
    db = _client[MONGODB_DATABASE]
    db.analysis_runs.create_index([("created_at", DESCENDING)])
    db.analysis_runs.create_index("signature", unique=True)
    db.event_evidence.create_index([("run_id", 1), ("timestamp", 1)])
    db.event_evidence.create_index([("event_id", 1)])
    db.event_evidence.create_index([("host", 1), ("event_type", 1)])
    return db


def connection_status() -> dict[str, Any]:
    try:
        db = _db()
        return {"connected": True, "database": MONGODB_DATABASE, "uri": MONGODB_URI, "runs": db.analysis_runs.count_documents({})}
    except Exception as exc:
        return {"connected": False, "database": MONGODB_DATABASE, "uri": MONGODB_URI, "error": str(exc)}


def _plain(value):
    if hasattr(value, "isoformat"):
        return value.isoformat()
    if hasattr(value, "item"):
        try:
            return value.item()
        except Exception:
            pass
    return value


def save_analysis(signature: str, run_doc: dict, events: list[dict]) -> tuple[str | None, bool, str | None]:
    """Save a run once per signature. Returns (id, was_created, error)."""
    try:
        db = _db()
        existing = db.analysis_runs.find_one({"signature": signature})
        if existing:
            return str(existing["_id"]), False, None
        doc = dict(run_doc)
        doc.update({"signature": signature, "created_at": datetime.now(timezone.utc).isoformat()})
        result = db.analysis_runs.insert_one(doc)
        run_id = str(result.inserted_id)
        docs = []
        for row in events:
            item = {k: _plain(v) for k, v in row.items()}
            item["run_id"] = run_id
            item["scenario"] = doc.get("scenario", "Uploaded logs")
            docs.append(item)
        if docs:
            # Batch inserts are far more efficient than inserting rows individually.
            for start in range(0, len(docs), 1000):
                db.event_evidence.insert_many(docs[start:start + 1000], ordered=False)
        return run_id, True, None
    except Exception as exc:
        return None, False, str(exc)


def list_runs(limit: int = 100) -> list[dict]:
    db = _db()
    out = []
    for doc in db.analysis_runs.find({}, {"signature": 0}).sort("created_at", DESCENDING).limit(limit):
        doc["id"] = str(doc.pop("_id"))
        out.append(doc)
    return out


def search_events(query: str = "", run_id: str | None = None, limit: int = 250) -> list[dict]:
    db = _db()
    filt: dict = {}
    if run_id:
        filt["run_id"] = run_id
    if query.strip():
        q = query.strip()
        filt["$or"] = [
            {"event_id": {"$regex": q, "$options": "i"}},
            {"source_entity": {"$regex": q, "$options": "i"}},
            {"target_entity": {"$regex": q, "$options": "i"}},
            {"host": {"$regex": q, "$options": "i"}},
            {"event_type": {"$regex": q, "$options": "i"}},
            {"details": {"$regex": q, "$options": "i"}},
            {"reasons": {"$regex": q, "$options": "i"}},
        ]
    out = []
    for doc in db.event_evidence.find(filt).sort("timestamp", DESCENDING).limit(limit):
        doc["id"] = str(doc.pop("_id"))
        out.append(doc)
    return out


def get_run(run_id: str) -> dict | None:
    from bson import ObjectId
    db = _db()
    try:
        doc = db.analysis_runs.find_one({"_id": ObjectId(run_id)})
    except Exception:
        return None
    if not doc:
        return None
    doc["id"] = str(doc.pop("_id"))
    return doc
