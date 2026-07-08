"""
api/main.py — FastAPI backend for Agentic-CTI.

Wraps the existing LangGraph pipeline (agent.run_pipeline) behind a clean
HTTP API. This decouples the Streamlit UI from the pipeline logic and exposes
programmatic access for CI/CD, integrations, and the Elasticsearch log path.

Endpoints
---------
GET  /api/health        — liveness probe
GET  /api/stats         — Qdrant collection stats
POST /api/analyze       — run text-report pipeline, return full result JSON
POST /api/query-logs    — run ES log-query pipeline, return YARA-L rule

Usage (local dev):
    uvicorn api.main:app --reload --port 8000

Usage (Docker):
    Built and started by docker-compose as the `fastapi-backend` service.
"""

from __future__ import annotations

import logging
import os
import sys
from pathlib import Path
from typing import Any, Optional

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

# ---------------------------------------------------------------------------
# Path setup — allow importing from repo root when run directly
# ---------------------------------------------------------------------------
_REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_REPO_ROOT))

from dotenv import load_dotenv
load_dotenv(_REPO_ROOT / ".env")

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# FastAPI application
# ---------------------------------------------------------------------------

app = FastAPI(
    title="Agentic-CTI API",
    description=(
        "Programmatic access to the Agentic-CTI LangGraph threat intelligence pipeline. "
        "Accepts raw threat reports or Elasticsearch log queries and returns extracted "
        "threat intel, RAG context, and a validated YARA-L 2.0 detection rule."
    ),
    version="1.0.0",
    docs_url="/api/docs",
    redoc_url="/api/redoc",
    openapi_url="/api/openapi.json",
)

# Allow all origins in development — restrict in production via env variable
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ---------------------------------------------------------------------------
# Request / Response models
# ---------------------------------------------------------------------------

class AnalyzeRequest(BaseModel):
    """Request body for the /api/analyze endpoint."""
    text: str

    model_config = {"json_schema_extra": {
        "example": {
            "text": (
                "APT41 has been observed deploying KEYPLUG malware targeting "
                "telecommunications companies via spear-phishing. C2: 203.0.113.45, "
                "backup.evil-apt41.com. TTPs: T1566.001, T1059.001."
            )
        }
    }}


class LogQueryRequest(BaseModel):
    """Request body for the /api/query-logs endpoint."""
    query: str
    index: str = "agentic-cti-logs"
    size: int = 100

    model_config = {"json_schema_extra": {
        "example": {
            "query": "event_type:NETWORK_CONNECTION AND dest_ip:185.220.101.47",
            "index": "agentic-cti-logs",
            "size": 50,
        }
    }}


class HealthResponse(BaseModel):
    status: str
    version: str = "1.0.0"


# ---------------------------------------------------------------------------
# Helper: serialize pipeline state for JSON response
# ---------------------------------------------------------------------------

def _serialize_state(state: dict[str, Any]) -> dict[str, Any]:
    """
    Convert a ThreatIntelState dict to a JSON-serialisable payload.

    Pydantic models (ThreatIntelReport, IOCBundle) are dumped to dicts;
    None values are preserved.
    """
    out: dict[str, Any] = {}
    for k, v in state.items():
        if hasattr(v, "model_dump"):
            out[k] = v.model_dump()
        else:
            out[k] = v
    return out


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@app.get("/api/health", response_model=HealthResponse, tags=["Health"])
async def health_check() -> HealthResponse:
    """Liveness probe — returns 200 OK when the service is up."""
    return HealthResponse(status="ok")


@app.get("/api/stats", tags=["Metadata"])
async def get_stats() -> dict[str, Any]:
    """
    Return Qdrant collection statistics.

    Provides the number of stored threat reports and basic collection metadata.
    """
    try:
        import vector_store as vs
        info = vs.get_collection_info()
        return {"qdrant": info}
    except Exception as exc:
        logger.exception("Failed to fetch Qdrant stats")
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@app.post("/api/analyze", tags=["Pipeline"])
async def analyze_text(request: AnalyzeRequest) -> dict[str, Any]:
    """
    Run the full Agentic-CTI LangGraph pipeline on a raw threat report.

    Stages:
      1. Prompt injection guard (Node 0)
      2. LLM threat intel extraction (Node 1)
      3. Qdrant RAG contextualization (Node 2)
      4. YARA-L 2.0 generation with retry loop (Nodes 3–4)
      5. Finalize (Node 5)

    Returns the full pipeline state as JSON, including extracted intel,
    RAG context, the validated YARA-L rule, and any error messages.
    """
    if not request.text.strip():
        raise HTTPException(status_code=422, detail="Text cannot be empty.")

    try:
        from agent import run_pipeline
        state = run_pipeline(request.text)
        return _serialize_state(state)
    except Exception as exc:
        logger.exception("Pipeline error in /api/analyze")
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@app.post("/api/query-logs", tags=["Pipeline"])
async def query_logs(request: LogQueryRequest) -> dict[str, Any]:
    """
    Run the Elasticsearch log-query pipeline path.

    Accepts a Lucene/ES query string, retrieves matching log events from
    Elasticsearch, synthesizes threat intelligence from those events using the
    LLM, then feeds the result through the existing RAG → YARA-L pipeline.

    Returns the same structure as /api/analyze.
    """
    if not request.query.strip():
        raise HTTPException(status_code=422, detail="Query cannot be empty.")

    try:
        from agent import run_pipeline_from_logs
        state = run_pipeline_from_logs(
            query=request.query,
            index=request.index,
            size=request.size,
        )
        return _serialize_state(state)
    except Exception as exc:
        logger.exception("Pipeline error in /api/query-logs")
        raise HTTPException(status_code=500, detail=str(exc)) from exc


# ---------------------------------------------------------------------------
# Dev server entrypoint
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "api.main:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
        log_level="info",
    )
