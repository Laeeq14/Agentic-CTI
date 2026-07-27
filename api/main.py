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

from fastapi import FastAPI, HTTPException, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
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
        "threat intel, RAG context, and validated detection rules in three formats: "
        "YARA-L 2.0 (Google SecOps), Sigma (SIEM-agnostic), and KQL (Microsoft Sentinel). "
        "Also provides MITRE ATT\u0026CK Navigator layer export."
    ),
    version="2.0.0",
    docs_url="/api/docs",
    redoc_url="/api/redoc",
    openapi_url="/api/openapi.json",
)

# ---------------------------------------------------------------------------
# CORS — controlled by CORS_ALLOWED_ORIGINS env variable
# ---------------------------------------------------------------------------
# Development default: CORS_ALLOWED_ORIGINS is unset → allow_origins=["*"]
# Production:          CORS_ALLOWED_ORIGINS="https://app.example.com,https://dash.example.com"
#                      → origin list is comma-separated.
# ---------------------------------------------------------------------------
_cors_origins_raw = os.getenv("CORS_ALLOWED_ORIGINS", "*")
_cors_origins: list[str] = (
    [o.strip() for o in _cors_origins_raw.split(",") if o.strip()]
    if _cors_origins_raw != "*"
    else ["*"]
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=_cors_origins,
    allow_credentials=_cors_origins != ["*"],  # credentials only with explicit origin whitelist
    allow_methods=["*"],
    allow_headers=["*"],
)
logger.info("CORS origins configured: %s", _cors_origins)


# ---------------------------------------------------------------------------
# Optional API key middleware
# ---------------------------------------------------------------------------
# When API_KEY env variable is set, all endpoints except GET /api/health
# require the request to carry the header:  X-API-Key: <value>
#
# When API_KEY is not set (default for local dev), the middleware is a
# transparent pass-through — no keys required, behaviour unchanged.
# ---------------------------------------------------------------------------

_API_KEY: str | None = os.getenv("API_KEY") or None
# Endpoints that are always public regardless of API key config
_PUBLIC_PATHS: frozenset[str] = frozenset({"/api/health"})


@app.middleware("http")
async def api_key_middleware(request: Request, call_next):
    """
    Optional API key enforcement middleware.

    When API_KEY is set:
      - Requests to paths NOT in _PUBLIC_PATHS must supply the correct
        'X-API-Key' header.  Wrong / missing key → HTTP 401.
    When API_KEY is unset:
      - All requests pass through unconditionally (dev mode).
    """
    if _API_KEY is None:
        # Dev mode — no auth
        return await call_next(request)

    if request.url.path in _PUBLIC_PATHS:
        # Health probe is always public
        return await call_next(request)

    provided_key = request.headers.get("X-API-Key", "")
    if provided_key != _API_KEY:
        logger.warning(
            "Rejected request to %s — invalid or missing X-API-Key (source: %s)",
            request.url.path,
            request.client.host if request.client else "unknown",
        )
        return JSONResponse(
            status_code=status.HTTP_401_UNAUTHORIZED,
            content={
                "detail": "Missing or invalid API key. "
                          "Supply the correct key in the X-API-Key request header.",
                "hint": "Contact your administrator for an API key.",
            },
        )

    return await call_next(request)


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
    version: str = "2.0.0"


class NavigatorLayerRequest(BaseModel):
    """
    Request body for the /api/navigator-layer endpoint.

    Two modes:
      1. Direct TTP list: provide 'ttps' directly (fast, no LLM call)
      2. Pipeline mode:   provide 'reports' (list of report texts) to run
         extraction and then build the layer from extracted TTPs.
    """
    # Mode 1: direct TTP list
    ttps: Optional[list[str]] = None

    # Mode 2: raw report texts (will run extraction pipeline)
    reports: Optional[list[str]] = None

    # Layer metadata
    name: str = "Agentic-CTI Threat Landscape"
    description: str = "Automatically generated ATT&CK layer from Agentic-CTI pipeline."

    # Safety limit for pipeline mode to prevent runaway API costs
    max_reports: int = 10

    model_config = {"json_schema_extra": {
        "example": {
            "ttps": ["T1059.001", "T1071.001", "T1041", "T1078", "T1566.001"],
            "name": "APT41 Detection Layer",
        }
    }}


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
      4. Sigma rule generation with validation (Node 3a)
      5. Sentinel KQL query generation (Node 3b)
      6. YARA-L 2.0 generation with retry loop (Nodes 3c–4)
      7. Finalize (Node 5)

    Returns the full pipeline state as JSON, including extracted intel,
    RAG context, the validated YARA-L rule, Sigma rule, KQL query,
    and any error messages.
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


@app.get("/api/formats", tags=["Metadata"])
async def get_formats() -> dict[str, Any]:
    """
    Describe the three detection rule formats generated by the pipeline.

    Informational endpoint for clients that need to know what fields to
    expect in /api/analyze and /api/query-logs responses.
    """
    return {
        "formats": [
            {
                "id": "yaral",
                "name": "YARA-L 2.0",
                "platform": "Google Security Operations (SecOps / Chronicle)",
                "response_field": "final_yaral_rule",
                "file_extension": ".yaral",
                "description": (
                    "Primary detection format. Validated by a deterministic structural "
                    "checker (validator.py) with up to 3 auto-correction retries. "
                    "Targets UDM (Unified Data Model) event schema."
                ),
            },
            {
                "id": "sigma",
                "name": "Sigma",
                "platform": "SIEM-agnostic (converts to Splunk, QRadar, Elastic, etc.)",
                "response_field": "sigma_rule",
                "file_extension": ".yml",
                "description": (
                    "Vendor-neutral detection rule format. Logsource is parameterized "
                    "by TTP using a TTP\u2192logsource map (src/ttp_logsource_map.py). "
                    "Validated by sigma_validator.py with 1 correction pass."
                ),
            },
            {
                "id": "kql",
                "name": "KQL",
                "platform": "Microsoft Sentinel",
                "response_field": "kql_query",
                "file_extension": ".kql",
                "description": (
                    "Kusto Query Language detection query targeting SecurityEvent or "
                    "CommonSecurityLog depending on dominant TTPs. "
                    "Uses has_any() with dynamic IOC arrays for maintainability."
                ),
            },
        ]
    }


@app.post("/api/navigator-layer", tags=["Navigator"])
async def generate_navigator_layer(request: NavigatorLayerRequest) -> dict[str, Any]:
    """
    Generate a MITRE ATT&CK Navigator layer JSON.

    Two modes:
      1. **Direct TTP list** (fast): provide 'ttps' in the request body.
         No LLM calls made. Returns the layer immediately.

      2. **Pipeline extraction** (slow): provide 'reports' (list of raw threat
         report texts). Runs the extraction pipeline on each report (up to
         max_reports, default 10) and builds the layer from extracted TTPs.
         Note: each report incurs a Groq API call.

    Returns a Navigator v4.9 layer dict that can be loaded directly at
    https://mitre-attack.github.io/attack-navigator/
    """
    from src.navigator import build_navigator_layer, ttps_to_navigator_layer

    try:
        # Mode 1: direct TTP list
        if request.ttps:
            layer = build_navigator_layer(
                ttps=request.ttps,
                name=request.name,
                description=request.description,
            )
            return {
                "layer": layer,
                "mode": "direct_ttps",
                "ttp_count": len(set(request.ttps)),
                "total_observations": len(request.ttps),
            }

        # Mode 2: extract TTPs from reports via pipeline
        if request.reports:
            from agent import run_pipeline
            reports_to_process = request.reports[:request.max_reports]

            if len(request.reports) > request.max_reports:
                logger.warning(
                    "/api/navigator-layer: truncating %d reports to max_reports=%d to limit API costs",
                    len(request.reports), request.max_reports,
                )

            report_data: list[dict] = []
            extraction_errors: list[str] = []

            for i, report_text in enumerate(reports_to_process):
                if not report_text.strip():
                    continue
                try:
                    state = run_pipeline(report_text)
                    extracted = state.get("extracted_report")
                    if extracted:
                        ttps_list = extracted.mitre_ttps or []
                        actor = extracted.threat_actor or f"Unknown-{i+1}"
                        report_data.append({"threat_actor": actor, "ttps": ttps_list})
                    else:
                        extraction_errors.append(
                            f"Report {i+1}: extraction failed — {state.get('extraction_error', 'unknown error')}"
                        )
                except Exception as exc:
                    extraction_errors.append(f"Report {i+1}: pipeline error — {exc}")
                    logger.exception("Navigator pipeline error on report %d", i + 1)

            if not report_data:
                raise HTTPException(
                    status_code=422,
                    detail=f"No TTPs could be extracted from any of the {len(reports_to_process)} reports. "
                           f"Errors: {extraction_errors[:3]}",
                )

            layer = ttps_to_navigator_layer(
                reports=report_data,
                name=request.name,
                description=request.description,
            )
            return {
                "layer": layer,
                "mode": "pipeline_extraction",
                "reports_processed": len(report_data),
                "reports_requested": len(request.reports),
                "reports_truncated": len(request.reports) > request.max_reports,
                "extraction_errors": extraction_errors,
                "ttp_count": len({t["techniqueID"] for t in layer["techniques"]}),
                "total_observations": sum(t["score"] for t in layer["techniques"]),
            }

        raise HTTPException(
            status_code=422,
            detail="Provide either 'ttps' (direct list) or 'reports' (raw text list) in the request body.",
        )

    except HTTPException:
        raise
    except Exception as exc:
        logger.exception("Navigator layer generation failed")
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
