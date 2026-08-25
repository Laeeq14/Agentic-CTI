"""
api/graphql_schema.py — Strawberry GraphQL schema for Agentic-CTI.

Mounts at /graphql alongside the existing REST API.  Clients can select
exactly the fields they need — e.g. only IOCs + YARA-L — without
receiving the entire pipeline payload, which is the canonical GraphQL
advantage over REST for a richly structured domain like threat intelligence.

Endpoints exposed:
  Query:
    health        → HealthResult           (liveness probe)
    indexStats    → IndexStats             (Elasticsearch index metadata)

  Mutation:
    analyzeReport → ThreatIntelResult      (text threat report → all rule formats)
    queryLogs     → ThreatIntelResult      (ES Lucene query → all rule formats)
    navigatorLayer→ NavigatorResult        (TTP list → ATT&CK Navigator layer JSON)

Usage (interactive Playground):
    http://localhost:8000/graphql

Example query — fetch only IOCs and the YARA-L rule:

    mutation {
      analyzeReport(text: "APT41 deployed KEYPLUG via T1566.001. C2: 203.0.113.45") {
        threatActor
        mitreTtps
        iocs { ips domains hashes }
        yaralRule
        pipelineError
      }
    }
"""

from __future__ import annotations

import logging
from typing import Optional

import strawberry
from strawberry.fastapi import GraphQLRouter

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# GraphQL output types
# ---------------------------------------------------------------------------

@strawberry.type
class HealthResult:
    status: str
    version: str


@strawberry.type
class IOCBundle:
    """Indicators of Compromise grouped by type."""
    ips: list[str]
    domains: list[str]
    hashes: list[str]


@strawberry.type
class TimeRange:
    min: str
    max: str


@strawberry.type
class IndexStats:
    """Basic statistics about the Elasticsearch log index."""
    index: str
    doc_count: int
    size_bytes: int
    time_range: Optional[TimeRange]


@strawberry.type
class ThreatIntelResult:
    """
    Full output from a single pipeline run.

    Clients may select any subset of fields.  Fields are None when the
    pipeline stage was not reached or encountered an error.
    """
    # Extracted threat intelligence
    threat_actor: Optional[str]
    malware_families: list[str]
    mitre_ttps: list[str]
    iocs: Optional[IOCBundle]

    # Detection rules
    yaral_rule: Optional[str]
    sigma_rule: Optional[str]
    kql_query: Optional[str]

    # Pipeline metadata
    retry_count: int
    pipeline_error: Optional[str]
    extraction_error: Optional[str]


@strawberry.type
class NavigatorResult:
    """MITRE ATT&CK Navigator layer output."""
    layer_json: str          # serialised Navigator v4.9 layer dict
    ttp_count: int
    total_observations: int
    mode: str                # "direct_ttps" or "pipeline_extraction"
    extraction_errors: list[str]


# ---------------------------------------------------------------------------
# Helpers — convert raw pipeline state dicts to GraphQL types
# ---------------------------------------------------------------------------

def _ioc_bundle_from_dict(ioc_dict: dict) -> IOCBundle:
    return IOCBundle(
        ips=ioc_dict.get("ips", []),
        domains=ioc_dict.get("domains", []),
        hashes=ioc_dict.get("hashes", []),
    )


def _threat_intel_result_from_state(state: dict) -> ThreatIntelResult:
    """
    Map a serialised ThreatIntelState dict to a ThreatIntelResult.

    The state is produced by agent._serialize_state() and already has
    Pydantic sub-models dumped to plain dicts.
    """
    extracted = state.get("extracted_report") or {}

    iocs_raw = extracted.get("iocs") or {}
    iocs = _ioc_bundle_from_dict(iocs_raw) if iocs_raw else None

    return ThreatIntelResult(
        threat_actor=extracted.get("threat_actor"),
        malware_families=extracted.get("malware_families") or [],
        mitre_ttps=extracted.get("mitre_ttps") or [],
        iocs=iocs,
        yaral_rule=state.get("final_yaral_rule"),
        sigma_rule=state.get("sigma_rule"),
        kql_query=state.get("kql_query"),
        retry_count=state.get("retry_count", 0),
        pipeline_error=state.get("pipeline_error"),
        extraction_error=state.get("extraction_error"),
    )


# ---------------------------------------------------------------------------
# Resolvers
# ---------------------------------------------------------------------------

@strawberry.type
class Query:

    @strawberry.field(description="Liveness probe — returns ok when the service is up.")
    def health(self) -> HealthResult:
        return HealthResult(status="ok", version="2.0.0")

    @strawberry.field(
        description=(
            "Return basic statistics about an Elasticsearch log index. "
            "Defaults to the 'agentic-cti-logs' index."
        )
    )
    def index_stats(self, index: str = "agentic-cti-logs") -> IndexStats:
        from api.es_client import get_index_stats
        raw = get_index_stats(index)
        tr_raw = raw.get("time_range")
        time_range = (
            TimeRange(min=tr_raw["min"], max=tr_raw["max"]) if tr_raw else None
        )
        return IndexStats(
            index=raw["index"],
            doc_count=raw["doc_count"],
            size_bytes=raw["size_bytes"],
            time_range=time_range,
        )


@strawberry.type
class Mutation:

    @strawberry.mutation(
        description=(
            "Run the full Agentic-CTI LangGraph pipeline on a raw threat report "
            "and return extracted IOCs, TTPs, and validated detection rules in "
            "YARA-L 2.0, Sigma, and KQL formats. "
            "Select only the fields you need — unselected fields are never serialised."
        )
    )
    def analyze_report(self, text: str) -> ThreatIntelResult:
        if not text.strip():
            raise ValueError("text cannot be empty")
        from agent import run_pipeline
        from api.main import _serialize_state
        state = run_pipeline(text)
        return _threat_intel_result_from_state(_serialize_state(state))

    @strawberry.mutation(
        description=(
            "Query Elasticsearch with a Lucene query string, synthesise threat "
            "intelligence from the returned log events, and generate detection "
            "rules. Returns the same structure as analyzeReport."
        )
    )
    def query_logs(
        self,
        query: str,
        index: str = "agentic-cti-logs",
        size: int = 100,
    ) -> ThreatIntelResult:
        if not query.strip():
            raise ValueError("query cannot be empty")
        from agent import run_pipeline_from_logs
        from api.main import _serialize_state
        state = run_pipeline_from_logs(query=query, index=index, size=size)
        return _threat_intel_result_from_state(_serialize_state(state))

    @strawberry.mutation(
        description=(
            "Generate a MITRE ATT&CK Navigator v4.9 layer from a list of "
            "technique IDs (e.g. ['T1059.001', 'T1071.001']). "
            "Returns serialised layer JSON ready to load at "
            "https://mitre-attack.github.io/attack-navigator/"
        )
    )
    def navigator_layer(
        self,
        ttps: list[str],
        name: str = "Agentic-CTI Threat Landscape",
        description: str = "Automatically generated ATT&CK layer from Agentic-CTI pipeline.",
    ) -> NavigatorResult:
        if not ttps:
            raise ValueError("ttps list cannot be empty")
        import json as _json
        from src.navigator import build_navigator_layer
        layer = build_navigator_layer(ttps=ttps, name=name, description=description)
        ttp_count = len({t["techniqueID"] for t in layer["techniques"]})
        total_obs = sum(t["score"] for t in layer["techniques"])
        return NavigatorResult(
            layer_json=_json.dumps(layer),
            ttp_count=ttp_count,
            total_observations=total_obs,
            mode="direct_ttps",
            extraction_errors=[],
        )


# ---------------------------------------------------------------------------
# Router — import this in api/main.py and include it on the FastAPI app
# ---------------------------------------------------------------------------

schema = strawberry.Schema(query=Query, mutation=Mutation)

graphql_router = GraphQLRouter(
    schema,
    graphql_ide="graphiql",   # interactive playground at /graphql
)
