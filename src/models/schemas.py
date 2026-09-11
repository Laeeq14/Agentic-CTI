"""
src/models/schemas.py — Pydantic schemas and LangGraph state for Agentic-CTI.

Defines the data contracts shared across the entire pipeline:
  - IOCBundle          — IOCs grouped by type (IPs, domains, hashes)
  - ThreatIntelReport  — Structured threat intel extracted from a raw report
  - ThreatIntelState   — Shared state dict passed between all LangGraph nodes
"""

from typing import Any, Optional

from pydantic import BaseModel, Field
from typing_extensions import TypedDict


# ---------------------------------------------------------------------------
# Pydantic schema for extracted threat intelligence
# ---------------------------------------------------------------------------

class IOCBundle(BaseModel):
    """Container for Indicators of Compromise grouped by type."""

    ips: list[str] = Field(default_factory=list, description="IPv4/IPv6 addresses")
    domains: list[str] = Field(default_factory=list, description="Fully-qualified domain names")
    hashes: list[str] = Field(default_factory=list, description="MD5, SHA1, or SHA256 file hashes")


class ThreatIntelReport(BaseModel):
    """
    Structured threat intelligence extracted from an unstructured report.

    All fields are required; empty lists/strings are used when data is absent.
    """

    threat_actor: str = Field(description="Name of the threat actor or APT group")
    malware_families: list[str] = Field(
        default_factory=list, description="Names of malware families identified"
    )
    mitre_ttps: list[str] = Field(
        default_factory=list,
        description="MITRE ATT&CK technique IDs (e.g. T1059.001)",
    )
    iocs: IOCBundle = Field(
        default_factory=IOCBundle,
        description="Indicators of Compromise grouped by type",
    )


# ---------------------------------------------------------------------------
# LangGraph state definition
# ---------------------------------------------------------------------------

class ThreatIntelState(TypedDict):
    """
    Shared state dictionary passed between all LangGraph nodes.

    Fields are populated progressively as the graph executes.

    Two pipeline paths are supported:
      - input_type == "text_report"  → scan_for_injection → extract_threat_intel → ...
      - input_type == "log_query"    → query_elasticsearch_logs → synthesize_from_logs → ...
    """

    # Input — shared
    raw_text: str
    input_type: str  # "text_report" (default) or "log_query"

    # ES log-query path inputs (only used when input_type == "log_query")
    log_query: Optional[str]        # Lucene query string
    log_query_index: Optional[str]  # target ES index
    log_query_size: Optional[int]   # max log events to retrieve

    # ES log-query path intermediates
    log_events: Optional[list[dict[str, Any]]]  # raw log events from ES

    # Node 0 — Security scan (text_report path only)
    security_scan: Optional[dict[str, Any]]  # ScanResult fields; None = not yet run

    # Extraction node output
    extracted_report: Optional[ThreatIntelReport]
    extraction_error: Optional[str]
    llm_raw_response: Optional[str]  # raw LLM text for debugging failed extractions

    # RAG node output
    rag_context: Optional[dict[str, Any]]

    # YARA-L generation/validation
    yaral_draft: Optional[str]
    yaral_validation_error: Optional[str]
    retry_count: int

    # Sigma rule generation
    sigma_rule: Optional[str]
    sigma_generation_error: Optional[str]

    # KQL query generation (Microsoft Sentinel)
    kql_query: Optional[str]
    kql_generation_error: Optional[str]

    # Final output
    final_yaral_rule: Optional[str]
    pipeline_error: Optional[str]

    # Rate-limit telemetry — total seconds slept across all backoff events
    # in this pipeline run.  0.0 means no throttling occurred.
    # Set by run_pipeline; used by the eval runner to flag inflated latency.
    rate_limit_sleep_s: float
