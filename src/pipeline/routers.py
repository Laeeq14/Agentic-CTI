"""
src/pipeline/routers.py — Conditional edge router functions for the LangGraph.

Each router inspects the current state and returns the name of the next node
to execute. They are registered as conditional edges in graph.py.
"""

import logging

from src.models.schemas import ThreatIntelState
from src.pipeline.constants import MAX_RETRIES

logger = logging.getLogger(__name__)


def _route_entry_point(state: ThreatIntelState) -> str:
    """
    Router at the graph entry point.

    Dispatches to the correct first node based on input_type:
      - "log_query"    → query_elasticsearch_logs (ES path)
      - "text_report"  → scan_for_injection        (default text path)
    """
    if state.get("input_type") == "log_query":
        logger.info("[Router] input_type=log_query → ES pipeline path.")
        return "query_elasticsearch_logs"
    logger.info("[Router] input_type=text_report → text pipeline path.")
    return "scan_for_injection"


def _route_after_scan(state: ThreatIntelState) -> str:
    """
    Router called after the scan_for_injection node.

    Returns:
        'extract_threat_intel' if the input is clean.
        'finalize' if the prompt guard flagged the input as adversarial.
    """
    if state.get("pipeline_error"):
        logger.warning("[Router] Prompt guard blocked input — routing to finalize.")
        return "finalize"
    return "extract_threat_intel"


def _route_after_extraction(state: ThreatIntelState) -> str:
    """
    Router called after the extract_threat_intel (or synthesize_from_logs) node.

    Returns:
        'contextualize_with_rag' on success.
        'finalize' if extraction failed (surface error to UI).
    """
    if state.get("extraction_error"):
        return "finalize"
    return "contextualize_with_rag"


def _route_after_es_query(state: ThreatIntelState) -> str:
    """
    Router called after query_elasticsearch_logs.

    Returns:
        'synthesize_from_logs' if events were retrieved.
        'finalize' if the ES query failed.
    """
    if state.get("pipeline_error"):
        return "finalize"
    return "synthesize_from_logs"


def _route_after_validation(state: ThreatIntelState) -> str:
    """
    Router called after the validate_yaral node.

    Returns:
        'finalize' if validation passed or retries exhausted.
        'generate_yaral' if validation failed and retries remain.
    """
    if state.get("final_yaral_rule"):
        return "finalize"
    if state.get("retry_count", 0) >= MAX_RETRIES:
        logger.warning("Max retries reached; routing to finalize with error.")
        return "finalize"
    return "generate_yaral"
