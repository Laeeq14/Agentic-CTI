"""
src/pipeline/nodes/es_query.py — Node 0.5 (ES path): Elasticsearch log query.

Queries Elasticsearch with a Lucene query string from the pipeline state
and stores the resulting raw log events for downstream synthesis.
Only activated when input_type == "log_query".
"""

import logging

from src.models.schemas import ThreatIntelState

logger = logging.getLogger(__name__)


def query_elasticsearch_logs(state: ThreatIntelState) -> ThreatIntelState:
    """
    Node 0.5 (ES path) — Query Elasticsearch for security log events.

    Runs only when input_type == "log_query". Calls the Elasticsearch client
    with the Lucene query string from state, returning up to log_query_size
    matching raw log events as a list of dicts stored in state["log_events"].

    On failure, sets pipeline_error and routes to finalize.

    Args:
        state: Current graph state. Expects 'log_query', 'log_query_index',
               and 'log_query_size' to be set.

    Returns:
        Updated state with 'log_events' populated, or 'pipeline_error' on failure.
    """
    query = state.get("log_query", "")
    index = state.get("log_query_index") or "agentic-cti-logs"
    size  = state.get("log_query_size") or 100

    logger.info(
        "[Node 0.5/ES] Querying Elasticsearch: index=%s, size=%d, query=%r",
        index, size, query,
    )

    try:
        from api.es_client import search_logs  # lazy import — avoids loading at module level
        events = search_logs(query=query, index=index, size=size)
        logger.info("[Node 0.5/ES] Retrieved %d log events.", len(events))
        return {**state, "log_events": events}
    except Exception as exc:
        msg = f"Elasticsearch query failed: {type(exc).__name__}: {exc}"
        logger.exception("[Node 0.5/ES] %s", msg)
        return {**state, "log_events": [], "pipeline_error": msg}
