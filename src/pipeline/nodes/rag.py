"""
src/pipeline/nodes/rag.py — Node 2: RAG contextualization.

Queries Qdrant for historically similar threat reports using an embedding
of the extracted ThreatIntelReport, then auto-ingests the current report
so it enriches future queries.
"""

import logging

import vector_store as vs
from src.models.schemas import ThreatIntelReport, ThreatIntelState

logger = logging.getLogger(__name__)


def contextualize_with_rag(state: ThreatIntelState) -> ThreatIntelState:
    """
    Node 2 — Query Qdrant for similar historical threat reports.

    Generates an embedding from the extracted ThreatIntelReport and retrieves
    the top-K most similar stored reports. Returns a similarity score and
    context snippets used to enrich YARA-L generation.

    Stores the current report in Qdrant for future queries (auto-ingestion).

    Args:
        state: Current graph state. Expects 'extracted_report' to be set.

    Returns:
        Updated state with 'rag_context' populated.
    """
    logger.info("[Node 2] Running RAG contextualization...")

    if not state.get("extracted_report"):
        logger.warning("[Node 2] No extracted report found; skipping RAG.")
        return {**state, "rag_context": {"matches": [], "top_similarity_score": 0.0}}

    report: ThreatIntelReport = state["extracted_report"]

    try:
        # Query before ingesting to avoid the report matching itself
        rag_result = vs.query_similar(report)
        logger.info(
            "[Node 2] ✅ RAG complete. Top similarity: %.4f, matches: %d",
            rag_result["top_similarity_score"],
            len(rag_result["matches"]),
        )

        # Auto-ingest the current report for future queries
        vs.add_report(report, source_text=state.get("raw_text", ""))

        return {**state, "rag_context": rag_result}

    except Exception as e:
        logger.exception("[Node 2] ❌ RAG query failed: %s", e)
        return {
            **state,
            "rag_context": {
                "matches": [],
                "top_similarity_score": 0.0,
                "error": str(e),
            },
        }
