"""
src/pipeline/runner.py — Public entry points for the Agentic-CTI pipeline.

Exposes two functions:
  run_pipeline          — Process a raw text threat intelligence report.
  run_pipeline_from_logs — Process Elasticsearch log events via a Lucene query.

Both functions initialise the LangGraph state, invoke the compiled graph,
and annotate the result with rate-limit telemetry from the current run.
"""

import logging

from dotenv import load_dotenv

from src.llm.rate_limit import reset_sleep_total, get_sleep_total
from src.models.schemas import ThreatIntelState
from src.pipeline.constants import MAX_INPUT_CHARS
from src.pipeline.graph import graph

load_dotenv()
logger = logging.getLogger(__name__)


def run_pipeline(text: str) -> ThreatIntelState:
    """
    Execute the full Agentic-CTI pipeline on unstructured threat intel text.

    Args:
        text: Raw unstructured threat intelligence report text.
              If longer than MAX_INPUT_CHARS, it is truncated with a warning
              logged. This prevents context-window overruns on large PDFs.

    Returns:
        The final ThreatIntelState dict with all populated fields.
        Key fields of interest:
          - extracted_report: ThreatIntelReport | None
          - rag_context: dict with 'matches' and 'top_similarity_score'
          - final_yaral_rule: str | None (the validated YARA-L rule)
          - sigma_rule: str | None
          - kql_query: str | None
          - pipeline_error: str | None (non-None if something went wrong)

    Raises:
        ValueError: If the input text is empty or whitespace-only.
    """
    reset_sleep_total()  # reset accumulator for this run

    if not text or not text.strip():
        raise ValueError("Input text cannot be empty.")

    # Truncate oversized inputs (e.g. full PDFs) to avoid context-window errors.
    if len(text) > MAX_INPUT_CHARS:
        logger.warning(
            "Input text is %d chars — truncating to %d chars to fit LLM context window.",
            len(text), MAX_INPUT_CHARS,
        )
        text = (
            text[:MAX_INPUT_CHARS]
            + f"\n\n[... TRUNCATED — original document was {len(text):,} characters. "
            "IOC extraction above covers the first portion of the report. ...]"
        )

    initial_state: ThreatIntelState = {
        "raw_text": text,
        "input_type": "text_report",
        # ES path fields (not used in text_report path)
        "log_query": None,
        "log_query_index": None,
        "log_query_size": None,
        "log_events": None,
        # Pipeline fields
        "security_scan": None,
        "extracted_report": None,
        "extraction_error": None,
        "llm_raw_response": None,
        "rag_context": None,
        "sigma_rule": None,
        "sigma_generation_error": None,
        "kql_query": None,
        "kql_generation_error": None,
        "yaral_draft": None,
        "yaral_validation_error": None,
        "retry_count": 0,
        "final_yaral_rule": None,
        "pipeline_error": None,
        "rate_limit_sleep_s": 0.0,
    }

    logger.info("Starting Agentic-CTI text-report pipeline...")
    result: ThreatIntelState = graph.invoke(initial_state)
    sleep_total = get_sleep_total()
    result["rate_limit_sleep_s"] = round(sleep_total, 2)
    if sleep_total > 0:
        logger.info("Pipeline finished. Total rate-limit sleep: %.1fs.", sleep_total)
    else:
        logger.info("Pipeline finished.")
    return result


def run_pipeline_from_logs(
    query: str,
    index: str = "agentic-cti-logs",
    size: int = 100,
) -> ThreatIntelState:
    """
    Execute the Agentic-CTI pipeline starting from an Elasticsearch log query.

    Instead of processing a text report, the pipeline:
      1. Queries Elasticsearch with the given Lucene query string.
      2. Synthesizes threat intelligence from the raw log events.
      3. Feeds the extracted intel through the existing RAG → YARA-L pipeline.

    Args:
        query: Lucene query string (e.g. "event_type:NETWORK_CONNECTION AND dest_ip:1.2.3.4").
        index: Elasticsearch index to query. Defaults to 'agentic-cti-logs'.
        size:  Maximum number of log events to retrieve. Defaults to 100.

    Returns:
        The final ThreatIntelState dict with all populated fields.

    Raises:
        ValueError: If the query is empty or whitespace-only.
    """
    if not query or not query.strip():
        raise ValueError("Log query cannot be empty.")

    reset_sleep_total()  # reset accumulator for this run

    initial_state: ThreatIntelState = {
        "raw_text": f"[ES log query: {query}]",  # summary for RAG embedding
        "input_type": "log_query",
        "log_query": query,
        "log_query_index": index,
        "log_query_size": size,
        "log_events": None,
        "security_scan": None,
        "extracted_report": None,
        "extraction_error": None,
        "llm_raw_response": None,
        "rag_context": None,
        "sigma_rule": None,
        "sigma_generation_error": None,
        "kql_query": None,
        "kql_generation_error": None,
        "yaral_draft": None,
        "yaral_validation_error": None,
        "retry_count": 0,
        "final_yaral_rule": None,
        "pipeline_error": None,
        "rate_limit_sleep_s": 0.0,
    }

    logger.info(
        "Starting Agentic-CTI ES log-query pipeline... query=%r, index=%s, size=%d",
        query, index, size,
    )
    result: ThreatIntelState = graph.invoke(initial_state)
    sleep_total = get_sleep_total()
    result["rate_limit_sleep_s"] = round(sleep_total, 2)
    if sleep_total > 0:
        logger.info("ES pipeline finished. Total rate-limit sleep: %.1fs.", sleep_total)
    else:
        logger.info("ES pipeline finished.")
    return result
