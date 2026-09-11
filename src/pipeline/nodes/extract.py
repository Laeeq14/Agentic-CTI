"""
src/pipeline/nodes/extract.py — Extraction nodes (text-report and ES-log paths).

Node 1  (text path): extract_threat_intel  — LLM extracts structured threat
                     intel from a raw text report.
Node 1b (ES path):   synthesize_from_logs  — LLM synthesises the same
                     ThreatIntelReport schema from raw Elasticsearch log events.

Both nodes produce the same output shape so the shared downstream pipeline
(RAG → rule generation → validation) is completely path-agnostic.
"""

import json
import logging
from typing import Optional

from pydantic import ValidationError

from langchain_core.messages import HumanMessage, SystemMessage

from prompts import (
    EXTRACTION_SYSTEM_PROMPT,
    EXTRACTION_USER_TEMPLATE,
    ES_SYNTHESIS_SYSTEM_PROMPT,
    ES_SYNTHESIS_USER_TEMPLATE,
)
from src.llm.factory import _get_llm
from src.llm.rate_limit import _llm_invoke_with_backoff, _get_response_text, _extract_json_from_llm_response
from src.models.schemas import ThreatIntelReport, ThreatIntelState

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Node 1 (text path): Extract threat intelligence from a raw report
# ---------------------------------------------------------------------------

def extract_threat_intel(state: ThreatIntelState) -> ThreatIntelState:
    """
    Node 1 — Extract structured threat intelligence from raw text using the LLM.

    Calls the configured LLM with the extraction system prompt and parses the
    JSON response into a ThreatIntelReport Pydantic model. On failure, sets
    extraction_error for downstream error handling.

    Args:
        state: Current graph state containing 'raw_text'.

    Returns:
        Updated state with 'extracted_report' or 'extraction_error' populated.
    """
    logger.info("[Node 1] Extracting threat intelligence from raw text...")

    raw_response: Optional[str] = None  # initialise so all error handlers can access it

    try:
        llm = _get_llm(temperature=0.0)
        messages = [
            SystemMessage(content=EXTRACTION_SYSTEM_PROMPT),
            HumanMessage(
                content=EXTRACTION_USER_TEMPLATE.format(report_text=state["raw_text"])
            ),
        ]

        response = _llm_invoke_with_backoff(llm, messages)
        raw_response = _get_response_text(response).strip()
        logger.info("[Node 1] Raw LLM response (first 500 chars): %s", raw_response[:500])

        parsed = _extract_json_from_llm_response(raw_response)

        # Normalize iocs field — LLM may return a flat dict
        if isinstance(parsed.get("iocs"), dict):
            iocs_raw = parsed["iocs"]
            parsed["iocs"] = {
                "ips": iocs_raw.get("ips", []),
                "domains": iocs_raw.get("domains", []),
                "hashes": iocs_raw.get("hashes", []),
            }

        report = ThreatIntelReport(**parsed)
        logger.info("[Node 1] Extraction successful. Threat actor: %s", report.threat_actor)
        return {**state, "extracted_report": report, "extraction_error": None, "llm_raw_response": raw_response}

    except ValueError as e:
        msg = f"JSON parse failed: {e}"
        logger.error("[Node 1] %s", msg)
        return {**state, "extracted_report": None, "extraction_error": msg, "llm_raw_response": raw_response}

    except json.JSONDecodeError as e:
        msg = f"Invalid JSON from LLM: {e}"
        logger.error("[Node 1] %s", msg)
        return {**state, "extracted_report": None, "extraction_error": msg, "llm_raw_response": raw_response}

    except ValidationError as e:
        msg = f"Schema validation failed: {e}"
        logger.error("[Node 1] %s", msg)
        return {**state, "extracted_report": None, "extraction_error": msg, "llm_raw_response": raw_response}

    except Exception as e:
        # Captures API errors, rate limits, network failures etc.
        msg = f"API/pipeline error: {type(e).__name__}: {e}"
        logger.exception("[Node 1] %s", msg)
        debug_info = raw_response if raw_response else (
            f"[No response received — error before API call completed]\nException: {type(e).__name__}: {e}"
        )
        return {**state, "extracted_report": None, "extraction_error": msg, "llm_raw_response": debug_info}


# ---------------------------------------------------------------------------
# Node 1b (ES path): Synthesize threat intel from Elasticsearch log events
# ---------------------------------------------------------------------------

def synthesize_from_logs(state: ThreatIntelState) -> ThreatIntelState:
    """
    Node 1b (ES path) — Synthesize structured threat intel from raw log events.

    Feeds the raw Elasticsearch log events (stored as a JSON array) to the LLM
    using the ES synthesis prompt. Extracts the same ThreatIntelReport schema
    as extract_threat_intel, so the downstream RAG → YARA-L pipeline is
    completely unchanged.

    Args:
        state: Current graph state. Expects 'log_events' to be populated.

    Returns:
        Updated state with 'extracted_report' or 'extraction_error' populated.
    """
    logger.info(
        "[Node 1/ES] Synthesizing threat intel from %d log events...",
        len(state.get("log_events") or []),
    )

    events = state.get("log_events") or []
    if not events:
        msg = "No log events retrieved from Elasticsearch; cannot synthesize threat intel."
        logger.error("[Node 1/ES] %s", msg)
        return {**state, "extracted_report": None, "extraction_error": msg}

    raw_response: Optional[str] = None

    try:
        # Truncate event list if extremely large
        max_events = 50  # cap JSON payload to ~10k chars
        if len(events) > max_events:
            logger.warning(
                "[Node 1/ES] Truncating log events from %d to %d for LLM context.",
                len(events), max_events,
            )
            events = events[:max_events]

        log_events_json = json.dumps(events, indent=2)

        llm = _get_llm(temperature=0.0)
        messages = [
            SystemMessage(content=ES_SYNTHESIS_SYSTEM_PROMPT),
            HumanMessage(
                content=ES_SYNTHESIS_USER_TEMPLATE.format(log_events_json=log_events_json)
            ),
        ]

        response = _llm_invoke_with_backoff(llm, messages)
        raw_response = _get_response_text(response).strip()
        logger.info("[Node 1/ES] Raw LLM response (first 500 chars): %s", raw_response[:500])

        parsed = _extract_json_from_llm_response(raw_response)

        # Normalize iocs field
        if isinstance(parsed.get("iocs"), dict):
            iocs_raw = parsed["iocs"]
            parsed["iocs"] = {
                "ips":     iocs_raw.get("ips", []),
                "domains": iocs_raw.get("domains", []),
                "hashes":  iocs_raw.get("hashes", []),
            }

        report = ThreatIntelReport(**parsed)
        logger.info("[Node 1/ES] Synthesis successful. Threat actor: %s", report.threat_actor)
        return {
            **state,
            "extracted_report": report,
            "extraction_error": None,
            "llm_raw_response": raw_response,
        }

    except ValueError as e:
        msg = f"JSON parse failed (ES synthesis): {e}"
        logger.error("[Node 1/ES] %s", msg)
        return {**state, "extracted_report": None, "extraction_error": msg, "llm_raw_response": raw_response}
    except ValidationError as e:
        msg = f"Schema validation failed (ES synthesis): {e}"
        logger.error("[Node 1/ES] %s", msg)
        return {**state, "extracted_report": None, "extraction_error": msg, "llm_raw_response": raw_response}
    except Exception as e:
        msg = f"API/pipeline error (ES synthesis): {type(e).__name__}: {e}"
        logger.exception("[Node 1/ES] %s", msg)
        debug_info = raw_response or f"[No response — exception before API call completed]\n{e}"
        return {**state, "extracted_report": None, "extraction_error": msg, "llm_raw_response": debug_info}
