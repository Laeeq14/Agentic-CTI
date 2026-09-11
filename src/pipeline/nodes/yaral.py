"""
src/pipeline/nodes/yaral.py — Nodes 3c & 4: YARA-L generation and validation.

Node 3c: generate_yaral  — LLM generates a YARA-L 2.0 detection rule, with a
                            correction-prompt retry loop on validation failure.
Node 4:  validate_yaral  — Deterministic structural validation of the draft rule.
"""

import logging
from typing import Optional

from langchain_core.messages import HumanMessage, SystemMessage

import validator as val
from prompts import (
    YARAL_CORRECTION_SYSTEM_PROMPT,
    YARAL_CORRECTION_USER_TEMPLATE,
    YARAL_GENERATION_SYSTEM_PROMPT,
    YARAL_GENERATION_USER_TEMPLATE,
)
from src.llm.factory import _get_llm
from src.llm.rate_limit import _llm_invoke_with_backoff, _get_response_text
from src.models.schemas import ThreatIntelReport, ThreatIntelState
from src.pipeline.constants import MAX_RETRIES

logger = logging.getLogger(__name__)


def generate_yaral(state: ThreatIntelState) -> ThreatIntelState:
    """
    Node 3c — Generate a YARA-L 2.0 detection rule using the LLM.

    On the first attempt, uses the standard generation prompt.
    On retry attempts (retry_count > 0), uses the correction prompt which
    includes the validation error from the previous attempt.

    Args:
        state: Current graph state. Expects 'extracted_report' and 'rag_context'.

    Returns:
        Updated state with 'yaral_draft' set to the raw LLM output.
    """
    retry = state.get("retry_count", 0)
    attempt_label = f"attempt {retry + 1}/{MAX_RETRIES}"
    logger.info("[Node 3c] Generating YARA-L rule (%s)...", attempt_label)

    report: ThreatIntelReport = state["extracted_report"]
    rag_context: dict = state.get("rag_context", {})

    # Build context string for the prompt
    matches = rag_context.get("matches", [])
    if matches:
        context_lines = [
            f"- Threat actor: {m['threat_actor']}, "
            f"TTPs: {', '.join(m['mitre_ttps'])}, "
            f"Score: {m['score']:.4f}"
            for m in matches
        ]
        context_str = "Similar historical reports:\n" + "\n".join(context_lines)
    else:
        context_str = "No similar historical reports found in the knowledge base."

    json_data = report.model_dump_json(indent=2)
    llm = _get_llm(temperature=0.2)

    try:
        if retry == 0:
            # First attempt: standard generation
            messages = [
                SystemMessage(content=YARAL_GENERATION_SYSTEM_PROMPT),
                HumanMessage(
                    content=YARAL_GENERATION_USER_TEMPLATE.format(
                        json_data=json_data,
                        context=context_str,
                    )
                ),
            ]
        else:
            # Retry: correction prompt with validation error
            prev_draft = state.get("yaral_draft", "")
            validation_error = state.get("yaral_validation_error", "Unknown error")
            messages = [
                SystemMessage(content=YARAL_CORRECTION_SYSTEM_PROMPT),
                HumanMessage(
                    content=YARAL_CORRECTION_USER_TEMPLATE.format(
                        failed_rule=prev_draft,
                        validation_error=validation_error,
                    )
                ),
            ]

        response = _llm_invoke_with_backoff(llm, messages)
        draft = val.extract_yaral_from_response(_get_response_text(response))
        logger.info("[Node 3c] ✅ YARA-L draft generated (%d chars).", len(draft))
        return {**state, "yaral_draft": draft}

    except Exception as e:
        msg = f"LLM call failed during YARA-L generation: {e}"
        logger.exception("[Node 3c] ❌ %s", msg)
        return {**state, "yaral_draft": None, "pipeline_error": msg}


def validate_yaral(state: ThreatIntelState) -> ThreatIntelState:
    """
    Node 4 — Deterministically validate the LLM-generated YARA-L draft.

    Calls the regex-based validator. If validation passes, sets final_yaral_rule.
    If validation fails and retries remain, sets yaral_validation_error and
    increments retry_count (which routes back to Node 3c).

    Args:
        state: Current graph state. Expects 'yaral_draft'.

    Returns:
        Updated state with either 'final_yaral_rule' (success) or
        'yaral_validation_error' + incremented 'retry_count' (failure).
    """
    logger.info("[Node 4] Validating YARA-L rule...")

    draft = state.get("yaral_draft")
    if not draft:
        msg = "YARA-L draft is empty; cannot validate."
        logger.error("[Node 4] ❌ %s", msg)
        return {**state, "pipeline_error": msg, "yaral_validation_error": msg}

    is_valid, error_msg = val.validate_yaral_rule(draft)

    if is_valid:
        logger.info("[Node 4] ✅ YARA-L validation passed.")
        return {
            **state,
            "final_yaral_rule": draft,
            "yaral_validation_error": None,
        }
    else:
        retry = state.get("retry_count", 0)
        logger.warning(
            "[Node 4] ❌ Validation failed (retry %d/%d): %s",
            retry + 1, MAX_RETRIES, error_msg,
        )
        return {
            **state,
            "yaral_validation_error": error_msg,
            "retry_count": retry + 1,
        }
