"""
src/pipeline/nodes/finalize.py — Node 5: Pipeline finalisation.

Packages the final output and surfaces a meaningful error message if the
pipeline exhausted all retries or failed at an earlier stage.
"""

import logging

from src.models.schemas import ThreatIntelState
from src.pipeline.constants import MAX_RETRIES

logger = logging.getLogger(__name__)


def finalize(state: ThreatIntelState) -> ThreatIntelState:
    """
    Node 5 — Final packaging node.

    If the pipeline exhausted all retries without a valid YARA-L rule, sets
    pipeline_error. Preserves any existing pipeline_error already set by an
    upstream node (e.g. prompt guard block, extraction failure).

    Args:
        state: Current graph state.

    Returns:
        The state unchanged (all relevant fields already set by prior nodes).
    """
    if state.get("final_yaral_rule"):
        logger.info("[Node 5] Pipeline complete. Final YARA-L rule is ready.")
        return state

    # If a prior node already set a meaningful error, preserve it.
    existing_error = state.get("pipeline_error")
    if existing_error:
        logger.error("[Node 5] Pipeline terminated with prior error: %s", existing_error)
        return state

    # Only now do we know it was a YARA-L generation failure.
    if state.get("extracted_report"):
        msg = (
            f"Pipeline exhausted all {MAX_RETRIES} YARA-L generation retries "
            "without producing a valid rule. Last validation error: "
            + (state.get("yaral_validation_error") or "unknown")
        )
    elif state.get("extraction_error"):
        msg = f"Extraction failed — pipeline halted. Error: {state['extraction_error']}"
    else:
        msg = "Pipeline terminated without a result. Check logs for details."

    logger.error("[Node 5] %s", msg)
    return {**state, "pipeline_error": msg}
