"""
src/pipeline/nodes/security.py — Node 0: Prompt injection security scan.

Runs a deterministic regex-based scan on the raw input text before any LLM
call. If adversarial patterns are detected the pipeline is halted immediately —
no tokens are consumed and no detection rule is generated.
"""

import logging
from typing import Any

from src.models.schemas import ThreatIntelState
from src.security.prompt_guard import scan as guard_scan, ScanResult

logger = logging.getLogger(__name__)


def scan_for_injection(state: ThreatIntelState) -> ThreatIntelState:
    """
    Node 0 — Deterministic prompt injection guardrail.

    Runs before any LLM call. Scans the raw input text for adversarial
    patterns (instruction overrides, role switching, jailbreaks, etc.) using
    the deterministic regex-based scanner in src/security/prompt_guard.py.

    If a threat is detected the pipeline is halted immediately — no LLM tokens
    are consumed and no YARA-L rule is generated.

    Args:
        state: Current graph state containing 'raw_text'.

    Returns:
        Updated state with 'security_scan' populated. If the input is flagged,
        'pipeline_error' is also set to halt further processing.
    """
    logger.info("[Node 0] Running prompt injection scan...")
    result: ScanResult = guard_scan(state["raw_text"])

    scan_payload: dict[str, Any] = {
        "is_safe": result.is_safe,
        "threat_type": result.threat_type,
        "matched_snippet": result.matched_snippet,
        "all_findings": result.all_findings,
    }

    if result.is_safe:
        logger.info("[Node 0] Input cleared — no adversarial patterns detected.")
        return {**state, "security_scan": scan_payload}
    else:
        msg = (
            f"[SECURITY] Input blocked by prompt guard. "
            f"Threat type: {result.threat_type}. "
            f"Match: '{result.matched_pattern}'"
        )
        logger.warning("[Node 0] %s", msg)
        return {**state, "security_scan": scan_payload, "pipeline_error": msg}
