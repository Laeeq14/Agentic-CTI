"""
src/pipeline/nodes/sigma.py — Node 3a: Sigma rule generation.

Generates a Sigma detection rule from the extracted threat intelligence.
Uses the TTP→logsource routing map to pick the correct logsource block
before calling the LLM, then runs a single correction pass on failure.

NOTE — parallel fan-out contract:
  This node runs concurrently with generate_kql (both fan out from
  contextualize_with_rag). Every return must yield ONLY the keys this node
  owns ('sigma_rule', 'sigma_generation_error'). Spreading **state would
  cause LangGraph to see two values for every shared key and raise
  INVALID_CONCURRENT_GRAPH_UPDATE at the fan-in join.
"""

import logging
from typing import Optional

from langchain_core.messages import HumanMessage, SystemMessage

import sigma_validator as sval
from prompts import (
    SIGMA_CORRECTION_SYSTEM_PROMPT,
    SIGMA_CORRECTION_USER_TEMPLATE,
    SIGMA_GENERATION_SYSTEM_PROMPT,
    SIGMA_GENERATION_USER_TEMPLATE,
)
from src.llm.factory import _get_llm
from src.llm.rate_limit import _llm_invoke_with_backoff, _get_response_text
from src.models.schemas import ThreatIntelReport, ThreatIntelState
from src.pipeline.constants import MAX_SIGMA_RETRIES
from src.ttp_logsource_map import resolve_logsource

logger = logging.getLogger(__name__)


def generate_sigma(state: ThreatIntelState) -> ThreatIntelState:
    """
    Node 3a — Generate a Sigma rule from the extracted threat intel.

    Uses the TTP→logsource routing map to select the appropriate Sigma
    logsource category/product before calling the LLM. This means logsource
    is a parameter derived from intelligence, not a hardcoded assumption.

    Runs a single correction pass on validation failure (max MAX_SIGMA_RETRIES).

    Args:
        state: Current graph state. Expects 'extracted_report' and 'rag_context'.

    Returns:
        Partial state dict containing only 'sigma_rule' and
        'sigma_generation_error'.
    """
    logger.info("[Node 3a] Generating Sigma rule...")

    report: ThreatIntelReport = state.get("extracted_report")
    if not report:
        logger.warning("[Node 3a] No extracted report — skipping Sigma generation.")
        return {"sigma_rule": None, "sigma_generation_error": "No extracted report available."}

    rag_context: dict = state.get("rag_context") or {}
    matches = rag_context.get("matches", [])
    context_str = (
        "Similar historical reports:\n" + "\n".join(
            f"- Threat actor: {m['threat_actor']}, TTPs: {', '.join(m['mitre_ttps'])}, Score: {m['score']:.4f}"
            for m in matches
        )
    ) if matches else "No similar historical reports found in the knowledge base."

    # Resolve logsource from TTPs — parameterized, not hardcoded
    logsource = resolve_logsource(report.mitre_ttps)
    logsource_lines = "\n".join(f"  {k}: {v}" for k, v in logsource.items())
    logsource_block = logsource_lines.strip()

    json_data = report.model_dump_json(indent=2)
    llm = _get_llm(temperature=0.2)

    sigma_draft: Optional[str] = None
    last_error: Optional[str] = None

    for attempt in range(MAX_SIGMA_RETRIES):
        try:
            if attempt == 0:
                messages = [
                    SystemMessage(content=SIGMA_GENERATION_SYSTEM_PROMPT.replace("{logsource_block}", logsource_block)),
                    HumanMessage(
                        content=SIGMA_GENERATION_USER_TEMPLATE.format(
                            json_data=json_data,
                            logsource_block=logsource_block,
                            context=context_str,
                        )
                    ),
                ]
            else:
                messages = [
                    SystemMessage(content=SIGMA_CORRECTION_SYSTEM_PROMPT),
                    HumanMessage(
                        content=SIGMA_CORRECTION_USER_TEMPLATE.format(
                            failed_rule=sigma_draft or "",
                            validation_error=last_error or "",
                        )
                    ),
                ]

            response = _llm_invoke_with_backoff(llm, messages)
            sigma_draft = sval.extract_sigma_from_response(_get_response_text(response))
            is_valid, err = sval.validate_sigma_rule(sigma_draft)

            if is_valid:
                logger.info("[Node 3a] ✅ Sigma rule validated (attempt %d).", attempt + 1)
                # Return ONLY owned keys — no **state spread (parallel fan-out contract)
                return {"sigma_rule": sigma_draft, "sigma_generation_error": None}
            else:
                logger.warning("[Node 3a] Sigma validation failed (attempt %d): %s", attempt + 1, err[:200])
                last_error = err

        except Exception as e:
            last_error = f"LLM call failed: {type(e).__name__}: {e}"
            logger.exception("[Node 3a] ❌ %s", last_error)
            break  # _llm_invoke_with_backoff already handled rate-limit retries

    # All attempts failed — store whatever draft we have (best effort)
    logger.error("[Node 3a] ❌ Sigma generation exhausted %d attempts.", MAX_SIGMA_RETRIES)
    # Return ONLY owned keys — no **state spread (parallel fan-out contract)
    return {
        "sigma_rule": sigma_draft,
        "sigma_generation_error": last_error,
    }
