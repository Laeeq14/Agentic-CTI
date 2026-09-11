"""
src/pipeline/nodes/kql.py — Node 3b: Microsoft Sentinel KQL query generation.

Generates a KQL detection query from the extracted threat intelligence.
Uses the same TTP→logsource routing map as the Sigma node to stay in sync
when new TTP mappings are added.

No retry loop — KQL syntax is simpler and LLMs get it right first-pass
more reliably than YARA-L or Sigma YAML.

NOTE — parallel fan-out contract:
  This node runs concurrently with generate_sigma (both fan out from
  contextualize_with_rag). Every return must yield ONLY the keys this node
  owns ('kql_query', 'kql_generation_error'). Spreading **state would
  cause LangGraph to see two values for every shared key and raise
  INVALID_CONCURRENT_GRAPH_UPDATE at the fan-in join.
"""

import logging
import re

from langchain_core.messages import HumanMessage, SystemMessage

from prompts import (
    KQL_GENERATION_SYSTEM_PROMPT,
    KQL_GENERATION_USER_TEMPLATE,
)
from src.llm.factory import _get_llm
from src.llm.rate_limit import _llm_invoke_with_backoff, _get_response_text
from src.models.schemas import ThreatIntelReport, ThreatIntelState
from src.ttp_logsource_map import resolve_kql_table

logger = logging.getLogger(__name__)


def generate_kql(state: ThreatIntelState) -> ThreatIntelState:
    """
    Node 3b — Generate a Microsoft Sentinel KQL detection query.

    Uses the same TTP→logsource routing map to select SecurityEvent vs.
    CommonSecurityLog, mirroring the Sigma logsource split so both generators
    stay in sync when new TTP mappings are added.

    Args:
        state: Current graph state. Expects 'extracted_report' and 'rag_context'.

    Returns:
        Partial state dict containing only 'kql_query' and
        'kql_generation_error'.
    """
    logger.info("[Node 3b] Generating Sentinel KQL query...")

    report: ThreatIntelReport = state.get("extracted_report")
    if not report:
        logger.warning("[Node 3b] No extracted report — skipping KQL generation.")
        # Return ONLY owned keys — no **state spread (parallel fan-out contract)
        return {"kql_query": None, "kql_generation_error": "No extracted report available."}

    rag_context: dict = state.get("rag_context") or {}
    matches = rag_context.get("matches", [])
    context_str = (
        "Similar historical reports:\n" + "\n".join(
            f"- Threat actor: {m['threat_actor']}, TTPs: {', '.join(m['mitre_ttps'])}, Score: {m['score']:.4f}"
            for m in matches
        )
    ) if matches else "No similar historical reports found in the knowledge base."

    # Resolve KQL table from TTPs — same routing logic as Sigma
    kql_table = resolve_kql_table(report.mitre_ttps)
    ttps_summary = ", ".join(report.mitre_ttps[:10]) or "Unknown"
    json_data = report.model_dump_json(indent=2)

    llm = _get_llm(temperature=0.1)

    try:
        system_prompt = KQL_GENERATION_SYSTEM_PROMPT.replace("{kql_table}", kql_table)
        messages = [
            SystemMessage(content=system_prompt),
            HumanMessage(
                content=KQL_GENERATION_USER_TEMPLATE.format(
                    json_data=json_data,
                    kql_table=kql_table,
                    ttps_summary=ttps_summary,
                    context=context_str,
                )
            ),
        ]

        response = _llm_invoke_with_backoff(llm, messages)
        # Strip markdown fences if present
        kql_raw = _get_response_text(response).strip()
        fence_match = re.search(
            r"```(?:kql|kusto|text|plaintext)?\s*\n?(.*?)```", kql_raw, re.DOTALL | re.IGNORECASE
        )
        kql_query = fence_match.group(1).strip() if fence_match else kql_raw

        logger.info("[Node 3b] ✅ KQL query generated (%d chars).", len(kql_query))
        # Return ONLY owned keys — no **state spread (parallel fan-out contract)
        return {"kql_query": kql_query, "kql_generation_error": None}

    except Exception as e:
        msg = f"KQL generation failed: {type(e).__name__}: {e}"
        logger.exception("[Node 3b] ❌ %s", msg)
        # Return ONLY owned keys — no **state spread (parallel fan-out contract)
        return {"kql_query": None, "kql_generation_error": msg}
