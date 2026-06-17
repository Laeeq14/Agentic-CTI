"""
agent.py — LangGraph state machine for the Agentic-CTI pipeline.

Orchestrates the full threat intelligence workflow:
  1. extract_threat_intel  — LLM extracts structured data from raw text.
  2. contextualize_with_rag — Qdrant similarity search for historical context.
  3. generate_yaral         — LLM generates a YARA-L 2.0 detection rule.
  4. validate_yaral         — Deterministic structural validation.
  5. finalize               — Packages final output for UI consumption.

A conditional retry loop routes failed YARA-L rules back to generate_yaral
with the validation error embedded in the prompt (max MAX_RETRIES attempts).
"""

import json
import logging
import os
import re
from typing import Any, Optional

from dotenv import load_dotenv
from langchain_groq import ChatGroq
from langchain_core.messages import HumanMessage, SystemMessage
from langgraph.graph import END, StateGraph
from pydantic import BaseModel, Field, ValidationError
from typing_extensions import TypedDict

import vector_store as vs
import validator as val
from src.security.prompt_guard import scan as guard_scan, ScanResult
from prompts import (
    EXTRACTION_SYSTEM_PROMPT,
    EXTRACTION_USER_TEMPLATE,
    YARAL_CORRECTION_SYSTEM_PROMPT,
    YARAL_CORRECTION_USER_TEMPLATE,
    YARAL_GENERATION_SYSTEM_PROMPT,
    YARAL_GENERATION_USER_TEMPLATE,
)

load_dotenv()
logger = logging.getLogger(__name__)

MAX_RETRIES = 3

# Maximum characters of raw text sent to the LLM.
# Groq's llama-3.3-70b supports ~128k tokens; we cap at 25k chars (~6k tokens)
# to leave ample room for system prompts and structured JSON output.
# Research/policy PDFs (e.g. Meta surveillance reports) often have IOCs
# deeper in the document, so 25k covers more ground than the initial 12k.
MAX_INPUT_CHARS = 25_000


# ---------------------------------------------------------------------------
# Pydantic schema for extracted threat intelligence
# ---------------------------------------------------------------------------

class IOCBundle(BaseModel):
    """Container for Indicators of Compromise grouped by type."""

    ips: list[str] = Field(default_factory=list, description="IPv4/IPv6 addresses")
    domains: list[str] = Field(default_factory=list, description="Fully-qualified domain names")
    hashes: list[str] = Field(default_factory=list, description="MD5, SHA1, or SHA256 file hashes")


class ThreatIntelReport(BaseModel):
    """
    Structured threat intelligence extracted from an unstructured report.

    All fields are required; empty lists/strings are used when data is absent.
    """

    threat_actor: str = Field(description="Name of the threat actor or APT group")
    malware_families: list[str] = Field(
        default_factory=list, description="Names of malware families identified"
    )
    mitre_ttps: list[str] = Field(
        default_factory=list,
        description="MITRE ATT&CK technique IDs (e.g. T1059.001)",
    )
    iocs: IOCBundle = Field(
        default_factory=IOCBundle,
        description="Indicators of Compromise grouped by type",
    )


# ---------------------------------------------------------------------------
# LangGraph state definition
# ---------------------------------------------------------------------------

class ThreatIntelState(TypedDict):
    """
    Shared state dictionary passed between all LangGraph nodes.

    Fields are populated progressively as the graph executes.
    """

    # Input
    raw_text: str

    # Node 0 — Security scan
    security_scan: Optional[dict[str, Any]]  # ScanResult fields; None = not yet run

    # Extraction node output
    extracted_report: Optional[ThreatIntelReport]
    extraction_error: Optional[str]
    llm_raw_response: Optional[str]  # raw LLM text for debugging failed extractions

    # RAG node output
    rag_context: Optional[dict[str, Any]]

    # YARA-L generation/validation
    yaral_draft: Optional[str]
    yaral_validation_error: Optional[str]
    retry_count: int

    # Final output
    final_yaral_rule: Optional[str]
    pipeline_error: Optional[str]


# ---------------------------------------------------------------------------
# LLM factory
# ---------------------------------------------------------------------------

def _get_llm(temperature: float = 0.1) -> ChatGroq:
    """
    Instantiate a Groq-backed Llama-3 LLM.

    Args:
        temperature: Sampling temperature. Lower = more deterministic.
                     Use ~0.1 for extraction, ~0.3 for creative YARA-L generation.

    Returns:
        A configured ChatGroq instance.

    Raises:
        EnvironmentError: If GROQ_API_KEY is not set.
    """
    api_key = os.getenv("GROQ_API_KEY")
    if not api_key:
        raise EnvironmentError(
            "GROQ_API_KEY not found. Set it in your .env file or environment."
        )
    model = os.getenv("GROQ_MODEL", "llama3-70b-8192")
    return ChatGroq(api_key=api_key, model_name=model, temperature=temperature)


# ---------------------------------------------------------------------------
# JSON extraction helper
# ---------------------------------------------------------------------------

def _extract_json_from_llm_response(raw: str) -> dict:
    """
    Robustly extract a JSON object from an LLM response string.

    Tries three strategies in order:
      1. Direct json.loads() — for well-behaved responses.
      2. Strip markdown code fences (```json ... ```) and retry.
      3. Regex search for the first {...} block in the string.

    Args:
        raw: The raw string returned by the LLM.

    Returns:
        A parsed dict.

    Raises:
        ValueError: If no valid JSON object can be found.
    """
    text = raw.strip()

    # Strategy 1: direct parse
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass

    # Strategy 2: strip markdown code fences
    fence_match = re.search(r"```(?:json)?\s*([\s\S]*?)```", text, re.IGNORECASE)
    if fence_match:
        try:
            return json.loads(fence_match.group(1).strip())
        except json.JSONDecodeError:
            pass

    # Strategy 3: find the outermost { ... } block
    brace_match = re.search(r"(\{[\s\S]*\})", text)
    if brace_match:
        try:
            return json.loads(brace_match.group(1))
        except json.JSONDecodeError:
            pass

    raise ValueError(
        f"No valid JSON object found in LLM response. "
        f"First 300 chars of response: {text[:300]!r}"
    )


# ---------------------------------------------------------------------------
# Node 0: Prompt injection security scan
# ---------------------------------------------------------------------------

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


# ---------------------------------------------------------------------------
# Node 1: Threat intelligence extraction
# ---------------------------------------------------------------------------

def extract_threat_intel(state: ThreatIntelState) -> ThreatIntelState:
    """
    Node 1 — Extract structured threat intelligence from raw text using the LLM.

    Calls Groq/Llama-3 with the extraction system prompt and parses the JSON
    response into a ThreatIntelReport Pydantic model. On failure, sets
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

        response = llm.invoke(messages)
        raw_response = response.content.strip()
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
        # Store the error text as raw_response so the UI can display it
        debug_info = raw_response if raw_response else f"[No response received — error before API call completed]\nException: {type(e).__name__}: {e}"
        return {**state, "extracted_report": None, "extraction_error": msg, "llm_raw_response": debug_info}


# ---------------------------------------------------------------------------
# Node 2: RAG contextualization
# ---------------------------------------------------------------------------

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


# ---------------------------------------------------------------------------
# Node 3: YARA-L 2.0 generation
# ---------------------------------------------------------------------------

def generate_yaral(state: ThreatIntelState) -> ThreatIntelState:
    """
    Node 3 — Generate a YARA-L 2.0 detection rule using the LLM.

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
    logger.info("[Node 3] Generating YARA-L rule (%s)...", attempt_label)

    report: ThreatIntelReport = state["extracted_report"]
    rag_context: dict = state.get("rag_context", {})

    # Build context string for the prompt
    matches = rag_context.get("matches", [])
    if matches:
        context_lines = []
        for m in matches:
            context_lines.append(
                f"- Threat actor: {m['threat_actor']}, "
                f"TTPs: {', '.join(m['mitre_ttps'])}, "
                f"Score: {m['score']:.4f}"
            )
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

        response = llm.invoke(messages)
        draft = val.extract_yaral_from_response(response.content)
        logger.info("[Node 3] ✅ YARA-L draft generated (%d chars).", len(draft))
        return {**state, "yaral_draft": draft}

    except Exception as e:
        msg = f"LLM call failed during YARA-L generation: {e}"
        logger.exception("[Node 3] ❌ %s", msg)
        return {**state, "yaral_draft": None, "pipeline_error": msg}


# ---------------------------------------------------------------------------
# Node 4: YARA-L validation
# ---------------------------------------------------------------------------

def validate_yaral(state: ThreatIntelState) -> ThreatIntelState:
    """
    Node 4 — Deterministically validate the LLM-generated YARA-L draft.

    Calls the regex-based validator. If validation passes, sets final_yaral_rule.
    If validation fails and retries remain, sets yaral_validation_error and
    increments retry_count (which routes back to Node 3).

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


# ---------------------------------------------------------------------------
# Node 5: Finalize
# ---------------------------------------------------------------------------

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



# ---------------------------------------------------------------------------
# Conditional routing
# ---------------------------------------------------------------------------

def _route_after_validation(state: ThreatIntelState) -> str:
    """
    Router function called after the validate_yaral node.

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


def _route_after_scan(state: ThreatIntelState) -> str:
    """
    Router function called after the scan_for_injection node.

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
    Router function called after the extract_threat_intel node.

    Returns:
        'contextualize_with_rag' on success.
        'finalize' if extraction failed (surface error to UI).
    """
    if state.get("extraction_error"):
        return "finalize"
    return "contextualize_with_rag"


# ---------------------------------------------------------------------------
# Graph construction
# ---------------------------------------------------------------------------

def _build_graph() -> Any:
    """
    Build and compile the LangGraph state machine.

    Graph topology:
      scan_for_injection           ← NEW: Node 0, prompt guard
            ↓ (safe)
      extract_threat_intel
            ↓ (success)
      contextualize_with_rag
            ↓
      generate_yaral  ←──────────────────────┐
            ↓                                │
      validate_yaral  ──(fail, retries left)─┘
            ↓ (pass or retries exhausted)
         finalize
            ↓
           END

    If the prompt guard flags the input, the pipeline routes directly from
    scan_for_injection to finalize — no LLM calls are made.

    Returns:
        A compiled LangGraph CompiledGraph ready for invocation.
    """
    workflow = StateGraph(ThreatIntelState)

    # Register nodes
    workflow.add_node("scan_for_injection", scan_for_injection)  # Node 0
    workflow.add_node("extract_threat_intel", extract_threat_intel)
    workflow.add_node("contextualize_with_rag", contextualize_with_rag)
    workflow.add_node("generate_yaral", generate_yaral)
    workflow.add_node("validate_yaral", validate_yaral)
    workflow.add_node("finalize", finalize)

    # Entry point — always the prompt guard
    workflow.set_entry_point("scan_for_injection")

    # Conditional edge after scan: safe -> extract, flagged -> finalize
    workflow.add_conditional_edges(
        "scan_for_injection",
        _route_after_scan,
        {
            "extract_threat_intel": "extract_threat_intel",
            "finalize": "finalize",
        },
    )

    # Conditional edge after extraction (may short-circuit to finalize on error)
    workflow.add_conditional_edges(
        "extract_threat_intel",
        _route_after_extraction,
        {
            "contextualize_with_rag": "contextualize_with_rag",
            "finalize": "finalize",
        },
    )

    # Linear edges through RAG and generation
    workflow.add_edge("contextualize_with_rag", "generate_yaral")
    workflow.add_edge("generate_yaral", "validate_yaral")

    # Conditional retry loop after validation
    workflow.add_conditional_edges(
        "validate_yaral",
        _route_after_validation,
        {
            "generate_yaral": "generate_yaral",
            "finalize": "finalize",
        },
    )

    # Finalize always terminates
    workflow.add_edge("finalize", END)

    return workflow.compile()


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

# Compile once at module import time
_graph = _build_graph()


def run_pipeline(text: str) -> ThreatIntelState:
    """
    Execute the full Agentic-CTI pipeline on unstructured threat intel text.

    Args:
        text: Raw unstructured threat intelligence report text.
              If longer than MAX_INPUT_CHARS, it is truncated with a warning
              logged. This prevents Groq context-window overruns on large PDFs.

    Returns:
        The final ThreatIntelState dict with all populated fields.
        Key fields of interest:
          - extracted_report: ThreatIntelReport | None
          - rag_context: dict with 'matches' and 'top_similarity_score'
          - final_yaral_rule: str | None (the validated YARA-L rule)
          - pipeline_error: str | None (non-None if something went wrong)

    Raises:
        ValueError: If the input text is empty or whitespace-only.
    """
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
        "security_scan": None,
        "extracted_report": None,
        "extraction_error": None,
        "llm_raw_response": None,
        "rag_context": None,
        "yaral_draft": None,
        "yaral_validation_error": None,
        "retry_count": 0,
        "final_yaral_rule": None,
        "pipeline_error": None,
    }

    logger.info("Starting Agentic-CTI pipeline...")
    result: ThreatIntelState = _graph.invoke(initial_state)
    logger.info("Pipeline finished.")
    return result


# ---------------------------------------------------------------------------
# Quick self-test (run: python agent.py)
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(levelname)s | %(message)s")

    SAMPLE_REPORT = """
    APT41, a Chinese state-sponsored threat actor also tracked as Double Dragon,
    has been observed deploying KEYPLUG malware and DEADEYE downloader in a campaign
    targeting telecommunications companies in Southeast Asia.

    The group leveraged spear-phishing emails with malicious Microsoft Office attachments
    (SHA256: 3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c)
    to gain initial access. Command-and-control communications were observed to
    203.0.113.45 and backup.evil-apt41.com via HTTPS on port 443.

    MITRE ATT&CK techniques identified: T1566.001 (Spearphishing Attachment),
    T1059.003 (Windows Command Shell), T1055 (Process Injection),
    T1071.001 (Web Protocols), T1027 (Obfuscated Files or Information).

    Additional IOCs:
    - IP: 198.51.100.22
    - Domain: update.apt41-c2.net
    - Hash (MD5): aabbccdd11223344aabbccdd11223344
    """

    result = run_pipeline(SAMPLE_REPORT)

    print("\n" + "=" * 60)
    print("EXTRACTED REPORT:")
    if result.get("extracted_report"):
        print(result["extracted_report"].model_dump_json(indent=2))

    print("\nRAG CONTEXT:")
    print(json.dumps(result.get("rag_context"), indent=2))

    print("\nFINAL YARA-L RULE:")
    print(result.get("final_yaral_rule") or "❌ No valid rule generated.")

    if result.get("pipeline_error"):
        print("\n⚠️  PIPELINE ERROR:", result["pipeline_error"])
