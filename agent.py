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
import random
import re
import threading
import time
from typing import Any, Optional

from dotenv import load_dotenv
from langchain_groq import ChatGroq
from langchain_openai import ChatOpenAI
from langchain_core.messages import HumanMessage, SystemMessage
from langgraph.graph import END, StateGraph
from pydantic import BaseModel, Field, ValidationError
from typing_extensions import TypedDict

import vector_store as vs
import validator as val
import sigma_validator as sval
from src.security.prompt_guard import scan as guard_scan, ScanResult
from src.ttp_logsource_map import resolve_logsource, resolve_kql_table
from prompts import (
    EXTRACTION_SYSTEM_PROMPT,
    EXTRACTION_USER_TEMPLATE,
    YARAL_CORRECTION_SYSTEM_PROMPT,
    YARAL_CORRECTION_USER_TEMPLATE,
    YARAL_GENERATION_SYSTEM_PROMPT,
    YARAL_GENERATION_USER_TEMPLATE,
    ES_SYNTHESIS_SYSTEM_PROMPT,
    ES_SYNTHESIS_USER_TEMPLATE,
    SIGMA_GENERATION_SYSTEM_PROMPT,
    SIGMA_GENERATION_USER_TEMPLATE,
    SIGMA_CORRECTION_SYSTEM_PROMPT,
    SIGMA_CORRECTION_USER_TEMPLATE,
    KQL_GENERATION_SYSTEM_PROMPT,
    KQL_GENERATION_USER_TEMPLATE,
)

load_dotenv()
logger = logging.getLogger(__name__)

MAX_RETRIES = 3

# Maximum characters of raw text sent to the LLM (extraction step only).
#
# Context math:
#   Cerebras / OpenRouter free tier  → 128k token context → ~500k chars headroom.
#   Groq free "on_demand" tier       → 8,000 TPM per request (≈20k chars safe).
#
# 100k chars covers the vast majority of real-world threat advisories.
# If you are on Groq free tier and hit 413 errors, either:
#   a) Upgrade to Groq Dev Tier, or
#   b) Add OPENROUTER_API_KEY or CEREBRAS_API_KEY — both have 128k+ context.
MAX_INPUT_CHARS = 100_000


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

    Two pipeline paths are supported:
      - input_type == "text_report"  → scan_for_injection → extract_threat_intel → ...
      - input_type == "log_query"    → query_elasticsearch_logs → synthesize_from_logs → ...
    """

    # Input — shared
    raw_text: str
    input_type: str  # "text_report" (default) or "log_query"

    # ES log-query path inputs (only used when input_type == "log_query")
    log_query: Optional[str]        # Lucene query string
    log_query_index: Optional[str]  # target ES index
    log_query_size: Optional[int]   # max log events to retrieve

    # ES log-query path intermediates
    log_events: Optional[list[dict[str, Any]]]  # raw log events from ES

    # Node 0 — Security scan (text_report path only)
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

    # Sigma rule generation
    sigma_rule: Optional[str]
    sigma_generation_error: Optional[str]

    # KQL query generation (Microsoft Sentinel)
    kql_query: Optional[str]
    kql_generation_error: Optional[str]

    # Final output
    final_yaral_rule: Optional[str]
    pipeline_error: Optional[str]

    # Rate-limit telemetry — total seconds slept across all backoff events
    # in this pipeline run.  0.0 means no throttling occurred.
    # Set by run_pipeline; used by the eval runner to flag inflated latency.
    rate_limit_sleep_s: float


# ---------------------------------------------------------------------------
# Provider detection — Cerebras → OpenRouter → Groq (first key found wins)
# ---------------------------------------------------------------------------

PROVIDER_CEREBRAS    = "cerebras"
PROVIDER_OPENROUTER  = "openrouter"
PROVIDER_GROQ        = "groq"


def _detect_provider() -> str:
    """
    Choose an LLM provider based on which API key is present.

    Priority:
      1. Cerebras   — blazing-fast inference, 128k context, free tier.
      2. OpenRouter  — free tier access to many models, 128k+ context.
      3. Groq        — default; free tier limited to 8k TPM per request.

    Override by setting LLM_PROVIDER=groq|openrouter|cerebras explicitly.
    """
    explicit = os.getenv("LLM_PROVIDER", "").strip().lower()
    if explicit in (PROVIDER_CEREBRAS, PROVIDER_OPENROUTER, PROVIDER_GROQ):
        return explicit
    if os.getenv("CEREBRAS_API_KEY"):
        return PROVIDER_CEREBRAS
    if os.getenv("OPENROUTER_API_KEY"):
        return PROVIDER_OPENROUTER
    return PROVIDER_GROQ


# ---------------------------------------------------------------------------
# LLM factory
# ---------------------------------------------------------------------------

def _get_llm(temperature: float = 0.1):
    """
    Instantiate the configured LLM.

    Provider priority: Cerebras → OpenRouter → Groq.
    Override with LLM_PROVIDER env var.

    Args:
        temperature: Sampling temperature. Lower = more deterministic.
                     Use ~0.1 for extraction, ~0.3 for creative generation.

    Returns:
        A LangChain chat model (ChatGroq or ChatOpenAI depending on provider).

    Raises:
        EnvironmentError: If no API key is found for the selected provider.
    """
    provider = _detect_provider()

    if provider == PROVIDER_CEREBRAS:
        api_key = os.getenv("CEREBRAS_API_KEY")
        if not api_key:
            raise EnvironmentError("CEREBRAS_API_KEY not set.")
        model = os.getenv("CEREBRAS_MODEL", "gpt-oss-120b")  # free tier: 8k ctx, 1M tokens/day
        logger.info("[LLM] Provider=Cerebras model=%s", model)
        return ChatOpenAI(
            api_key=api_key,
            base_url="https://api.cerebras.ai/v1",
            model=model,
            temperature=temperature,
        )

    if provider == PROVIDER_OPENROUTER:
        return _get_openrouter_llm(temperature)

    # Groq (default)
    api_key = os.getenv("GROQ_API_KEY")
    if not api_key:
        raise EnvironmentError(
            "No LLM API key found. Set GROQ_API_KEY, OPENROUTER_API_KEY, "
            "or CEREBRAS_API_KEY in your .env file."
        )
    model = os.getenv("GROQ_MODEL", "qwen/qwen3.6-27b")
    logger.info("[LLM] Provider=Groq model=%s", model)
    return ChatGroq(api_key=api_key, model_name=model, temperature=temperature)


def _get_openrouter_llm(temperature: float = 0.1) -> ChatOpenAI | None:
    """
    Build a ChatOpenAI pointed at OpenRouter's free router.

    The model ``openrouter/free`` is a special OpenRouter meta-model that
    intelligently routes to whichever high-quality free model has capacity
    (GPT-OSS-120B accounts for ~13% of that pool). Supports up to 1M token
    context on some models in the pool.

    Returns None if OPENROUTER_API_KEY is not configured.
    """
    api_key = os.getenv("OPENROUTER_API_KEY")
    if not api_key:
        return None
    model = os.getenv("OPENROUTER_MODEL", "openrouter/free")
    logger.info("[LLM] Provider=OpenRouter model=%s", model)
    return ChatOpenAI(
        api_key=api_key,
        base_url="https://openrouter.ai/api/v1",
        model=model,
        temperature=temperature,
        max_tokens=16384,   # request generous output budget for large JSON
        default_headers={
            "HTTP-Referer": "https://github.com/Laeeq14/Agentic-CTI",
            "X-Title": "Agentic-CTI",
        },
    )


# ---------------------------------------------------------------------------
# API key pool — rotated on per-account rate-limit exhaustion
# ---------------------------------------------------------------------------

def _load_api_key_pool() -> list[str]:
    """
    Collect all Groq API keys from the environment.

    Reads GROQ_API_KEY (primary) plus GROQ_API_KEY_2, GROQ_API_KEY_3, …
    (overflow accounts) and returns them as an ordered list, deduplicated
    while preserving insertion order.  At least one key must be present or
    _get_llm() will raise EnvironmentError on first use.
    """
    seen: set[str] = set()
    keys: list[str] = []
    for var in ("GROQ_API_KEY", "GROQ_API_KEY_2", "GROQ_API_KEY_3"):
        val = os.getenv(var, "").strip()
        if val and val not in seen:
            seen.add(val)
            keys.append(val)
    return keys


_API_KEY_POOL: list[str] = []  # populated lazily on first LLM call
_current_key_idx: int = 0      # sticky: persists across requests for round-robin load-balancing
_rate_limit_sleep_total: float = 0.0  # accumulated sleep time; reset by run_pipeline per-request

# Thread-safety: generate_sigma and generate_kql run on separate OS threads
# inside LangGraph's ThreadPoolExecutor fan-out. Both write to the two globals
# above. Two lightweight locks protect those write paths without blocking
# the (CPython-atomic) reads.
#
# Lock choice — threading.Lock (not RLock):
#   Plain Lock is correct here because no code path acquires either lock and
#   then calls back into a function that acquires the same lock again (no
#   nested/re-entrant acquisition). If that ever changes — e.g. a helper that
#   calls _llm_invoke_with_backoff from inside a locked block — switch to
#   threading.RLock, or you'll get a silent deadlock rather than a clear error.
_key_idx_lock: threading.Lock   = threading.Lock()   # guards writes to _current_key_idx
_sleep_total_lock: threading.Lock = threading.Lock()  # guards += on _rate_limit_sleep_total


def _get_key_pool() -> list[str]:
    """Return the key pool, initialising it from the environment if needed."""
    global _API_KEY_POOL
    if not _API_KEY_POOL:
        _API_KEY_POOL = _load_api_key_pool()
    return _API_KEY_POOL


# ---------------------------------------------------------------------------
# Retry-After-based LLM invocation helper
# ---------------------------------------------------------------------------

_RATE_LIMIT_WAIT_CAP = 120.0  # never sleep more than 2 minutes
_RATE_LIMIT_JITTER   =   2.0  # ± seconds of random jitter added to every sleep


def _llm_invoke_with_backoff(llm: ChatGroq, messages: list, max_attempts: int = 3):
    """
    Invoke *llm* with *messages* using Retry-After-based back-off.

    On a Groq 429 RateLimitError the helper:
      1. Tries the *next* API key in the pool (if one exists) before sleeping.
         This immediately unblocks requests if the first account's TPM budget
         is exhausted but another account still has headroom.
      2. If no fresh key is available, parses the server-suggested wait time
         from the Groq error body — e.g. ``'Please try again in 8.85s.'`` —
         adds a fixed 2 s buffer plus ±2 s random jitter (to reduce thundering-
         herd collisions when Sigma and KQL retry simultaneously), then sleeps.
      3. If the error message does not contain the expected ``try again in Xs``
         string (e.g. a proxy timeout or a future Groq format change), falls
         back to a fixed 20 s delay so the function degrades gracefully rather
         than crashing.

    All other (non-rate-limit) exceptions are re-raised immediately.

    Args:
        llm:          A configured ``ChatGroq`` instance used for the *first*
                      attempt.  Subsequent attempts may switch to a different
                      API key from the pool.
        messages:     List of ``SystemMessage``/``HumanMessage`` objects.
        max_attempts: Maximum total call attempts across all keys (default: 3).

    Returns:
        The LLM response object returned by ``llm.invoke()``.

    Raises:
        Exception: Re-raises the last rate-limit exception when all attempts
                   across all keys are exhausted, or any non-rate-limit
                   exception on first occurrence.
    """
    # _rate_limit_sleep_total and _current_key_idx are written under their
    # respective locks inside _llm_invoke_with_backoff; reads of the int
    # _current_key_idx here are CPython-atomic and need no lock.
    global _rate_limit_sleep_total

    # Key-rotation is a Groq-specific feature (multiple GROQ_API_KEY_* accounts).
    # OpenRouter and Cerebras use a single key — skip rotation for those providers.
    is_groq = isinstance(llm, ChatGroq)

    pool = _get_key_pool() if is_groq else []
    # Snapshot the current key index once at entry.  This is a read-only
    # snapshot: the branch never writes _current_key_idx mid-flight.
    # The write happens inside the lock only on success (see below).
    # groq_api_key is a Pydantic SecretStr; unwrap before comparing against pool.
    if is_groq:
        try:
            raw_key = llm.groq_api_key.get_secret_value()
            start_idx = pool.index(raw_key)
        except (ValueError, AttributeError):
            start_idx = _current_key_idx % max(len(pool), 1)  # atomic CPython read
    else:
        start_idx = 0

    current_key_idx = start_idx

    model = os.getenv("GROQ_MODEL", "qwen/qwen3.6-27b")  # only used for Groq key rotation
    temperature = llm.temperature  # preserve caller's temperature
    active_llm = llm

    last_exc: Exception | None = None
    for attempt in range(max_attempts):
        try:
            resp = active_llm.invoke(messages)
            # Persist the winning key index for the next pipeline request.
            # Lock required: two parallel branches (Sigma, KQL) can both
            # succeed near-simultaneously and write this global from separate
            # threads. Without the lock the later write clobbers the earlier
            # one silently (lost update). The lock is uncontended on the fast
            # path (no rate limiting) so the overhead is negligible.
            with _key_idx_lock:
                _current_key_idx = current_key_idx
            return resp
        except Exception as exc:
            exc_str = str(exc)
            # Detect Groq 429 / rate-limit errors
            is_rate_limit = (
                "rate_limit_exceeded" in exc_str
                or "RateLimitError" in type(exc).__name__
                or ("429" in exc_str and "rate" in exc_str.lower())
            )
            if not is_rate_limit:
                raise  # non-recoverable — propagate immediately

            last_exc = exc

            # ── Strategy 0: Cerebras context/payment error → fallback to OpenRouter ──
            # Cerebras free tier caps context at 8k tokens. If the document is
            # too large (413/402/context_length_exceeded), transparently switch
            # to the OpenRouter free router which supports up to 1M token context.
            is_cerebras = (
                isinstance(active_llm, ChatOpenAI)
                and not is_groq
                and "api.cerebras.ai" in str(getattr(active_llm, "openai_api_base", ""))
                    or (hasattr(active_llm, "base_url")
                        and "cerebras" in str(active_llm.base_url))
            )
            exc_str_lower = exc_str.lower()
            is_context_error = (
                "402" in exc_str
                or "413" in exc_str
                or "payment_required" in exc_str_lower
                or "context_length_exceeded" in exc_str_lower
                or "context window" in exc_str_lower
                or "too large" in exc_str_lower
                or "max_tokens" in exc_str_lower
            )
            if is_cerebras and is_context_error:
                fallback = _get_openrouter_llm(temperature)
                if fallback is not None:
                    logger.warning(
                        "[LLM] Cerebras context/payment limit hit — failing over to OpenRouter "
                        "(attempt %d/%d).",
                        attempt + 1, max_attempts,
                    )
                    active_llm = fallback
                    continue  # retry with OpenRouter immediately
                raise  # no fallback available

            # ── Strategy 1: rotate to the next available API key (Groq only) ───────
            if is_groq:
                next_key_idx = (current_key_idx + 1) % max(len(pool), 1)
                if next_key_idx != start_idx and len(pool) > 1:
                    current_key_idx = next_key_idx
                    active_llm = ChatGroq(
                        api_key=pool[current_key_idx],
                        model_name=model,
                        temperature=temperature,
                    )
                    logger.warning(
                        "[LLM] Rate limit on key #%d. Rotating to key #%d (attempt %d/%d).",
                        (current_key_idx - 1) % len(pool) + 1, current_key_idx + 1,
                        attempt + 1, max_attempts,
                    )
                    continue  # retry immediately with the new key — no sleep needed

            # ── Strategy 2: all keys exhausted — sleep using Retry-After ─────
            # Primary: parse the server-suggested wait time, e.g.
            #   "Please try again in 8.85s."
            # Fallback: 20 s if the error body has an unexpected format
            # (proxy timeout, future Groq schema change, etc.).
            _FALLBACK_WAIT = 20.0
            wait_s: float = _FALLBACK_WAIT
            retry_match = re.search(r"try again in ([\d.]+)s", exc_str)
            if retry_match:
                wait_s = min(float(retry_match.group(1)) + 2.0, _RATE_LIMIT_WAIT_CAP)
            # Add ±jitter to reduce thundering-herd when Sigma and KQL
            # back off simultaneously after hitting the same TPM ceiling.
            jitter = random.uniform(-_RATE_LIMIT_JITTER, _RATE_LIMIT_JITTER)
            wait_s = max(1.0, wait_s + jitter)

            # Guard += with a lock: float read-modify-write is not atomic;
            # two threads accumulating simultaneously would produce a lost update.
            with _sleep_total_lock:
                _rate_limit_sleep_total += wait_s  # tracked for eval honesty
            logger.warning(
                "[LLM] All %d key(s) rate-limited (attempt %d/%d). "
                "Sleeping %.1fs (Retry-After%s).",
                len(pool), attempt + 1, max_attempts, wait_s,
                "=parsed" if retry_match else "=fallback",
            )
            time.sleep(wait_s)

    # All attempts exhausted across all keys
    raise last_exc


# ---------------------------------------------------------------------------
# JSON extraction helper
# ---------------------------------------------------------------------------

def _extract_json_from_llm_response(raw: str) -> dict:
    """
    Robustly extract a JSON object from an LLM response string.

    Tries four strategies in order:
      0. Strip <think>...</think> reasoning blocks emitted by thinking models
         (Qwen3, DeepSeek-R1, etc.) before any other processing.
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

    # Strategy 0: strip <think>...</think> blocks emitted by reasoning/thinking
    # models (Qwen3-27b, DeepSeek-R1, etc.).  These models wrap their chain-of-
    # thought in <think> tags before producing the actual output.  Without this
    # step, Strategy 3's brace search latches onto a '{' inside the think block
    # (e.g. from the JSON schema example in the system prompt) rather than the
    # real output JSON, causing all non-adversarial fixtures to fail with
    # "No valid JSON object found".
    think_stripped = re.sub(r"<think>[\s\S]*?</think>", "", text, flags=re.IGNORECASE).strip()
    if think_stripped:  # only use stripped version if something remains
        text = think_stripped

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

    # Strategy 4: repair truncated JSON
    # The model hit its output-token limit mid-stream, leaving an unclosed JSON
    # object (e.g. a long malware_families array cut off before the closing ]).
    # We attempt to close any open brackets/braces so json.loads can succeed.
    # Only values already emitted are kept; nothing is fabricated.
    brace_start = text.find("{")
    if brace_start != -1:
        partial = text[brace_start:].rstrip()
        # Remove any trailing incomplete token (unterminated string or comma)
        partial = re.sub(r',\s*$', '', partial)          # trailing comma
        partial = re.sub(r',\s*"[^"]*$', '', partial)   # trailing partial key
        partial = re.sub(r':\s*"[^"]*$', '', partial)   # trailing partial value string
        partial = re.sub(r':\s*\[[^\]]*$', ': []', partial)  # truncated array → empty
        # Count open brackets/braces and close them
        depth_brace  = partial.count('{') - partial.count('}')
        depth_bracket = partial.count('[') - partial.count(']')
        closing = ']' * max(depth_bracket, 0) + '}' * max(depth_brace, 0)
        repaired = partial + closing
        try:
            parsed = json.loads(repaired)
            import logging as _logging
            _logging.getLogger(__name__).warning(
                "[JSON] Response was truncated mid-stream; repaired %d open bracket(s). "
                "Some list values may be incomplete.",
                max(depth_bracket, 0) + max(depth_brace, 0),
            )
            return parsed
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

        response = _llm_invoke_with_backoff(llm, messages)
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

        response = _llm_invoke_with_backoff(llm, messages)
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
# Node 3a: Sigma rule generation
# ---------------------------------------------------------------------------

MAX_SIGMA_RETRIES = 2


def generate_sigma(state: ThreatIntelState) -> ThreatIntelState:
    """
    Node 3a — Generate a Sigma rule from the extracted threat intel.

    Uses the TTP→logsource routing map to select the appropriate Sigma
    logsource category/product before calling the LLM. This means logsource
    is a parameter derived from intelligence, not a hardcoded assumption.

    Runs a single correction pass on validation failure (max MAX_SIGMA_RETRIES).

    NOTE — parallel fan-out contract:
      This node runs concurrently with generate_kql (both fan out from
      contextualize_with_rag). LangGraph merges the outputs of both branches
      at the join node. To avoid INVALID_CONCURRENT_GRAPH_UPDATE every return
      must yield ONLY the keys this node owns ('sigma_rule',
      'sigma_generation_error'). Spreading **state would cause LangGraph to
      see two values for every shared key (raw_text, extracted_report, …)
      and raise a merge conflict.

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
            sigma_draft = sval.extract_sigma_from_response(response.content)
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


# ---------------------------------------------------------------------------
# Node 3b: KQL (Microsoft Sentinel) query generation
# ---------------------------------------------------------------------------


def generate_kql(state: ThreatIntelState) -> ThreatIntelState:
    """
    Node 3b — Generate a Microsoft Sentinel KQL detection query.

    Uses the same TTP→logsource routing map to select SecurityEvent vs.
    CommonSecurityLog, mirroring the Sigma logsource split so both generators
    stay in sync when new TTP mappings are added.

    No retry loop — KQL syntax is simpler and LLMs get it right first-pass
    more reliably than YARA-L or Sigma YAML.

    NOTE — parallel fan-out contract:
      This node runs concurrently with generate_sigma (both fan out from
      contextualize_with_rag). Every return must yield ONLY the keys this node
      owns ('kql_query', 'kql_generation_error'). Spreading **state would
      cause LangGraph to see two values for every shared key and raise
      INVALID_CONCURRENT_GRAPH_UPDATE at the fan-in join.

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
        kql_raw = response.content.strip()
        fence_match = __import__("re").search(
            r"```(?:kql|kusto|text|plaintext)?\s*\n?(.*?)```", kql_raw, __import__("re").DOTALL | __import__("re").IGNORECASE
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


# ---------------------------------------------------------------------------
# Node 0.5 (ES path): Query Elasticsearch logs
# ---------------------------------------------------------------------------

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

    logger.info("[Node 0.5/ES] Querying Elasticsearch: index=%s, size=%d, query=%r", index, size, query)

    try:
        from api.es_client import search_logs
        events = search_logs(query=query, index=index, size=size)
        logger.info("[Node 0.5/ES] Retrieved %d log events.", len(events))
        return {**state, "log_events": events}
    except Exception as exc:
        msg = f"Elasticsearch query failed: {type(exc).__name__}: {exc}"
        logger.exception("[Node 0.5/ES] %s", msg)
        return {**state, "log_events": [], "pipeline_error": msg}


# ---------------------------------------------------------------------------
# Node 1 (ES path): Synthesize threat intel from log events
# ---------------------------------------------------------------------------

def synthesize_from_logs(state: ThreatIntelState) -> ThreatIntelState:
    """
    Node 1 (ES path) — Synthesize structured threat intel from raw log events.

    Feeds the raw Elasticsearch log events (stored as a JSON array) to the LLM
    using the ES synthesis prompt. Extracts the same ThreatIntelReport schema
    as extract_threat_intel, so the downstream RAG → YARA-L pipeline is
    completely unchanged.

    Args:
        state: Current graph state. Expects 'log_events' to be populated.

    Returns:
        Updated state with 'extracted_report' or 'extraction_error' populated.
    """
    logger.info("[Node 1/ES] Synthesizing threat intel from %d log events...", len(state.get("log_events") or []))

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
            logger.warning("[Node 1/ES] Truncating log events from %d to %d for LLM context.", len(events), max_events)
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
        raw_response = response.content.strip()
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


def _route_entry_point(state: ThreatIntelState) -> str:
    """
    Router function at the graph entry point.

    Dispatches to the correct first node based on input_type:
      - "log_query"    → query_elasticsearch_logs (ES path)
      - "text_report"  → scan_for_injection        (default text path)
    """
    if state.get("input_type") == "log_query":
        logger.info("[Router] input_type=log_query → ES pipeline path.")
        return "query_elasticsearch_logs"
    logger.info("[Router] input_type=text_report → text pipeline path.")
    return "scan_for_injection"


def _route_after_es_query(state: ThreatIntelState) -> str:
    """
    Router function called after query_elasticsearch_logs.

    Returns:
        'synthesize_from_logs' if events were retrieved.
        'finalize' if the ES query failed.
    """
    if state.get("pipeline_error"):
        return "finalize"
    return "synthesize_from_logs"


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

    Graph topology (two entry paths):

      [TEXT REPORT PATH]
      entry_router ──(text_report)──► scan_for_injection (Node 0)
                                            ↓ (safe)
                                      extract_threat_intel (Node 1)
                                            ↓ (success)
                                           ┐
      [ES LOG QUERY PATH]                  │
      entry_router ──(log_query)──► query_elasticsearch_logs (Node 0.5)
                                            ↓
                                      synthesize_from_logs (Node 1.5)
                                            ↓
                                           ┘
                                      contextualize_with_rag (Node 2)
                                            │
                              ┌─────────────┴─────────────┐
                              ▼                           ▼
                        generate_sigma (Node 3a)   generate_kql (Node 3b)
                              │    [parallel fan-out]     │
                              └─────────────┬─────────────┘
                                            │ (fan-in join)
                                            ▼
                                      generate_yaral (Node 3c) ◄───┐
                                            ↓                      │
                                      validate_yaral (Node 4) ─(fail)┘
                                            ↓ (pass or exhausted)
                                         finalize (Node 5)
                                            ↓
                                           END

    Rate-limit note: extract_threat_intel (Node 1) is the largest single
    LLM call (~2 500 tokens requested for a dense fixture). Sigma and KQL
    then fire concurrently against whatever TPM headroom remains. Both nodes
    now use _llm_invoke_with_backoff, which rotates through the API key pool
    before sleeping so a rate-limit on one account does not stall the pipeline.

    Returns:
        A compiled LangGraph CompiledGraph ready for invocation.
    """
    workflow = StateGraph(ThreatIntelState)

    # ── Register all nodes ──────────────────────────────────────────────────
    # Shared entry router (virtual start node)
    workflow.add_node("entry_router_node", lambda s: s)  # pass-through; routing done by conditional edge

    # Text-report path
    workflow.add_node("scan_for_injection", scan_for_injection)         # Node 0
    workflow.add_node("extract_threat_intel", extract_threat_intel)     # Node 1

    # ES log-query path
    workflow.add_node("query_elasticsearch_logs", query_elasticsearch_logs)  # Node 0.5
    workflow.add_node("synthesize_from_logs", synthesize_from_logs)          # Node 1.5

    # Shared downstream pipeline
    workflow.add_node("contextualize_with_rag", contextualize_with_rag)  # Node 2
    workflow.add_node("generate_sigma", generate_sigma)                  # Node 3a
    workflow.add_node("generate_kql", generate_kql)                      # Node 3b
    workflow.add_node("generate_yaral", generate_yaral)                  # Node 3c
    workflow.add_node("validate_yaral", validate_yaral)                  # Node 4
    workflow.add_node("finalize", finalize)                              # Node 5

    # ── Entry point: dispatch to correct first node based on input_type ─────
    workflow.set_entry_point("entry_router_node")
    workflow.add_conditional_edges(
        "entry_router_node",
        _route_entry_point,
        {
            "scan_for_injection":        "scan_for_injection",
            "query_elasticsearch_logs":  "query_elasticsearch_logs",
        },
    )

    # ── Text-report path edges ───────────────────────────────────────────────
    workflow.add_conditional_edges(
        "scan_for_injection",
        _route_after_scan,
        {
            "extract_threat_intel": "extract_threat_intel",
            "finalize": "finalize",
        },
    )
    workflow.add_conditional_edges(
        "extract_threat_intel",
        _route_after_extraction,
        {
            "contextualize_with_rag": "contextualize_with_rag",
            "finalize": "finalize",
        },
    )

    # ── ES log-query path edges ──────────────────────────────────────────────
    workflow.add_conditional_edges(
        "query_elasticsearch_logs",
        _route_after_es_query,
        {
            "synthesize_from_logs": "synthesize_from_logs",
            "finalize": "finalize",
        },
    )
    workflow.add_conditional_edges(
        "synthesize_from_logs",
        _route_after_extraction,  # same router — checks extraction_error
        {
            "contextualize_with_rag": "contextualize_with_rag",
            "finalize": "finalize",
        },
    )

    # -- Shared downstream edges -----------------------------------------------
    # Sigma and KQL are independent of each other -- both only need the
    # extracted_report from RAG. Fan them out in parallel so they run
    # concurrently, then join at generate_yaral before the retry loop.
    #
    # Graph topology:
    #   contextualize_with_rag --+-- generate_sigma --+-- generate_yaral --> validate_yaral
    #                            +-- generate_kql   --+        ^                    |
    #                                                          | (retry)            |
    #                                                          +--------------------+
    #
    # LangGraph fan-in semantics: generate_yaral waits for ALL nodes that
    # triggered it in the SAME step. On the initial run that's both
    # generate_sigma and generate_kql. On retry it's only validate_yaral
    # (sigma/kql are already done), so no extra waiting occurs.
    workflow.add_edge("contextualize_with_rag", "generate_sigma")   # parallel fan-out
    workflow.add_edge("contextualize_with_rag", "generate_kql")     # parallel fan-out
    workflow.add_edge("generate_sigma", "generate_yaral")           # join (waits for both)
    workflow.add_edge("generate_kql", "generate_yaral")             # join
    workflow.add_edge("generate_yaral", "validate_yaral")
    workflow.add_conditional_edges(
        "validate_yaral",
        _route_after_validation,
        {
            "generate_yaral": "generate_yaral",
            "finalize": "finalize",
        },
    )
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
    global _rate_limit_sleep_total
    _rate_limit_sleep_total = 0.0  # reset accumulator for this run

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
    result: ThreatIntelState = _graph.invoke(initial_state)
    result["rate_limit_sleep_s"] = round(_rate_limit_sleep_total, 2)
    if _rate_limit_sleep_total > 0:
        logger.info(
            "Pipeline finished. Total rate-limit sleep: %.1fs.",
            _rate_limit_sleep_total,
        )
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

    This is the new log-query entry point (Step 2 of the upgrade plan).
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

    global _rate_limit_sleep_total
    _rate_limit_sleep_total = 0.0  # reset accumulator for this run
    logger.info("Starting Agentic-CTI ES log-query pipeline... query=%r, index=%s, size=%d", query, index, size)
    result: ThreatIntelState = _graph.invoke(initial_state)
    result["rate_limit_sleep_s"] = round(_rate_limit_sleep_total, 2)
    if _rate_limit_sleep_total > 0:
        logger.info("ES pipeline finished. Total rate-limit sleep: %.1fs.", _rate_limit_sleep_total)
    else:
        logger.info("ES pipeline finished.")
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
