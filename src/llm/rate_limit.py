"""
src/llm/rate_limit.py — API key pool, backoff logic, and LLM response helpers.

Responsibilities:
  - _load_api_key_pool / _get_key_pool  : load multiple Groq keys from env.
  - _llm_invoke_with_backoff            : Retry-After-based invocation with
                                          key rotation and provider fallback.
  - _get_response_text                  : normalise LLM response content to str.
  - _extract_json_from_llm_response     : robustly parse JSON from LLM output.
  - reset_sleep_total / get_sleep_total : per-run rate-limit telemetry.
"""

import json
import logging
import os
import random
import re
import threading
import time

from langchain_groq import ChatGroq
from langchain_google_genai import ChatGoogleGenerativeAI

from src.llm.factory import _get_openrouter_llm

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Rate-limit tuning
# ---------------------------------------------------------------------------

_RATE_LIMIT_WAIT_CAP = 120.0  # never sleep more than 2 minutes
_RATE_LIMIT_JITTER   =   2.0  # ± seconds of random jitter added to every sleep

# ---------------------------------------------------------------------------
# API key pool — rotated on per-account rate-limit exhaustion
# ---------------------------------------------------------------------------

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
_key_idx_lock: threading.Lock    = threading.Lock()   # guards writes to _current_key_idx
_sleep_total_lock: threading.Lock = threading.Lock()  # guards += on _rate_limit_sleep_total


# ---------------------------------------------------------------------------
# Sleep-total telemetry accessors
# ---------------------------------------------------------------------------

def reset_sleep_total() -> None:
    """Reset the per-run sleep accumulator. Call at the start of each pipeline run."""
    global _rate_limit_sleep_total
    _rate_limit_sleep_total = 0.0


def get_sleep_total() -> float:
    """Return the total seconds slept on rate limits for the current run."""
    return _rate_limit_sleep_total


# ---------------------------------------------------------------------------
# Key pool helpers
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


def _get_key_pool() -> list[str]:
    """Return the key pool, initialising it from the environment if needed."""
    global _API_KEY_POOL
    if not _API_KEY_POOL:
        _API_KEY_POOL = _load_api_key_pool()
    return _API_KEY_POOL


# ---------------------------------------------------------------------------
# Retry-After-based LLM invocation helper
# ---------------------------------------------------------------------------

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

    model = os.getenv("GROQ_MODEL", "openai/gpt-oss-120b")  # only used for Groq key rotation
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

            # ── Strategy 0a: Gemini daily quota exhausted → OpenRouter fallback ────
            # Gemini free tier caps at 20 RPD per model. When RESOURCE_EXHAUSTED
            # hits a *daily* quota ID (not per-minute), sleeping is useless —
            # the quota won't reset for hours. Immediately fall over to OpenRouter
            # (which routes through Google models with a separate quota pool).
            # Detection: "RESOURCE_EXHAUSTED" + daily quota dimension.
            is_gemini = type(active_llm).__name__ == "ChatGoogleGenerativeAI"
            is_daily_quota = (
                "RESOURCE_EXHAUSTED" in exc_str
                and (
                    "PerDay" in exc_str
                    or "per_day" in exc_str.lower()
                    or "GenerateRequestsPerDay" in exc_str
                    or "free_tier" in exc_str.lower()
                )
            )

            if is_gemini and is_daily_quota:
                # First try GEMINI_FALLBACK_MODEL (e.g. gemini-3.5-flash-lite)
                # which has a separate daily quota from the primary model.
                fallback_model = os.getenv("GEMINI_FALLBACK_MODEL", "").strip()
                current_model = os.getenv("GEMINI_MODEL", "gemini-3.5-flash")
                api_key = os.getenv("GEMINI_API_KEY", "")
                if fallback_model and fallback_model != current_model and api_key:
                    logger.warning(
                        "[LLM] Gemini daily quota exhausted for '%s'. "
                        "Switching to GEMINI_FALLBACK_MODEL='%s' (attempt %d/%d).",
                        current_model, fallback_model, attempt + 1, max_attempts,
                    )
                    active_llm = ChatGoogleGenerativeAI(
                        model=fallback_model,
                        google_api_key=api_key,
                        temperature=temperature,
                    )
                    continue  # retry immediately with fallback model

                # No within-Gemini fallback available — try OpenRouter next.
                openrouter_fallback = _get_openrouter_llm(temperature)
                if openrouter_fallback is not None:
                    logger.warning(
                        "[LLM] Gemini daily quota exhausted and no GEMINI_FALLBACK_MODEL set. "
                        "Failing over to OpenRouter (attempt %d/%d).",
                        attempt + 1, max_attempts,
                    )
                    active_llm = openrouter_fallback
                    continue  # retry immediately with OpenRouter

                # No fallbacks at all — re-raise so the node captures the error.
                raise

            # ── Strategy 0b: Cerebras context/payment error → fallback to OpenRouter ──
            # Cerebras free tier caps context at 8k tokens. If the document is
            # too large (413/402/context_length_exceeded), transparently switch
            # to the OpenRouter free router which supports up to 1M token context.
            is_cerebras = (
                not isinstance(active_llm, ChatGroq)
                and (
                    "api.cerebras.ai" in str(getattr(active_llm, "openai_api_base", ""))
                    or (
                        hasattr(active_llm, "base_url")
                        and "cerebras" in str(active_llm.base_url)
                    )
                )
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
# Response content normalizer
# ---------------------------------------------------------------------------

def _get_response_text(response) -> str:
    """
    Safely extract the text content from an LLM response.

    Different LangChain providers return ``response.content`` in different
    formats:
      - ChatGroq / ChatOpenAI: plain string
      - ChatGoogleGenerativeAI (Gemini 3.5 Flash with thinking enabled):
        a list of part-dicts, e.g.
          [{'type': 'thinking', 'thinking': '...'}, {'type': 'text', 'text': '...'}]
        or simply [{'type': 'text', 'text': '...'}]

    This helper normalises both into a single string so the rest of the
    pipeline can call ``.strip()`` and ``json.loads()`` safely.
    """
    content = response.content
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts = []
        for part in content:
            if isinstance(part, str):
                parts.append(part)
            elif isinstance(part, dict):
                # Gemini thinking blocks: skip 'thinking' parts, keep 'text'
                text = part.get("text") or part.get("content", "")
                if text:
                    parts.append(str(text))
        return "".join(parts)
    return str(content)


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
      4. Repair truncated JSON by closing open brackets/braces.

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
        depth_brace   = partial.count('{') - partial.count('}')
        depth_bracket = partial.count('[') - partial.count(']')
        closing = ']' * max(depth_bracket, 0) + '}' * max(depth_brace, 0)
        repaired = partial + closing
        try:
            parsed = json.loads(repaired)
            logger.warning(
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
