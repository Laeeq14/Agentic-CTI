"""
src/llm/factory.py — LLM provider detection and instantiation.

Chooses a LangChain chat-model based on which API keys are present
in the environment (or the explicit LLM_PROVIDER override), and
returns a configured instance ready for invocation.

Provider priority (auto-detection):
  1. Gemini     — Google AI Studio free tier; 1M token context; native JSON mode.
  2. Cerebras   — Blazing-fast inference; 65k context; free tier.
  3. OpenRouter — Free-tier router to many models; up to 1M token context.
  4. Groq       — Default; free tier limited to 8k TPM per request.
"""

import logging
import os

from dotenv import load_dotenv
from langchain_groq import ChatGroq
from langchain_google_genai import ChatGoogleGenerativeAI
from langchain_openai import ChatOpenAI

load_dotenv()
logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Provider constants
# ---------------------------------------------------------------------------

PROVIDER_GEMINI     = "gemini"
PROVIDER_CEREBRAS   = "cerebras"
PROVIDER_OPENROUTER = "openrouter"
PROVIDER_GROQ       = "groq"


# ---------------------------------------------------------------------------
# Provider detection
# ---------------------------------------------------------------------------

def _detect_provider() -> str:
    """
    Choose an LLM provider based on which API key is present.

    Priority (auto-detection order):
      1. Gemini     — Google AI Studio free tier, 1M token context, native JSON.
      2. Cerebras   — blazing-fast inference, 65k context, free tier.
      3. OpenRouter  — free tier access to many models, large context.
      4. Groq        — default; free tier limited to 8k TPM per request.

    Override by setting LLM_PROVIDER=gemini|groq|openrouter|cerebras explicitly.
    """
    explicit = os.getenv("LLM_PROVIDER", "").strip().lower()
    if explicit in (PROVIDER_GEMINI, PROVIDER_CEREBRAS, PROVIDER_OPENROUTER, PROVIDER_GROQ):
        return explicit
    if os.getenv("GEMINI_API_KEY"):
        return PROVIDER_GEMINI
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

    Provider priority: Gemini → Cerebras → OpenRouter → Groq.
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

    if provider == PROVIDER_GEMINI:
        api_key = os.getenv("GEMINI_API_KEY")
        if not api_key:
            raise EnvironmentError("GEMINI_API_KEY not set.")
        model = os.getenv("GEMINI_MODEL", "gemini-3.5-flash")
        logger.info("[LLM] Provider=Gemini model=%s", model)
        return ChatGoogleGenerativeAI(
            model=model,
            google_api_key=api_key,
            temperature=temperature,
        )

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
            "No LLM API key found. Set GEMINI_API_KEY, GROQ_API_KEY, "
            "OPENROUTER_API_KEY, or CEREBRAS_API_KEY in your .env file."
        )
    model = os.getenv("GROQ_MODEL", "openai/gpt-oss-120b")
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
    model = os.getenv("OPENROUTER_MODEL", "qwen/qwen2.5-72b-instruct:free")
    logger.info("[LLM] Provider=OpenRouter model=%s", model)
    return ChatOpenAI(
        api_key=api_key,
        base_url="https://openrouter.ai/api/v1",
        model=model,
        temperature=temperature,
        max_tokens=16384,
        timeout=90,
        model_kwargs={"response_format": {"type": "json_object"}},
        default_headers={
            "HTTP-Referer": "https://github.com/Laeeq14/Agentic-CTI",
            "X-Title": "Agentic-CTI",
        },
    )
