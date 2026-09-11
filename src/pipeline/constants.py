"""
src/pipeline/constants.py — Pipeline-wide tuneable constants.

Centralises the magic numbers that multiple nodes and the runner
share, so changing a value here propagates everywhere automatically.
"""

# Maximum YARA-L generation+correction attempts before the pipeline gives up.
MAX_RETRIES: int = 3

# Maximum Sigma rule generation+correction attempts.
MAX_SIGMA_RETRIES: int = 2

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
MAX_INPUT_CHARS: int = 100_000
