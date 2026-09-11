"""
agent.py — Backwards-compatibility shim.

The pipeline has been refactored into focused modules:
  src/models/   — Pydantic schemas and LangGraph state
                  (IOCBundle, ThreatIntelReport, ThreatIntelState)
  src/llm/      — LLM provider factory (factory.py) and
                  rate-limit / backoff logic (rate_limit.py)
  src/pipeline/ — Nodes, routers, graph construction, and
                  public runner functions

This module re-exports the public API so all existing callers
(app.py, api/, tests/, evals/, src/ingestion/watcher.py) continue to
work without any changes.
"""

# Public API — re-exported for backwards compatibility
from src.models.schemas import (  # noqa: F401
    IOCBundle,
    ThreatIntelReport,
    ThreatIntelState,
)
from src.pipeline.constants import MAX_INPUT_CHARS, MAX_RETRIES  # noqa: F401
from src.pipeline.runner import run_pipeline, run_pipeline_from_logs  # noqa: F401


# ---------------------------------------------------------------------------
# Quick self-test (run: python agent.py)
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    import json
    import logging

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
