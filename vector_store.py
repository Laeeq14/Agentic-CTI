"""
vector_store.py — Qdrant vector store layer for Agentic-CTI RAG.

This module manages a local Qdrant collection that stores historical threat
intelligence reports as vector embeddings. At query time it retrieves the
most similar past reports to provide contextual grounding for YARA-L generation.

Embeddings are generated locally via sentence-transformers (all-MiniLM-L6-v2),
requiring no external API key.
"""

import json
import logging
import os
import uuid
from typing import Any

from pydantic import BaseModel
from qdrant_client import QdrantClient
from qdrant_client.models import (
    Distance,
    PointStruct,
    VectorParams,
)
from sentence_transformers import SentenceTransformer

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

COLLECTION_NAME = "threat_intel"
EMBEDDING_MODEL = "all-MiniLM-L6-v2"
VECTOR_SIZE = 384  # Dimension of all-MiniLM-L6-v2 output
TOP_K = 3          # Number of similar results to retrieve


# ---------------------------------------------------------------------------
# Singleton wrappers (lazy-init, cached per process)
# ---------------------------------------------------------------------------

# Default local persistence path — survives module reloads and process restarts.
# Override by setting QDRANT_PATH=:memory: in .env for ephemeral mode.
_DEFAULT_QDRANT_PATH = "./qdrant_local_db"

_client: QdrantClient | None = None
_encoder: SentenceTransformer | None = None


def set_singletons(client: QdrantClient, encoder: SentenceTransformer) -> None:
    """
    Inject pre-created Qdrant client and encoder singletons into this module.

    Called from app.py's @st.cache_resource initializer so that Streamlit
    keeps the objects alive across reruns — even when the module is reloaded
    by Streamlit's file watcher.

    Args:
        client: A fully initialized QdrantClient instance.
        encoder: A fully loaded SentenceTransformer instance.
    """
    global _client, _encoder
    _client = client
    _encoder = encoder
    logger.info("Singletons injected from external cache.")


def _get_client() -> QdrantClient:
    """
    Return a singleton Qdrant client.

    Connection priority order:
    1. An externally injected client (via set_singletons).
    2. QDRANT_URL env var: connects to a remote Qdrant service (Docker networking).
    3. QDRANT_PATH env var / default local path: uses embedded local storage.

    Set QDRANT_URL=http://qdrant:6333 in docker-compose.yml for containerised use.
    Set QDRANT_PATH=:memory: in .env for ephemeral in-process mode.
    """
    global _client
    if _client is None:
        qdrant_url = os.getenv("QDRANT_URL")
        if qdrant_url:
            logger.info("Connecting to remote Qdrant at: %s", qdrant_url)
            _client = QdrantClient(url=qdrant_url)
        else:
            qdrant_path = os.getenv("QDRANT_PATH", _DEFAULT_QDRANT_PATH)
            if qdrant_path == ":memory:":
                logger.info("Initializing in-memory Qdrant instance (ephemeral).")
                _client = QdrantClient(":memory:")
            else:
                logger.info("Initializing persistent Qdrant at: %s", qdrant_path)
                _client = QdrantClient(path=qdrant_path)
    return _client


def _get_encoder() -> SentenceTransformer:
    """Return a singleton SentenceTransformer encoder (downloads on first call)."""
    global _encoder
    if _encoder is None:
        logger.info("Loading sentence-transformer model: %s", EMBEDDING_MODEL)
        _encoder = SentenceTransformer(EMBEDDING_MODEL)
    return _encoder


# ---------------------------------------------------------------------------
# Collection management
# ---------------------------------------------------------------------------

def initialize_collection() -> None:
    """
    Ensure the Qdrant collection exists and is ready to accept vectors.

    Safe to call multiple times — idempotent. Creates the collection only
    if it does not already exist.
    """
    client = _get_client()
    existing = {c.name for c in client.get_collections().collections}
    if COLLECTION_NAME not in existing:
        client.create_collection(
            collection_name=COLLECTION_NAME,
            vectors_config=VectorParams(
                size=VECTOR_SIZE,
                distance=Distance.COSINE,
            ),
        )
        logger.info("Created Qdrant collection: %s", COLLECTION_NAME)
    else:
        logger.info("Qdrant collection already exists: %s", COLLECTION_NAME)


# ---------------------------------------------------------------------------
# Ingestion
# ---------------------------------------------------------------------------

def _build_report_summary(report: "Any") -> str:
    """
    Build a human-readable summary string from a ThreatIntelReport for embedding.

    We embed a summary rather than raw JSON to produce better semantic vectors.
    Handles iocs as either a Pydantic model (IOCBundle) or a plain dict.
    """
    iocs = report.iocs
    # IOCBundle is a Pydantic model — use attribute access, not dict .get()
    if hasattr(iocs, "ips"):
        all_iocs = (
            list(iocs.ips or [])
            + list(iocs.domains or [])
            + list(iocs.hashes or [])
        )
    else:
        # Fallback: treat as plain dict (e.g., from serialized payloads)
        all_iocs = (
            iocs.get("ips", []) + iocs.get("domains", []) + iocs.get("hashes", [])
        )
    summary = (
        f"Threat actor: {report.threat_actor}. "
        f"Malware families: {', '.join(report.malware_families) or 'none'}. "
        f"MITRE TTPs: {', '.join(report.mitre_ttps) or 'none'}. "
        f"IOCs: {', '.join(all_iocs[:10]) or 'none'}."
    )
    return summary


def add_report(report: "Any", source_text: str = "") -> str:
    """
    Embed and upsert a ThreatIntelReport into the Qdrant collection.

    Args:
        report: A ThreatIntelReport Pydantic model instance.
        source_text: Optional raw source text to store as payload metadata.

    Returns:
        The UUID string of the inserted point.
    """
    initialize_collection()
    encoder = _get_encoder()
    client = _get_client()

    summary = _build_report_summary(report)
    vector = encoder.encode(summary, normalize_embeddings=True).tolist()

    point_id = str(uuid.uuid4())
    payload: dict[str, Any] = {
        "threat_actor": report.threat_actor,
        "malware_families": report.malware_families,
        "mitre_ttps": report.mitre_ttps,
        "iocs": report.iocs,
        "summary": summary,
        "source_text_snippet": source_text[:500] if source_text else "",
    }

    client.upsert(
        collection_name=COLLECTION_NAME,
        points=[PointStruct(id=point_id, vector=vector, payload=payload)],
    )
    logger.info("Upserted report for threat actor '%s' (id=%s)", report.threat_actor, point_id)
    return point_id


# ---------------------------------------------------------------------------
# Retrieval
# ---------------------------------------------------------------------------

def query_similar(report: "Any") -> dict[str, Any]:
    """
    Query Qdrant for reports semantically similar to the given ThreatIntelReport.

    The query vector is derived from a human-readable summary of the report,
    matching the approach used during ingestion for consistency.

    Args:
        report: A ThreatIntelReport Pydantic model instance.

    Returns:
        A dict with keys:
          - 'matches': list of dicts, each with 'score', 'threat_actor',
            'mitre_ttps', 'malware_families', 'summary'.
          - 'top_similarity_score': float in [0.0, 1.0], 0.0 if no results.
          - 'collection_size': int, current number of points in the collection.
    """
    initialize_collection()
    encoder = _get_encoder()
    client = _get_client()

    # Check collection size; if empty return a graceful no-match result
    collection_info = client.get_collection(COLLECTION_NAME)
    count = collection_info.points_count or 0

    if count == 0:
        logger.info("Qdrant collection is empty; skipping similarity search.")
        return {
            "matches": [],
            "top_similarity_score": 0.0,
            "collection_size": 0,
        }

    summary = _build_report_summary(report)
    vector = encoder.encode(summary, normalize_embeddings=True).tolist()

    results = client.query_points(
        collection_name=COLLECTION_NAME,
        query=vector,
        limit=min(TOP_K, count),
        with_payload=True,
    ).points

    matches = []
    for hit in results:
        matches.append(
            {
                "score": round(float(hit.score), 4),
                "threat_actor": hit.payload.get("threat_actor", "Unknown"),
                "mitre_ttps": hit.payload.get("mitre_ttps", []),
                "malware_families": hit.payload.get("malware_families", []),
                "summary": hit.payload.get("summary", ""),
            }
        )

    top_score = matches[0]["score"] if matches else 0.0
    return {
        "matches": matches,
        "top_similarity_score": top_score,
        "collection_size": count,
    }


# ---------------------------------------------------------------------------
# Quick self-test (run: python vector_store.py)
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    import sys

    logging.basicConfig(level=logging.INFO)

    # Minimal mock report for testing without importing agent.py
    class _MockReport(BaseModel):
        threat_actor: str
        malware_families: list[str]
        mitre_ttps: list[str]
        iocs: dict[str, list[str]]

    initialize_collection()

    r1 = _MockReport(
        threat_actor="APT41",
        malware_families=["DEADEYE", "KEYPLUG"],
        mitre_ttps=["T1059.001", "T1055"],
        iocs={"ips": ["192.168.1.1"], "domains": ["evil.com"], "hashes": []},
    )
    add_report(r1, source_text="Test APT41 report")

    r2 = _MockReport(
        threat_actor="APT41",
        malware_families=["DUSTPAN"],
        mitre_ttps=["T1059.001", "T1027"],
        iocs={"ips": ["10.0.0.5"], "domains": ["malware.net"], "hashes": []},
    )
    result = query_similar(r2)

    print("\n=== Query Result ===")
    print(json.dumps(result, indent=2))
    print(f"\nTop similarity score: {result['top_similarity_score']}")
