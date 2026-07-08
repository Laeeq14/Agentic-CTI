"""
api/es_client.py — Thin Elasticsearch client wrapper for Agentic-CTI.

Provides two public functions:
  - search_logs(query, index, size) → list of raw log event dicts
  - get_index_stats(index) → dict with event count and time range

The client reads ELASTICSEARCH_URL from the environment (defaulting to
http://localhost:9200 for local development).

All calls are synchronous. The FastAPI layer handles async via threadpool
offloading (run_in_executor) if needed.
"""

from __future__ import annotations

import logging
import os
from typing import Any

from elasticsearch import Elasticsearch, NotFoundError

logger = logging.getLogger(__name__)

_ES_URL = os.getenv("ELASTICSEARCH_URL", "http://localhost:9200")
_DEFAULT_INDEX = "agentic-cti-logs"

# Module-level singleton (lazy-initialised on first call)
_client: Elasticsearch | None = None


def _get_client() -> Elasticsearch:
    """Return (or lazily create) the Elasticsearch client singleton."""
    global _client
    if _client is None:
        logger.info("Connecting to Elasticsearch at %s", _ES_URL)
        _client = Elasticsearch(
            _ES_URL,
            request_timeout=30,
            retry_on_timeout=True,
            max_retries=3,
        )
    return _client


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def search_logs(
    query: str,
    index: str = _DEFAULT_INDEX,
    size: int = 100,
) -> list[dict[str, Any]]:
    """
    Execute a Lucene query string search against an Elasticsearch index.

    Args:
        query: Lucene query string (e.g. "event_type:NETWORK_CONNECTION AND dest_ip:1.2.3.4")
        index: Target index name. Defaults to 'agentic-cti-logs'.
        size:  Maximum number of log events to return. Defaults to 100.

    Returns:
        List of raw log event dicts (_source fields only).

    Raises:
        elasticsearch.NotFoundError: If the index does not exist.
        elasticsearch.ConnectionError: If ES is not reachable.
    """
    client = _get_client()
    logger.info(
        "Searching ES index '%s' | query=%r | size=%d", index, query, size
    )

    resp = client.search(
        index=index,
        body={
            "query": {"query_string": {"query": query}},
            "size": size,
            "sort": [{"@timestamp": {"order": "desc"}}],
        },
    )

    hits = resp["hits"]["hits"]
    events = [hit["_source"] for hit in hits]
    logger.info("ES search returned %d events.", len(events))
    return events


def get_index_stats(index: str = _DEFAULT_INDEX) -> dict[str, Any]:
    """
    Return basic statistics about an Elasticsearch index.

    Args:
        index: Target index name. Defaults to 'agentic-cti-logs'.

    Returns:
        Dict with keys:
          - index:       index name
          - doc_count:   number of indexed documents
          - size_bytes:  total store size in bytes
          - time_range:  {"min": ISO8601, "max": ISO8601} from @timestamp field
                         (or None if index is empty or @timestamp not present)
    """
    client = _get_client()

    try:
        stats = client.indices.stats(index=index)
        total = stats["_all"]["total"]
        doc_count = total["docs"]["count"]
        size_bytes = total["store"]["size_in_bytes"]
    except NotFoundError:
        logger.warning("Index '%s' not found — returning zero stats.", index)
        return {"index": index, "doc_count": 0, "size_bytes": 0, "time_range": None}

    # Get time range from a date aggregation
    time_range: dict[str, str] | None = None
    try:
        agg_resp = client.search(
            index=index,
            body={
                "size": 0,
                "aggs": {
                    "min_ts": {"min": {"field": "@timestamp"}},
                    "max_ts": {"max": {"field": "@timestamp"}},
                },
            },
        )
        aggs = agg_resp.get("aggregations", {})
        min_val = aggs.get("min_ts", {}).get("value_as_string")
        max_val = aggs.get("max_ts", {}).get("value_as_string")
        if min_val and max_val:
            time_range = {"min": min_val, "max": max_val}
    except Exception as exc:
        logger.warning("Could not fetch time range for index '%s': %s", index, exc)

    return {
        "index": index,
        "doc_count": doc_count,
        "size_bytes": size_bytes,
        "time_range": time_range,
    }
