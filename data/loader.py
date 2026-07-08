"""
data/loader.py — Bulk-index the Agentic-CTI synthetic log dataset into Elasticsearch.

Reads NDJSON from data/logs/sample_bots_v1.json and indexes each event
into the specified Elasticsearch index using the bulk helpers API.

Usage:
    python data/loader.py
    python data/loader.py --es-url http://localhost:9200 --index agentic-cti-logs
    python data/loader.py --dry-run   # show count without indexing

Requirements:
    elasticsearch>=8.0.0 (installed via requirements.txt)
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
from pathlib import Path

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
logger = logging.getLogger(__name__)

_DATA_FILE = Path(__file__).parent / "logs" / "sample_bots_v1.json"
_DEFAULT_ES_URL = os.getenv("ELASTICSEARCH_URL", "http://localhost:9200")
_DEFAULT_INDEX = "agentic-cti-logs"


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Bulk-index the Agentic-CTI synthetic log dataset into Elasticsearch."
    )
    parser.add_argument(
        "--es-url",
        default=_DEFAULT_ES_URL,
        help=f"Elasticsearch URL. Default: {_DEFAULT_ES_URL}",
    )
    parser.add_argument(
        "--index",
        default=_DEFAULT_INDEX,
        help=f"Target index name. Default: {_DEFAULT_INDEX}",
    )
    parser.add_argument(
        "--data-file",
        default=str(_DATA_FILE),
        help=f"Path to NDJSON log file. Default: {_DATA_FILE}",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Count events without indexing.",
    )
    parser.add_argument(
        "--recreate",
        action="store_true",
        help="Delete and recreate the index before indexing.",
    )
    return parser.parse_args()


def _create_index(client, index: str) -> None:
    """Create index with explicit mapping for known fields."""
    mapping = {
        "mappings": {
            "properties": {
                "@timestamp":       {"type": "date"},
                "event_type":       {"type": "keyword"},
                "src_ip":           {"type": "ip"},
                "dest_ip":          {"type": "ip"},
                "dest_port":        {"type": "integer"},
                "protocol":         {"type": "keyword"},
                "domain":           {"type": "keyword"},
                "process_name":     {"type": "keyword"},
                "command_line":     {"type": "text"},
                "file_hash_sha256": {"type": "keyword"},
                "http_uri":         {"type": "keyword"},
                "threat_category":  {"type": "keyword"},
                "severity":         {"type": "keyword"},
            }
        },
        "settings": {
            "number_of_shards":   1,
            "number_of_replicas": 0,
        },
    }
    client.indices.create(index=index, body=mapping)
    logger.info("Created index '%s'.", index)


def main() -> None:
    args = _parse_args()
    data_path = Path(args.data_file)

    if not data_path.exists():
        logger.error("Data file not found: %s", data_path)
        sys.exit(1)

    # Parse NDJSON
    events: list[dict] = []
    with data_path.open(encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line:
                events.append(json.loads(line))

    logger.info("Parsed %d events from %s.", len(events), data_path)

    if args.dry_run:
        logger.info("[DRY RUN] Would index %d events into '%s' at %s.", len(events), args.index, args.es_url)
        return

    try:
        from elasticsearch import Elasticsearch
        from elasticsearch.helpers import bulk
    except ImportError:
        logger.error("elasticsearch package not installed. Run: pip install elasticsearch>=8.0.0")
        sys.exit(1)

    client = Elasticsearch(args.es_url, request_timeout=30)

    # Check connectivity
    if not client.ping():
        logger.error("Cannot connect to Elasticsearch at %s", args.es_url)
        sys.exit(1)

    # Recreate index if requested
    if args.recreate and client.indices.exists(index=args.index):
        client.indices.delete(index=args.index)
        logger.info("Deleted existing index '%s'.", args.index)

    if not client.indices.exists(index=args.index):
        _create_index(client, args.index)

    # Prepare bulk actions
    actions = [
        {
            "_index": args.index,
            "_source": event,
        }
        for event in events
    ]

    logger.info("Indexing %d events into '%s'...", len(actions), args.index)
    success, errors = bulk(client, actions, raise_on_error=False, stats_only=False)
    failed = len(errors) if isinstance(errors, list) else errors

    if failed:
        logger.warning("Indexing completed with %d failures.", failed)
    else:
        logger.info("✅ Successfully indexed %d events.", success)

    # Verify
    client.indices.refresh(index=args.index)
    count = client.count(index=args.index)["count"]
    logger.info("Index '%s' now contains %d documents.", args.index, count)


if __name__ == "__main__":
    main()
