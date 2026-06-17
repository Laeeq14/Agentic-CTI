"""
src/ingestion/watcher.py — Asyncio file watcher for automated threat intel ingestion.

Monitors a designated inbox directory for new .txt and .pdf threat advisory files,
reads them asynchronously, and pipes each one through the Agentic-CTI LangGraph
pipeline automatically.

This component decouples data ingestion from the Streamlit UI, enabling production-
scale processing of threat intelligence feeds, email attachments, or advisory drops
without manual copy-paste.

Architecture:
  - watchdog FileSystemEventHandler  : detects new/moved files in ./watch_inbox/
  - asyncio queue                    : decouples file detection from processing
  - async worker coroutines          : run pipeline concurrently (configurable)
  - results JSON sink                : writes output to ./watch_results/<filename>.json

Supported formats:
  - .txt : read as UTF-8 text
  - .pdf : extracted with pypdf (install: pip install pypdf)

Usage:
    # Start the watcher (blocks until Ctrl+C):
    python src/ingestion/watcher.py

    # With custom inbox / results directories:
    python src/ingestion/watcher.py --inbox ./my_inbox --results ./my_results

    # With more concurrent workers (default: 2):
    python src/ingestion/watcher.py --workers 4

Drop a .txt file into the watch_inbox/ directory and the pipeline will
automatically process it and write a result JSON to watch_results/.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

# ---------------------------------------------------------------------------
# Path setup — allow running from repo root or src/ingestion/
# ---------------------------------------------------------------------------
_REPO_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(_REPO_ROOT))

from dotenv import load_dotenv
load_dotenv(_REPO_ROOT / ".env")

try:
    from watchdog.events import FileSystemEvent, FileSystemEventHandler
    from watchdog.observers import Observer
except ImportError:
    print("ERROR: watchdog is not installed. Run: pip install watchdog")
    sys.exit(1)

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
DEFAULT_INBOX_DIR   = _REPO_ROOT / "watch_inbox"
DEFAULT_RESULTS_DIR = _REPO_ROOT / "watch_results"
SUPPORTED_EXTENSIONS = {".txt", ".pdf"}
MAX_FILE_SIZE_BYTES = 5 * 1024 * 1024  # 5 MB safety cap


# ---------------------------------------------------------------------------
# File reading helpers
# ---------------------------------------------------------------------------

def _read_txt(path: Path) -> str:
    """Read a plain text file, trying UTF-8 with a Latin-1 fallback."""
    try:
        return path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        return path.read_text(encoding="latin-1")


def _read_pdf(path: Path) -> str:
    """
    Extract text from a PDF file using pypdf.

    Returns concatenated text from all pages. Raises ImportError if
    pypdf is not installed (install separately: pip install pypdf).
    """
    try:
        import pypdf  # type: ignore
    except ImportError as exc:
        raise ImportError(
            "pypdf is required for PDF ingestion: pip install pypdf"
        ) from exc

    reader = pypdf.PdfReader(str(path))
    pages = []
    for page in reader.pages:
        text = page.extract_text() or ""
        pages.append(text.strip())
    return "\n\n".join(p for p in pages if p)


def read_file(path: Path) -> Optional[str]:
    """
    Read a supported file and return its text content.

    Args:
        path: Path to the file to read.

    Returns:
        Text content of the file, or None if the file could not be read.
    """
    suffix = path.suffix.lower()
    if suffix not in SUPPORTED_EXTENSIONS:
        logger.warning("Skipping unsupported file type: %s", path.name)
        return None

    file_size = path.stat().st_size
    if file_size == 0:
        logger.warning("Skipping empty file: %s", path.name)
        return None
    if file_size > MAX_FILE_SIZE_BYTES:
        logger.warning(
            "Skipping oversized file: %s (%d bytes > %d limit)",
            path.name, file_size, MAX_FILE_SIZE_BYTES,
        )
        return None

    try:
        if suffix == ".txt":
            return _read_txt(path)
        if suffix == ".pdf":
            return _read_pdf(path)
    except Exception as exc:
        logger.exception("Failed to read file %s: %s", path.name, exc)
        return None

    return None


# ---------------------------------------------------------------------------
# watchdog event handler
# ---------------------------------------------------------------------------

class _InboxEventHandler(FileSystemEventHandler):
    """
    Watchdog handler that enqueues newly created / moved-in files for processing.

    Files are added to an asyncio.Queue for consumption by async worker coroutines,
    keeping the filesystem callback non-blocking.
    """

    def __init__(self, queue: asyncio.Queue, loop: asyncio.AbstractEventLoop) -> None:
        super().__init__()
        self._queue = queue
        self._loop  = loop

    def _enqueue(self, path_str: str) -> None:
        path = Path(path_str)
        if path.suffix.lower() not in SUPPORTED_EXTENSIONS:
            return
        logger.info("[Watcher] New file detected: %s", path.name)
        # Thread-safe enqueue from watchdog callback thread into async queue
        self._loop.call_soon_threadsafe(self._queue.put_nowait, path)

    def on_created(self, event: FileSystemEvent) -> None:
        if not event.is_directory:
            self._enqueue(event.src_path)

    def on_moved(self, event: FileSystemEvent) -> None:
        # File moved into the watch directory (e.g., from an atomic write)
        if not event.is_directory:
            self._enqueue(event.dest_path)


# ---------------------------------------------------------------------------
# Async pipeline worker
# ---------------------------------------------------------------------------

async def _process_file(
    path: Path,
    results_dir: Path,
    worker_id: int,
) -> None:
    """
    Read a file, run it through the Agentic-CTI pipeline, and write results.

    Args:
        path        : Path to the file to process.
        results_dir : Directory to write the result JSON to.
        worker_id   : Worker identifier for log correlation.
    """
    log_prefix = f"[Worker-{worker_id}][{path.name}]"
    logger.info("%s Starting pipeline...", log_prefix)

    # Short settling delay to handle files still being written
    await asyncio.sleep(0.5)

    # Read file in a thread pool to avoid blocking the event loop
    loop = asyncio.get_running_loop()
    text = await loop.run_in_executor(None, read_file, path)
    if text is None:
        logger.warning("%s Could not read file — skipping.", log_prefix)
        return

    logger.info("%s File read: %d chars. Running pipeline...", log_prefix, len(text))

    # Run the (synchronous) LangGraph pipeline in a thread pool
    t0 = time.perf_counter()
    try:
        from agent import run_pipeline  # lazy import — avoids loading at module level
        result = await loop.run_in_executor(None, run_pipeline, text)
    except Exception as exc:
        logger.exception("%s Pipeline raised exception: %s", log_prefix, exc)
        result = {"pipeline_error": str(exc)}

    elapsed = round(time.perf_counter() - t0, 2)
    logger.info("%s Pipeline complete in %.2fs.", log_prefix, elapsed)

    # Serialize and write result JSON
    output_payload: dict = {
        "source_file"   : str(path),
        "processed_at"  : datetime.now(timezone.utc).isoformat(),
        "elapsed_seconds": elapsed,
        "pipeline_result": _serialise_result(result),
    }

    stem = path.stem
    ts   = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    out_path = results_dir / f"{stem}_{ts}.json"

    try:
        out_path.write_text(
            json.dumps(output_payload, indent=2, default=str),
            encoding="utf-8",
        )
        logger.info("%s Result saved to: %s", log_prefix, out_path.name)
    except OSError as exc:
        logger.error("%s Failed to write result: %s", log_prefix, exc)


def _serialise_result(result: dict) -> dict:
    """Convert pipeline result to a JSON-serialisable dict."""
    serialised: dict = {}
    for key, val in result.items():
        if hasattr(val, "model_dump_json"):
            # Pydantic model
            serialised[key] = json.loads(val.model_dump_json())
        elif isinstance(val, (str, int, float, bool, list, dict)) or val is None:
            serialised[key] = val
        else:
            serialised[key] = str(val)
    return serialised


# ---------------------------------------------------------------------------
# Worker pool
# ---------------------------------------------------------------------------

async def _worker(
    worker_id: int,
    queue: asyncio.Queue,
    results_dir: Path,
    processed: set[Path],
) -> None:
    """
    Long-running coroutine that consumes files from the queue and processes them.

    Args:
        worker_id   : Numeric ID for logging.
        queue       : Shared asyncio.Queue of Path objects to process.
        results_dir : Directory to write result JSON files.
        processed   : Shared set of already-processed paths (deduplication).
    """
    logger.info("[Worker-%d] Started.", worker_id)
    while True:
        path: Path = await queue.get()
        try:
            if path in processed:
                logger.debug("[Worker-%d] Skipping duplicate: %s", worker_id, path.name)
            else:
                processed.add(path)
                await _process_file(path, results_dir, worker_id)
        except Exception as exc:
            logger.exception("[Worker-%d] Unhandled error: %s", worker_id, exc)
        finally:
            queue.task_done()


# ---------------------------------------------------------------------------
# Main watch loop
# ---------------------------------------------------------------------------

async def watch(
    inbox_dir: Path,
    results_dir: Path,
    num_workers: int = 2,
) -> None:
    """
    Start the async file watcher loop.

    1. Creates a watchdog Observer pointing at inbox_dir.
    2. Spawns num_workers async worker coroutines.
    3. Blocks until cancelled (Ctrl+C).

    Args:
        inbox_dir   : Directory to monitor for new files.
        results_dir : Directory to write result JSON files.
        num_workers : Number of concurrent pipeline workers.
    """
    inbox_dir.mkdir(parents=True, exist_ok=True)
    results_dir.mkdir(parents=True, exist_ok=True)

    queue: asyncio.Queue[Path] = asyncio.Queue()
    processed: set[Path] = set()
    loop = asyncio.get_running_loop()

    # Start watchdog observer
    handler  = _InboxEventHandler(queue, loop)
    observer = Observer()
    observer.schedule(handler, str(inbox_dir), recursive=False)
    observer.start()

    logger.info("=" * 60)
    logger.info("  Agentic-CTI File Watcher — ACTIVE")
    logger.info("  Inbox  : %s", inbox_dir)
    logger.info("  Results: %s", results_dir)
    logger.info("  Workers: %d", num_workers)
    logger.info("  Watching for: %s", ", ".join(sorted(SUPPORTED_EXTENSIONS)))
    logger.info("=" * 60)
    logger.info("  Drop .txt or .pdf files into the inbox to trigger analysis.")
    logger.info("  Press Ctrl+C to stop.")
    logger.info("=" * 60)

    # Spawn worker pool
    workers = [
        asyncio.create_task(_worker(i + 1, queue, results_dir, processed))
        for i in range(num_workers)
    ]

    try:
        # Process any pre-existing files in the inbox on startup
        existing = list(inbox_dir.glob("*"))
        for p in existing:
            if p.is_file() and p.suffix.lower() in SUPPORTED_EXTENSIONS:
                logger.info("[Startup] Queueing pre-existing file: %s", p.name)
                await queue.put(p)

        # Wait indefinitely
        while True:
            await asyncio.sleep(1)

    except asyncio.CancelledError:
        logger.info("Watcher shutting down...")
    finally:
        observer.stop()
        observer.join()
        for w in workers:
            w.cancel()
        await asyncio.gather(*workers, return_exceptions=True)
        logger.info("Watcher stopped.")


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Agentic-CTI async file watcher — monitors a directory for "
                    "threat advisory files and pipes them through the analysis pipeline."
    )
    parser.add_argument(
        "--inbox", "-i",
        type=Path,
        default=DEFAULT_INBOX_DIR,
        help=f"Directory to watch for new files (default: {DEFAULT_INBOX_DIR})",
    )
    parser.add_argument(
        "--results", "-r",
        type=Path,
        default=DEFAULT_RESULTS_DIR,
        help=f"Directory to write result JSON files (default: {DEFAULT_RESULTS_DIR})",
    )
    parser.add_argument(
        "--workers", "-w",
        type=int,
        default=2,
        help="Number of concurrent pipeline workers (default: 2)",
    )
    parser.add_argument(
        "--log-level",
        default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        help="Log verbosity (default: INFO)",
    )
    args = parser.parse_args()

    logging.basicConfig(
        level=getattr(logging, args.log_level),
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )

    try:
        asyncio.run(watch(args.inbox, args.results, num_workers=args.workers))
    except KeyboardInterrupt:
        print("\nWatcher stopped by user.")


if __name__ == "__main__":
    main()
