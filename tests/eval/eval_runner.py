"""
tests/eval/eval_runner.py — Continuous evaluation framework for Agentic-CTI.

Runs each ground-truth fixture through the full pipeline and scores the output
against expected values across four key metrics:

  1. IOC Extraction Recall
       Fraction of expected IOCs (IPs, domains, hashes) that the pipeline
       correctly identified. Measures completeness of indicator extraction.

  2. TTP Extraction Recall
       Fraction of expected MITRE ATT&CK TTP IDs correctly identified.

  3. Schema Conformance Rate
       Whether Pydantic successfully validated the LLM output (extraction
       did not fail). A 0 means the LLM produced malformed JSON.

  4. YARA-L First-Pass Rate
       Whether the generated YARA-L rule passed the validator on the first
       attempt (retry_count == 0). Tracks prompt quality over time.

  5. Prompt Guard Block Rate
       For adversarial fixtures, whether the guard correctly blocked the input.

Usage:
    # Run all fixtures (calls real Groq API):
    python tests/eval/eval_runner.py

    # Run a single fixture by ID:
    python tests/eval/eval_runner.py --fixture F01_apt41_baseline

    # Save results to JSON:
    python tests/eval/eval_runner.py --output tests/eval/results/run_<timestamp>.json

    # Dry-run (skip LLM calls, use prompt guard only):
    python tests/eval/eval_runner.py --dry-run
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# Allow running from the repo root
_REPO_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(_REPO_ROOT))

from dotenv import load_dotenv

load_dotenv(_REPO_ROOT / ".env")

from tests.eval.fixtures import FIXTURES
from src.security.prompt_guard import scan as guard_scan

logger = logging.getLogger(__name__)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)


# ---------------------------------------------------------------------------
# Metric helpers
# ---------------------------------------------------------------------------

def _normalise(value: str) -> str:
    """Lower-case and strip a string for case-insensitive comparison."""
    return value.strip().lower()


def _ioc_recall(predicted_iocs: Any, ground_truth_iocs: dict) -> float:
    """
    Compute IOC extraction recall across all categories (IPs, domains, hashes).

    Recall = |correctly_extracted| / |total_expected|
    Returns 1.0 if there are no expected IOCs (vacuously true).
    """
    # Normalise predicted
    if hasattr(predicted_iocs, "ips"):
        pred_ips     = {_normalise(x) for x in (predicted_iocs.ips or [])}
        pred_domains = {_normalise(x) for x in (predicted_iocs.domains or [])}
        pred_hashes  = {_normalise(x) for x in (predicted_iocs.hashes or [])}
    else:
        pred_ips     = {_normalise(x) for x in predicted_iocs.get("ips", [])}
        pred_domains = {_normalise(x) for x in predicted_iocs.get("domains", [])}
        pred_hashes  = {_normalise(x) for x in predicted_iocs.get("hashes", [])}

    gt_ips     = {_normalise(x) for x in ground_truth_iocs.get("ips", [])}
    gt_domains = {_normalise(x) for x in ground_truth_iocs.get("domains", [])}
    gt_hashes  = {_normalise(x) for x in ground_truth_iocs.get("hashes", [])}

    total_expected = len(gt_ips) + len(gt_domains) + len(gt_hashes)
    if total_expected == 0:
        return 1.0

    correctly_extracted = (
        len(pred_ips & gt_ips)
        + len(pred_domains & gt_domains)
        + len(pred_hashes & gt_hashes)
    )
    return round(correctly_extracted / total_expected, 4)


def _ttp_recall(predicted_ttps: list[str], ground_truth_ttps: list[str]) -> float:
    """
    Compute MITRE ATT&CK TTP extraction recall.

    Handles sub-technique matching: T1059 matches T1059.001.
    Returns 1.0 if there are no expected TTPs.
    """
    if not ground_truth_ttps:
        return 1.0

    pred_set = {_normalise(t) for t in predicted_ttps}
    total_hit = 0

    for expected in ground_truth_ttps:
        norm = _normalise(expected)
        # Exact match
        if norm in pred_set:
            total_hit += 1
            continue
        # Partial match: if expected is T1059, check if T1059.xxx was found
        if any(p.startswith(norm) for p in pred_set):
            total_hit += 1
            continue
        # Reverse partial: if expected is T1059.001, check if T1059 was found
        parent = norm.split(".")[0]
        if parent in pred_set:
            total_hit += 1

    return round(total_hit / len(ground_truth_ttps), 4)


def _actor_match(predicted_actor: str, gt_actor: str, alt_actors: list[str]) -> bool:
    """Return True if the predicted actor matches the canonical name or any alias."""
    norm_pred = _normalise(predicted_actor)
    accepted = {_normalise(gt_actor)} | {_normalise(a) for a in alt_actors}
    return any(a in norm_pred or norm_pred in a for a in accepted)


# ---------------------------------------------------------------------------
# Single fixture evaluation
# ---------------------------------------------------------------------------

def _evaluate_fixture(
    fixture: dict[str, Any],
    dry_run: bool = False,
) -> dict[str, Any]:
    """
    Run one fixture through the pipeline and return a scored result dict.

    Args:
        fixture : A fixture entry from tests/eval/fixtures.py.
        dry_run : If True, skip LLM calls. Only runs the prompt guard.

    Returns:
        Scored result dict with metrics and raw pipeline output.
    """
    fid   = fixture["id"]
    text  = fixture["report_text"]
    gt    = fixture["ground_truth"]
    expected_blocked = gt.get("_expected_blocked", False)

    result: dict[str, Any] = {
        "id"                  : fid,
        "description"         : fixture["description"],
        "timestamp_utc"       : datetime.now(timezone.utc).isoformat(),
        # --- security ---
        "guard_blocked"       : None,
        "guard_threat_type"   : None,
        # --- extraction ---
        "schema_conformance"  : None,   # bool
        "ioc_recall"          : None,   # float 0-1
        "ttp_recall"          : None,   # float 0-1
        "actor_match"         : None,   # bool
        # --- rule generation ---
        "yaral_first_pass"    : None,   # bool (passed on first attempt)
        "retry_count"         : None,   # int
        # --- raw ---
        "pipeline_result"     : None,
        "errors"              : [],
    }

    # Step 1: Prompt guard scan
    logger.info("[%s] Running prompt guard scan...", fid)
    guard_result = guard_scan(text)
    result["guard_blocked"]    = not guard_result.is_safe
    result["guard_threat_type"] = guard_result.threat_type

    if expected_blocked:
        result["schema_conformance"] = guard_result.is_safe is False  # True = correctly blocked
        logger.info("[%s] Adversarial fixture. Guard blocked: %s", fid, not guard_result.is_safe)
        return result

    if not guard_result.is_safe:
        result["errors"].append(
            f"Prompt guard blocked legitimate input: {guard_result.threat_type}"
        )
        result["schema_conformance"] = False
        logger.warning("[%s] False positive from prompt guard!", fid)
        return result

    if dry_run:
        logger.info("[%s] Dry-run mode — skipping LLM pipeline.", fid)
        return result

    # Step 2: Run full pipeline
    logger.info("[%s] Running LLM pipeline...", fid)
    t0 = time.perf_counter()
    try:
        from agent import run_pipeline
        pipeline_out = run_pipeline(text)
    except Exception as exc:
        result["errors"].append(f"Pipeline exception: {exc}")
        result["schema_conformance"] = False
        logger.exception("[%s] Pipeline raised an exception.", fid)
        return result
    elapsed = round(time.perf_counter() - t0, 2)
    result["pipeline_result"] = {"elapsed_seconds": elapsed}

    # Step 3: Schema conformance
    extracted = pipeline_out.get("extracted_report")
    if extracted is None:
        result["schema_conformance"] = False
        result["errors"].append(
            f"Extraction failed: {pipeline_out.get('extraction_error', 'unknown')}"
        )
        return result

    result["schema_conformance"] = True
    result["ioc_recall"] = _ioc_recall(extracted.iocs, gt["iocs"])
    result["ttp_recall"] = _ttp_recall(extracted.mitre_ttps, gt["mitre_ttps"])
    result["actor_match"] = _actor_match(
        extracted.threat_actor or "",
        gt["threat_actor"],
        gt.get("alt_actors", []),
    )

    # Step 4: YARA-L rule scoring
    retry_count = pipeline_out.get("retry_count", 0)
    final_rule  = pipeline_out.get("final_yaral_rule")
    result["retry_count"]      = retry_count
    result["yaral_first_pass"] = (final_rule is not None) and (retry_count == 0)

    logger.info(
        "[%s] Done in %.2fs | ioc_recall=%.2f | ttp_recall=%.2f | yaral_pass=%s",
        fid, elapsed, result["ioc_recall"], result["ttp_recall"], result["yaral_first_pass"],
    )
    return result


# ---------------------------------------------------------------------------
# Aggregate metrics
# ---------------------------------------------------------------------------

def _aggregate(results: list[dict[str, Any]]) -> dict[str, Any]:
    """Compute aggregate metrics across all non-adversarial fixtures."""
    non_adversarial = [r for r in results if r.get("guard_threat_type") is None
                       and not any("Adversarial" in r["description"]
                                   or "_expected_blocked" in str(r) for _ in [1])]
    # simpler: filter out F06
    non_adv = [r for r in results if not r["description"].startswith("Prompt injection")]

    def _safe_mean(vals: list) -> float | None:
        clean = [v for v in vals if v is not None]
        return round(sum(clean) / len(clean), 4) if clean else None

    return {
        "total_fixtures"           : len(results),
        "non_adversarial_fixtures" : len(non_adv),
        "schema_conformance_rate"  : _safe_mean([r["schema_conformance"] for r in non_adv
                                                  if r["schema_conformance"] is not None]),
        "mean_ioc_recall"          : _safe_mean([r["ioc_recall"] for r in non_adv
                                                  if r["ioc_recall"] is not None]),
        "mean_ttp_recall"          : _safe_mean([r["ttp_recall"] for r in non_adv
                                                  if r["ttp_recall"] is not None]),
        "actor_match_rate"         : _safe_mean([r["actor_match"] for r in non_adv
                                                  if r["actor_match"] is not None]),
        "yaral_first_pass_rate"    : _safe_mean([r["yaral_first_pass"] for r in non_adv
                                                  if r["yaral_first_pass"] is not None]),
        "mean_retry_count"         : _safe_mean([r["retry_count"] for r in non_adv
                                                  if r["retry_count"] is not None]),
        "guard_true_positive_rate" : _safe_mean([r["schema_conformance"] for r in results
                                                  if r["description"].startswith("Prompt injection")]),
    }


# ---------------------------------------------------------------------------
# Report formatting
# ---------------------------------------------------------------------------

_COL = {
    "green" : "\033[92m",
    "yellow": "\033[93m",
    "red"   : "\033[91m",
    "cyan"  : "\033[96m",
    "bold"  : "\033[1m",
    "reset" : "\033[0m",
}


def _pct(val: float | None) -> str:
    if val is None:
        return "  N/A  "
    pct = val * 100
    color = _COL["green"] if pct >= 80 else (_COL["yellow"] if pct >= 50 else _COL["red"])
    return f"{color}{pct:5.1f}%{_COL['reset']}"


def _bool_str(val: bool | None) -> str:
    if val is None:
        return "  N/A  "
    return f"{_COL['green']}PASS{_COL['reset']}" if val else f"{_COL['red']}FAIL{_COL['reset']}"


def print_report(results: list[dict[str, Any]], agg: dict[str, Any]) -> None:
    sys.stdout.reconfigure(encoding="utf-8")
    W = 100
    print("\n" + "=" * W)
    print(f"  AGENTIC-CTI EVALUATION REPORT  //  {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}")
    print("=" * W)

    # Per-fixture table
    print(f"\n{'ID':<30} {'Guard':>6} {'Schema':>7} {'IOC Rec':>8} {'TTP Rec':>8} "
          f"{'Actor':>6} {'YARAL 1st':>10} {'Retries':>8}")
    print("-" * W)

    for r in results:
        guard = "BLOCK" if r["guard_blocked"] else "  OK "
        schema = _bool_str(r["schema_conformance"]) if r["schema_conformance"] is not None else "  N/A "
        print(
            f"{r['id']:<30} {guard:>6} {schema:>13} "
            f"{_pct(r['ioc_recall']):>14} {_pct(r['ttp_recall']):>14} "
            f"{_bool_str(r['actor_match']):>12} {_bool_str(r['yaral_first_pass']):>16} "
            f"{'N/A' if r['retry_count'] is None else r['retry_count']:>8}"
        )
        if r["errors"]:
            for e in r["errors"]:
                print(f"  {'':>30} ERROR: {e}")

    # Aggregate summary
    print("\n" + "=" * W)
    print("  AGGREGATE METRICS")
    print("=" * W)
    metrics = [
        ("Schema Conformance Rate ",   agg["schema_conformance_rate"]),
        ("Mean IOC Extraction Recall",  agg["mean_ioc_recall"]),
        ("Mean TTP Extraction Recall",  agg["mean_ttp_recall"]),
        ("Threat Actor Match Rate    ", agg["actor_match_rate"]),
        ("YARA-L First-Pass Rate    ",  agg["yaral_first_pass_rate"]),
        ("Mean Retry Count (rule gen)", None),  # special
        ("Guard True Positive Rate  ",  agg["guard_true_positive_rate"]),
    ]
    for label, val in metrics:
        if label.startswith("Mean Retry"):
            raw = agg["mean_retry_count"]
            print(f"  {label}: {raw if raw is not None else 'N/A'}")
        else:
            print(f"  {label}: {_pct(val)}")
    print("=" * W + "\n")


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Agentic-CTI continuous evaluation runner"
    )
    parser.add_argument(
        "--fixture", "-f",
        default=None,
        help="Run a single fixture by ID (e.g. F01_apt41_baseline). "
             "Omit to run all fixtures.",
    )
    parser.add_argument(
        "--output", "-o",
        default=None,
        help="Path to save results JSON. Defaults to tests/eval/results/run_<ts>.json",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Skip LLM calls. Only evaluates the prompt guard.",
    )
    args = parser.parse_args()

    # Select fixtures
    if args.fixture:
        target = [f for f in FIXTURES if f["id"] == args.fixture]
        if not target:
            print(f"ERROR: Fixture '{args.fixture}' not found. "
                  f"Available: {[f['id'] for f in FIXTURES]}")
            sys.exit(1)
        fixture_list = target
    else:
        fixture_list = FIXTURES

    print(f"\nRunning {len(fixture_list)} fixture(s)"
          f"{' [DRY RUN]' if args.dry_run else ''}...\n")

    results = []
    for fixture in fixture_list:
        logger.info("--- Evaluating: %s ---", fixture["id"])
        r = _evaluate_fixture(fixture, dry_run=args.dry_run)
        results.append(r)

    agg = _aggregate(results)
    print_report(results, agg)

    # Save results
    output_path = args.output
    if output_path is None:
        ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        output_dir = _REPO_ROOT / "tests" / "eval" / "results"
        output_dir.mkdir(parents=True, exist_ok=True)
        output_path = str(output_dir / f"run_{ts}.json")

    payload = {"aggregate": agg, "fixtures": results}
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2, default=str)
    print(f"Results saved to: {output_path}\n")


if __name__ == "__main__":
    main()
