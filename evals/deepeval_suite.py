"""
evals/deepeval_suite.py — LLM-graded evaluation suite using DeepEval.

Runs three semantic quality metrics against the Agentic-CTI pipeline outputs:
  1. Faithfulness     — extracted JSON accurately reflects the source report
  2. Answer Relevancy — YARA-L rule content matches extracted IOCs / TTPs
  3. Hallucination    — extracted IOCs are actually present in source text

Usage:
    python evals/deepeval_suite.py
    python evals/deepeval_suite.py --fixture F01_apt41_baseline
    python evals/deepeval_suite.py --dry-run   # skip pipeline, use mock state

Requirements:
    deepeval>=1.0.0 (installed via requirements.txt)
    GROQ_API_KEY set in environment (used by the underlying LangChain calls)

Note: DeepEval metrics make LLM API calls to evaluate outputs. Each fixture
      typically uses 3–5 LLM calls. Running the full 30-fixture suite against
      a live Groq endpoint costs ~90–150 LLM calls.
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
from pathlib import Path
from typing import Any

# ---------------------------------------------------------------------------
# Path setup
# ---------------------------------------------------------------------------
_REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_REPO_ROOT))

from dotenv import load_dotenv
load_dotenv(_REPO_ROOT / ".env")

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Parse arguments early so we can skip heavy imports on --dry-run
# ---------------------------------------------------------------------------

def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="LLM-graded DeepEval evaluation suite for Agentic-CTI."
    )
    parser.add_argument(
        "--fixture",
        default=None,
        help="Run only this fixture ID (e.g. F01_apt41_baseline). Default: all non-blocked fixtures.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Skip pipeline and deepeval; print fixtures that would run.",
    )
    parser.add_argument(
        "--threshold",
        type=float,
        default=0.7,
        help="Minimum passing score for each metric. Default: 0.7",
    )
    return parser.parse_args()


# ---------------------------------------------------------------------------
# Deep eval imports (skip if deepeval not installed)
# ---------------------------------------------------------------------------

def _import_deepeval():
    try:
        from deepeval import evaluate
        from deepeval.metrics import (
            AnswerRelevancyMetric,
            FaithfulnessMetric,
            HallucinationMetric,
        )
        from deepeval.test_case import LLMTestCase
        return evaluate, AnswerRelevancyMetric, FaithfulnessMetric, HallucinationMetric, LLMTestCase
    except ImportError as e:
        logger.error(
            "deepeval package not installed. Run: pip install deepeval>=1.0.0\n"
            "Error: %s", e
        )
        sys.exit(1)


# ---------------------------------------------------------------------------
# Pipeline runner
# ---------------------------------------------------------------------------

def _run_fixture(fixture: dict[str, Any]) -> dict[str, Any]:
    """Run the pipeline on a single fixture and return the state dict."""
    from agent import run_pipeline
    report_text = fixture["report_text"]
    logger.info("Running pipeline for fixture: %s", fixture["id"])
    return run_pipeline(report_text)


def _state_to_context_and_output(
    fixture: dict[str, Any],
    state: dict[str, Any],
) -> tuple[str, str, str]:
    """
    Convert pipeline state into DeepEval test case components.

    Returns:
        (input_text, actual_output, expected_output)
    """
    input_text = fixture["report_text"]

    # Actual output: extracted JSON + YARA-L rule
    report = state.get("extracted_report")
    if report and hasattr(report, "model_dump"):
        extracted_json = json.dumps(report.model_dump(), indent=2)
    else:
        extracted_json = json.dumps(state.get("extracted_report") or {}, indent=2)

    yaral = state.get("final_yaral_rule") or "[No YARA-L rule generated]"
    actual_output = f"Extracted Intel:\n{extracted_json}\n\nYARA-L Rule:\n{yaral}"

    # Expected output: ground truth
    gt = fixture["ground_truth"]
    expected_output = json.dumps({
        "threat_actor": gt.get("threat_actor"),
        "malware_families": gt.get("malware_families", []),
        "mitre_ttps": gt.get("mitre_ttps", []),
        "iocs": gt.get("iocs", {}),
    }, indent=2)

    return input_text, actual_output, expected_output


# ---------------------------------------------------------------------------
# Main evaluation loop
# ---------------------------------------------------------------------------

def main() -> None:
    args = _parse_args()

    from tests.eval.fixtures import EVAL_FIXTURES
    fixtures = EVAL_FIXTURES

    # Filter out blocked fixtures
    runnable = [
        f for f in fixtures
        if not f.get("ground_truth", {}).get("_expected_blocked", False)
    ]

    # Single-fixture filter
    if args.fixture:
        runnable = [f for f in runnable if f["id"] == args.fixture]
        if not runnable:
            logger.error("Fixture '%s' not found or is blocked.", args.fixture)
            sys.exit(1)

    if args.dry_run:
        print(f"\n{'='*60}")
        print(f"DRY RUN — Would evaluate {len(runnable)} fixtures:")
        for f in runnable:
            print(f"  [{f['id']}] {f['description']}")
        print(f"{'='*60}\n")
        return

    evaluate, AnswerRelevancyMetric, FaithfulnessMetric, HallucinationMetric, LLMTestCase = \
        _import_deepeval()

    threshold = args.threshold
    test_cases = []

    for fixture in runnable:
        logger.info("Processing fixture: %s", fixture["id"])
        try:
            state = _run_fixture(fixture)
            input_text, actual_output, expected_output = _state_to_context_and_output(fixture, state)

            # DeepEval LLMTestCase
            test_case = LLMTestCase(
                input=input_text,
                actual_output=actual_output,
                expected_output=expected_output,
                context=[fixture["report_text"]],  # source document as context
                retrieval_context=[
                    json.dumps(m) for m in (state.get("rag_context") or {}).get("matches", [])
                ],
            )
            test_cases.append((fixture["id"], test_case))
            logger.info("Test case built for fixture: %s", fixture["id"])

        except Exception as e:
            logger.error("Failed to process fixture %s: %s", fixture["id"], e)

    if not test_cases:
        logger.error("No test cases built. Exiting.")
        sys.exit(1)

    # Define metrics
    metrics = [
        FaithfulnessMetric(threshold=threshold, verbose_mode=False),
        AnswerRelevancyMetric(threshold=threshold, verbose_mode=False),
        HallucinationMetric(threshold=(1.0 - threshold), verbose_mode=False),  # lower = less hallucination
    ]

    # Run evaluation
    print(f"\n{'='*60}")
    print(f"Running DeepEval on {len(test_cases)} test cases...")
    print(f"Metrics: Faithfulness, AnswerRelevancy, Hallucination")
    print(f"Threshold: {threshold}")
    print(f"{'='*60}\n")

    results = []
    for fixture_id, test_case in test_cases:
        case_results = {"fixture_id": fixture_id}
        for metric in metrics:
            try:
                metric.measure(test_case)
                case_results[metric.__class__.__name__] = {
                    "score": metric.score,
                    "passed": metric.is_successful(),
                    "reason": getattr(metric, "reason", ""),
                }
            except Exception as e:
                logger.error("[%s] Metric %s failed: %s", fixture_id, metric.__class__.__name__, e)
                case_results[metric.__class__.__name__] = {"score": None, "passed": False, "reason": str(e)}
        results.append(case_results)

    # Print summary
    print(f"\n{'='*60}")
    print("DEEPEVAL RESULTS SUMMARY")
    print(f"{'='*60}")
    for r in results:
        fid = r["fixture_id"]
        scores = {k: v for k, v in r.items() if k != "fixture_id"}
        all_passed = all(v.get("passed", False) for v in scores.values())
        status = "✅ PASS" if all_passed else "❌ FAIL"
        print(f"\n{status} [{fid}]")
        for metric_name, metric_result in scores.items():
            score_str = f"{metric_result['score']:.3f}" if metric_result['score'] is not None else "N/A"
            pass_str = "PASS" if metric_result['passed'] else "FAIL"
            print(f"  {metric_name:25s}: {score_str} [{pass_str}]")

    total = len(results)
    passed = sum(
        1 for r in results
        if all(v.get("passed", False) for k, v in r.items() if k != "fixture_id")
    )
    print(f"\n{'='*60}")
    print(f"Overall: {passed}/{total} fixtures passed all metrics")
    print(f"{'='*60}\n")

    # Save results to JSON
    output_path = _REPO_ROOT / "evals" / "last_run_results.json"
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8") as fh:
        json.dump(results, fh, indent=2)
    logger.info("Results saved to %s", output_path)


if __name__ == "__main__":
    main()
