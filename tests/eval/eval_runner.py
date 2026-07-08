"""
tests/eval/eval_runner.py — Continuous evaluation framework for Agentic-CTI.

Runs each ground-truth fixture through the full pipeline and scores the output
against expected values across key metrics:

  1. IOC Extraction Recall
       Fraction of expected IOCs (IPs, domains, hashes) that the pipeline
       correctly identified. Measures completeness of indicator extraction.

  2. IOC Extraction Precision
       Fraction of extracted IOCs that are actually expected (no hallucination).

  3. IOC F1 Score
       Harmonic mean of IOC recall and precision.

  4. TTP Extraction Recall
       Fraction of expected MITRE ATT&CK TTP IDs correctly identified.

  5. Schema Conformance Rate
       Whether Pydantic successfully validated the LLM output (extraction
       did not fail). A 0 means the LLM produced malformed JSON.

  6. YARA-L First-Pass Rate
       Whether the generated YARA-L rule passed the validator on the first
       attempt (retry_count == 0). Tracks prompt quality over time.

  7. Prompt Guard Block Rate
       For adversarial fixtures, whether the guard correctly blocked the input.

Usage:
    # Dry-run (prompt guard only, no LLM calls):
    python tests/eval/eval_runner.py --dry-run

    # Live run (calls real Groq API for all fixtures):
    python tests/eval/eval_runner.py --live

    # Run a single fixture live:
    python tests/eval/eval_runner.py --fixture F01_apt41_baseline

    # Save results to JSON:
    python tests/eval/eval_runner.py --output tests/eval/results/run_<timestamp>.json

    # Save results as HTML report:
    python tests/eval/eval_runner.py --html --output report.html
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

# Support the EVAL_FIXTURES alias used by deepeval_suite and other consumers
try:
    from tests.eval.fixtures import EVAL_FIXTURES  # noqa: F401
except ImportError:
    pass  # EVAL_FIXTURES may not be exported by older versions of fixtures.py

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


def _ioc_precision(predicted_iocs: Any, ground_truth_iocs: dict) -> float:
    """
    Compute IOC extraction precision across all categories (IPs, domains, hashes).

    Precision = |correctly_extracted| / |total_predicted|
    Returns 1.0 if the pipeline extracted nothing (vacuously true — no false positives).
    """
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

    total_predicted = len(pred_ips) + len(pred_domains) + len(pred_hashes)
    if total_predicted == 0:
        return 1.0

    correctly_extracted = (
        len(pred_ips & gt_ips)
        + len(pred_domains & gt_domains)
        + len(pred_hashes & gt_hashes)
    )
    return round(correctly_extracted / total_predicted, 4)


def _ioc_f1(recall: float, precision: float) -> float:
    """
    Compute F1 score as the harmonic mean of IOC recall and precision.

    Returns 0.0 if both recall and precision are zero.
    """
    if recall + precision == 0:
        return 0.0
    return round(2 * recall * precision / (recall + precision), 4)


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
        "tier"                : _get_tier(fid),
        "timestamp_utc"       : datetime.now(timezone.utc).isoformat(),
        # --- security ---
        "guard_blocked"       : None,
        "guard_threat_type"   : None,
        # --- extraction ---
        "schema_conformance"  : None,   # bool
        "ioc_recall"          : None,   # float 0-1
        "ioc_precision"       : None,   # float 0-1
        "ioc_f1"              : None,   # float 0-1
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
    ioc_recall    = _ioc_recall(extracted.iocs, gt["iocs"])
    ioc_precision = _ioc_precision(extracted.iocs, gt["iocs"])
    result["ioc_recall"]    = ioc_recall
    result["ioc_precision"] = ioc_precision
    result["ioc_f1"]        = _ioc_f1(ioc_recall, ioc_precision)
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

def _get_tier(fixture_id: str) -> int:
    """
    Return the tier (1, 2, or 3) of a fixture based on its ID.

    Tier 1: F01–F06 (original 6 fixtures)
    Tier 2: F07–F20 (14 new APT group fixtures)
    Tier 3: F21–F30 (10 edge case fixtures)
    """
    try:
        num_str = fixture_id.split("_")[0][1:]  # e.g. "F01" -> "01"
        num = int(num_str)
        if num <= 6:
            return 1
        elif num <= 20:
            return 2
        else:
            return 3
    except (IndexError, ValueError):
        return 0


def _aggregate(results: list[dict[str, Any]]) -> dict[str, Any]:
    """Compute aggregate metrics across all non-adversarial fixtures, with per-tier breakdown."""
    non_adv = [
        r for r in results
        if not r.get("ground_truth", {}).get("_expected_blocked", False)
        and not (r.get("guard_blocked") and r.get("description", "").find("Adversarial") >= 0)
        and r.get("tier", 0) > 0
    ]
    # Simpler: filter out known adversarial (F06, F30)
    non_adv = [
        r for r in results
        if r.get("schema_conformance") is not None and r["schema_conformance"] is not True.__class__
    ]
    # Simplest reliable approach: exclude fixtures where schema_conformance is boolean True
    # corresponding to guard block detection (adversarial fixtures)
    non_adv = [
        r for r in results
        if r.get("ioc_recall") is not None  # only scored fixtures
    ]

    def _safe_mean(vals: list) -> float | None:
        clean = [v for v in vals if v is not None]
        return round(sum(clean) / len(clean), 4) if clean else None

    def _tier_stats(tier: int) -> dict[str, Any]:
        tier_results = [r for r in non_adv if r.get("tier") == tier]
        if not tier_results:
            return {"count": 0}
        return {
            "count":                   len(tier_results),
            "mean_ioc_recall":         _safe_mean([r["ioc_recall"] for r in tier_results]),
            "mean_ioc_precision":      _safe_mean([r["ioc_precision"] for r in tier_results]),
            "mean_ioc_f1":             _safe_mean([r["ioc_f1"] for r in tier_results]),
            "mean_ttp_recall":         _safe_mean([r["ttp_recall"] for r in tier_results]),
            "schema_conformance_rate": _safe_mean([float(r["schema_conformance"]) for r in tier_results
                                                    if r["schema_conformance"] is not None]),
        }

    # Adversarial guard rate
    adversarial = [r for r in results if r.get("guard_blocked") and r.get("ioc_recall") is None]

    return {
        "total_fixtures"           : len(results),
        "non_adversarial_fixtures" : len(non_adv),
        "schema_conformance_rate"  : _safe_mean([float(r["schema_conformance"]) for r in non_adv
                                                  if r["schema_conformance"] is not None]),
        "mean_ioc_recall"          : _safe_mean([r["ioc_recall"] for r in non_adv]),
        "mean_ioc_precision"       : _safe_mean([r["ioc_precision"] for r in non_adv
                                                  if r["ioc_precision"] is not None]),
        "mean_ioc_f1"              : _safe_mean([r["ioc_f1"] for r in non_adv
                                                  if r["ioc_f1"] is not None]),
        "mean_ttp_recall"          : _safe_mean([r["ttp_recall"] for r in non_adv
                                                  if r["ttp_recall"] is not None]),
        "actor_match_rate"         : _safe_mean([float(r["actor_match"]) for r in non_adv
                                                  if r["actor_match"] is not None]),
        "yaral_first_pass_rate"    : _safe_mean([float(r["yaral_first_pass"]) for r in non_adv
                                                  if r["yaral_first_pass"] is not None]),
        "mean_retry_count"         : _safe_mean([r["retry_count"] for r in non_adv
                                                  if r["retry_count"] is not None]),
        "guard_true_positive_rate" : _safe_mean([float(r["guard_blocked"]) for r in results
                                                  if r.get("ioc_recall") is None
                                                  and r["guard_blocked"] is not None]),
        "tier_breakdown"           : {
            "tier1": _tier_stats(1),
            "tier2": _tier_stats(2),
            "tier3": _tier_stats(3),
        },
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
    W = 115
    print("\n" + "=" * W)
    print(f"  AGENTIC-CTI EVALUATION REPORT  //  {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}")
    print("=" * W)

    # Per-fixture table
    print(f"\n{'ID':<30} {'Tier':>4} {'Guard':>6} {'Schema':>7} {'IOC Rec':>8} {'IOC Pre':>8} {'IOC F1':>7} "
          f"{'TTP Rec':>8} {'Actor':>6} {'YARAL 1st':>10} {'Retries':>8}")
    print("-" * W)

    for r in results:
        guard = "BLOCK" if r["guard_blocked"] else "  OK "
        schema = _bool_str(r["schema_conformance"]) if r["schema_conformance"] is not None else "  N/A "
        tier = r.get("tier", "?")
        print(
            f"{r['id']:<30} {tier:>4} {guard:>6} {schema:>13} "
            f"{_pct(r['ioc_recall']):>14} {_pct(r.get('ioc_precision')):>14} {_pct(r.get('ioc_f1')):>13} "
            f"{_pct(r['ttp_recall']):>14} "
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
        ("Mean IOC Extraction Precision", agg.get("mean_ioc_precision")),
        ("Mean IOC F1 Score         ",  agg.get("mean_ioc_f1")),
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

    # Per-tier breakdown
    tier_breakdown = agg.get("tier_breakdown", {})
    if any(v.get("count", 0) > 0 for v in tier_breakdown.values()):
        print("\n  PER-TIER BREAKDOWN")
        print("  " + "-" * 80)
        tier_labels = {
            "tier1": "Tier 1 — Original (F01–F06)",
            "tier2": "Tier 2 — APT Groups (F07–F20)",
            "tier3": "Tier 3 — Edge Cases (F21–F30)",
        }
        for tier_key, tier_label in tier_labels.items():
            td = tier_breakdown.get(tier_key, {})
            if not td or td.get("count", 0) == 0:
                continue
            print(f"\n  {tier_label} [{td['count']} fixtures]")
            print(f"    IOC Recall:    {_pct(td.get('mean_ioc_recall'))}")
            print(f"    IOC Precision: {_pct(td.get('mean_ioc_precision'))}")
            print(f"    IOC F1:        {_pct(td.get('mean_ioc_f1'))}")
            print(f"    TTP Recall:    {_pct(td.get('mean_ttp_recall'))}")
            print(f"    Schema Rate:   {_pct(td.get('schema_conformance_rate'))}")

    print("=" * W + "\n")


def _render_html(results: list[dict[str, Any]], agg: dict[str, Any]) -> str:
    """Render results as a self-contained HTML report."""
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    rows = ""
    for r in results:
        def pct_cell(v):
            if v is None:
                return "<td>N/A</td>"
            pct = v * 100
            color = "#22c55e" if pct >= 80 else ("#f59e0b" if pct >= 50 else "#ef4444")
            return f'<td style="color:{color};font-weight:bold">{pct:.1f}%</td>'
        guard_cell = '<td style="color:#ef4444">BLOCK</td>' if r["guard_blocked"] else '<td style="color:#22c55e">OK</td>'
        schema_cell = '<td style="color:#22c55e">PASS</td>' if r["schema_conformance"] else '<td style="color:#ef4444">FAIL</td>'
        rows += (
            f"<tr><td>{r['id']}</td><td>{r.get('tier','?')}</td>"
            f"{guard_cell}{schema_cell}"
            f"{pct_cell(r['ioc_recall'])}{pct_cell(r.get('ioc_precision'))}{pct_cell(r.get('ioc_f1'))}"
            f"{pct_cell(r['ttp_recall'])}"
            f"<td>{'PASS' if r.get('actor_match') else ('FAIL' if r.get('actor_match') is not None else 'N/A')}</td>"
            f"<td>{'PASS' if r.get('yaral_first_pass') else ('FAIL' if r.get('yaral_first_pass') is not None else 'N/A')}</td>"
            f"<td>{r['retry_count'] if r['retry_count'] is not None else 'N/A'}</td></tr>\n"
        )
    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Agentic-CTI Eval Report {ts}</title>
  <style>
    body {{ font-family: 'Segoe UI', monospace; background: #0f172a; color: #e2e8f0; padding: 2rem; }}
    h1 {{ color: #38bdf8; }}
    table {{ border-collapse: collapse; width: 100%; font-size: 0.85rem; }}
    th, td {{ border: 1px solid #334155; padding: 6px 10px; text-align: left; }}
    th {{ background: #1e293b; color: #94a3b8; text-transform: uppercase; font-size: 0.75rem; }}
    tr:nth-child(even) {{ background: #1e293b; }}
    .agg {{ background: #1e293b; border-radius: 8px; padding: 1rem; margin-top: 2rem; }}
    .agg h2 {{ color: #38bdf8; margin: 0 0 1rem; }}
    .metric {{ display: flex; justify-content: space-between; border-bottom: 1px solid #334155; padding: 4px 0; }}
  </style>
</head>
<body>
  <h1>Agentic-CTI Evaluation Report</h1>
  <p style="color:#94a3b8">{ts}</p>
  <table>
    <thead><tr>
      <th>Fixture ID</th><th>Tier</th><th>Guard</th><th>Schema</th>
      <th>IOC Rec</th><th>IOC Pre</th><th>IOC F1</th><th>TTP Rec</th>
      <th>Actor</th><th>YARAL 1st</th><th>Retries</th>
    </tr></thead>
    <tbody>
      {rows}
    </tbody>
  </table>
  <div class="agg">
    <h2>Aggregate Metrics</h2>
    {''.join(f'<div class="metric"><span>{k}</span><span>{round(v*100,1)}% ' + '</span></div>' if isinstance(v, float) else f'<div class="metric"><span>{k}</span><span>{v}</span></div>' for k, v in agg.items() if not isinstance(v, dict) and v is not None)}
  </div>
</body>
</html>"""
    return html


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
        help="Path to save results JSON (or HTML if --html). Defaults to tests/eval/results/run_<ts>.json",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Skip LLM calls. Only evaluates the prompt guard.",
    )
    parser.add_argument(
        "--live",
        action="store_true",
        help="Explicitly invoke the full LLM pipeline (overrides --dry-run if both given).",
    )
    parser.add_argument(
        "--html",
        action="store_true",
        help="Save an HTML report instead of JSON.",
    )
    args = parser.parse_args()

    # --live takes precedence over --dry-run
    dry_run = args.dry_run and not args.live

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
          f"{' [DRY RUN]' if dry_run else ' [LIVE]'}...\n")

    results = []
    for fixture in fixture_list:
        logger.info("--- Evaluating: %s ---", fixture["id"])
        r = _evaluate_fixture(fixture, dry_run=dry_run)
        results.append(r)

    agg = _aggregate(results)
    print_report(results, agg)

    # Save results
    output_path = args.output
    if output_path is None:
        ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        output_dir = _REPO_ROOT / "tests" / "eval" / "results"
        output_dir.mkdir(parents=True, exist_ok=True)
        ext = "html" if args.html else "json"
        output_path = str(output_dir / f"run_{ts}.{ext}")

    if args.html:
        html_content = _render_html(results, agg)
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(html_content)
        print(f"HTML report saved to: {output_path}\n")
    else:
        payload = {"aggregate": agg, "fixtures": results}
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2, default=str)
        print(f"Results saved to: {output_path}\n")


if __name__ == "__main__":
    main()
