# Agentic-CTI Evaluation Architecture

This document explains how the benchmark numbers in the README were produced,
how the two evaluation systems relate to each other, and how to reproduce results.

---

## Two Evaluation Systems

### 1. Deterministic Regression Gate — `tests/eval/eval_runner.py`

**This is the authoritative benchmark system.** Source of the **98.8% IOC F1**,
**0.0% FP rate**, and **100% Prompt Guard TPR** headline metrics.

| Property | Detail |
|---|---|
| **Fixture dataset** | `tests/data/eval_fixtures_v1.json` (30 fixtures, version-controlled) |
| **Scoring method** | Exact match / set intersection — fully deterministic, no LLM calls during scoring |
| **Metrics** | IOC F1/Precision/Recall, TTP Recall, Schema Conformance, YARA-L/Sigma/KQL first-pass rate, FP rate (125-event benign set), Prompt Guard TPR |
| **CI integration** | Dry-run on every PR (no API key needed); live-eval on `run-live-eval` label or nightly schedule |
| **Reproducibility** | Deterministic per fixture; variance comes from LLM — run multiple times and report mean |

Why deterministic over LLM-graded scoring: exact F1 (set intersection of
extracted vs. ground-truth IOCs, normalised for case/whitespace) is more
reproducible and auditable than LLM-as-judge scoring. The deterministic gate
catches regressions reliably; the semantic suite catches qualitative drift.

---

### 2. Semantic Assessment — `evals/deepeval_suite.py`

**Offline, LLM-as-judge quality assessment.** Does **not** produce the headline
benchmark numbers.

| Property | Detail |
|---|---|
| **Fixture dataset** | Same `tests/data/eval_fixtures_v1.json` (via `EVAL_FIXTURES` alias) |
| **Scoring method** | LLM-as-judge via DeepEval: Faithfulness, AnswerRelevancy, Hallucination |
| **Run frequency** | Offline only (not in CI) — consumes ~90-150 LLM API calls per full suite |
| **Judge model** | Configurable via `DEEPEVAL_MODEL` env var |
| **Purpose** | Catch qualitative regressions (narrative coherence, hallucinated IOCs) that exact-match F1 cannot surface |

> **Important:** LLM-as-judge metrics are probabilistic. The deterministic gate
> is ground truth for CI gating decisions. The semantic suite is supplementary signal.

---

## Ground-Truth Dataset

**File:** `tests/data/eval_fixtures_v1.json`

Each fixture includes provenance fields so results are self-describing:

```json
{
  "id": "F01_apt41_baseline",
  "tier": 1,
  "description": "APT41 telecom campaign — full IOC set, 2 malware families",
  "benchmark_model": "meta-llama/llama-4-scout-17b-16e-instruct",
  "benchmark_provider": "groq",
  "benchmark_date": "2026-07-08",
  "report_text": "...",
  "ground_truth": {
    "threat_actor": "APT41",
    "alt_actors": ["Double Dragon", "APT 41"],
    "malware_families": ["KEYPLUG", "DEADEYE"],
    "mitre_ttps": ["T1566.001", "T1059.001", "T1055", "T1071.001"],
    "iocs": {
      "ips": ["203.0.113.45", "198.51.100.22"],
      "domains": ["backup.evil-apt41.com", "update.apt41-c2.net"],
      "hashes": ["3b4c5d6e...", "aabbccdd..."]
    }
  }
}
```

> The v1 dataset was benchmarked against `meta-llama/llama-4-scout-17b-16e-instruct`
> (Groq, 2026-07-08). Current active provider is Gemini `gemini-3.5-flash` — re-run
> in progress. Ground truth is model-independent; only the `benchmark_model` provenance
> field updates as fixtures are re-validated against a new provider.

---

## Fixture Tiers

| Tier | Fixtures | Description |
|---|---|---|
| Tier 1 | F01-F06 | Baseline APT reports + 2 adversarial injection fixtures |
| Tier 2 | F07-F20 | Named APT groups (APT28/29, Sandworm, Kimsuky, REvil, Conti, etc.) |
| Tier 3 | F21-F30 | Edge cases: no IOCs, noisy PDF text, multi-actor, very long report, additional adversarial |

Adversarial fixtures (F06, F30) have `"_expected_blocked": true` in `ground_truth`.
They are excluded from extraction scoring but included in Prompt Guard TPR.

---

## CI/CD Integration

Defined in `.github/workflows/eval_gate.yml`:

| Stage | Trigger | What runs | API keys |
|---|---|---|---|
| **dry-run** | Every PR to `main` | Fixture loading, prompt guard scan x30, import validation | None |
| **live-eval** | `run-live-eval` label / nightly / manual dispatch | 5 representative fixtures; fails if IOC F1 < 90% or Guard TPR < 100% | `GROQ_API_KEY` secret |

**Regression thresholds:** IOC F1 >= 90% | Prompt Guard TPR = 100%

---

## Reproducing the 98.8% Benchmark

```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. Set your LLM API key (any supported provider)
export GEMINI_API_KEY=your_key   # or GROQ_API_KEY / OPENROUTER_API_KEY

# 3. Full 30-fixture live run
python tests/eval/eval_runner.py --live

# 4. Single fixture
python tests/eval/eval_runner.py --fixture F01_apt41_baseline --live

# 5. HTML report
python tests/eval/eval_runner.py --live --html --output report.html

# 6. Dry-run (no API calls — validates fixture loading and prompt guard only)
python tests/eval/eval_runner.py --dry-run
```

LLMs are non-deterministic. IOC F1 typically varies +-1-2% across runs.
The reported 98.8% is the mean of a single full run on `llama-4-scout-17b-16e-instruct`
(Groq) on 2026-07-08.

---

## Running the Semantic Assessment

```bash
pip install "deepeval>=1.0.0"

# Full suite (~90-150 LLM API calls)
python evals/deepeval_suite.py

# Single fixture
python evals/deepeval_suite.py --fixture F01_apt41_baseline

# List what would run without executing
python evals/deepeval_suite.py --dry-run
```

Results saved to `evals/last_run_results.json`. DeepEval metrics supplement
the deterministic F1 scores and are not used for CI gating decisions.

---

## Adding New Fixtures

1. Add the fixture dict to `tests/data/eval_fixtures_v1.json` following the
   schema above. Set `benchmark_model`, `benchmark_provider`, `benchmark_date`
   to current values.
2. Validate: `python tests/eval/eval_runner.py --fixture <new_id> --live`
3. Commit the JSON dataset update.
4. Do **not** modify `tests/eval/fixtures.py` for new fixtures — it is now a
   legacy compatibility shim. The JSON dataset is the authoritative source.
