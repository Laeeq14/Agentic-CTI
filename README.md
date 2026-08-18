# Agentic-CTI 🛡️

**A fully containerized, agentic threat triage engine powered by LangGraph, Elasticsearch, and Groq Llama-3.3-70b.**

This is not an LLM wrapper. It is an end-to-end SOC automation platform that accepts raw threat advisories *and* live Elasticsearch log streams, and converts both into validated detection rules in three formats — YARA-L 2.0 (Google SecOps), Sigma (SIEM-agnostic), and KQL (Microsoft Sentinel) — with a quantifiable extraction F1 score across a 30-fixture benchmark suite, false-positive rate measurement against a 125-event benign traffic dataset, per-run latency and cost tracking, and a MITRE ATT&CK Navigator layer export.

---

## 📈 Benchmark Results — 30-Fixture Live Evaluation

*Verified 2026-07-08 · Groq `meta-llama/llama-4-scout-17b-16e-instruct` · 30 fixtures across 3 tiers (Tier 1: baselines, Tier 2: APT groups, Tier 3: edge cases)*

| Metric | Score |
|---|---|
| **IOC Extraction F1** | **98.8%** |
| **IOC Extraction Recall** | 98.8% |
| **IOC Extraction Precision** | 98.8% |
| **TTP Extraction Recall** | **99.1%** |
| **Threat Actor Match Rate** | 96.4% |
| **YARA-L First-Pass Rate** | **92.9%** |
| **Sigma First-Pass Rate** | **96.4%** |
| **KQL Generation Rate** | **100.0%** |
| **Schema Conformance Rate** | **100.0%** |
| **Prompt Guard True-Positive Rate** | **100.0%** |
| **Mean FP Rate — YARA-L** (125-event benign set) | **0.0%** |
| **Mean FP Rate — Sigma** | **0.0%** |
| **Mean FP Rate — KQL** | **0.0%** |
| Mean YARA-L Retry Count | 0.071 |
| Mean Pipeline Latency | ~18s |
| Estimated Cost per Analysis | ~$0.0004 |

**Per-Tier IOC F1:**

| Tier | Fixtures | IOC F1 | TTP Recall | Schema | YARA-L 1st Pass | FP Rate |
|---|---|---|---|---|---|---|
| Tier 1 — Baseline (F01–F06) | 5 scorable | 100.0% | 100.0% | 100.0% | 100.0% | 0.0% |
| Tier 2 — APT Groups (F07–F20) | 14 fixtures | 100.0% | 100.0% | 100.0% | 92.9% | 0.0% |
| Tier 3 — Edge Cases (F21–F30) | 9 scorable | 96.3% | 97.2% | 100.0% | 88.9% | 0.0% |

> **Notable:** Both adversarial prompt-injection fixtures (F06, F30) were correctly blocked before reaching the LLM — 0 pipeline calls made on malicious input. The two YARA-L retries (F12 TA505, F20 APT36) auto-corrected on the first retry via the validator feedback loop. FP rate measured against 125 synthetic benign events covering DNS, network connections, process launches, and file creation events.

---

## ⚡ What Makes This Different

| Capability | Detail |
|---|---|
| **Dual ingestion paths** | Text threat reports *and* live Elasticsearch log queries both produce detection rules through the same pipeline |
| **Triple rule output** | Generates YARA-L 2.0 (Google SecOps), Sigma (SIEM-agnostic), and KQL (Microsoft Sentinel) from a single analysis pass |
| **Parallel generation** | Sigma and KQL fan out from RAG simultaneously (LangGraph parallel branches on separate OS threads), then join before YARA-L — ~2× faster than sequential |
| **Rate-limit resilience** | Three-account Groq API key pool; on a 429 the pipeline rotates to the next account immediately (no sleep) before falling back to Retry-After-based backoff with ±2s jitter. Thread-safe writes guarded by `threading.Lock` — parallel branches cannot produce lost-update corruption on the shared key index |
| **FP rate measurement** | Rules checked against a 125-event benign traffic dataset; rules exceeding 5% FP rate are flagged `needs_review` before the analyst sees them |
| **Navigator export** | `/api/navigator-layer` endpoint emits ATT&CK Navigator v4.9 layers with frequency-proportional color gradients |
| **CI/CD regression gate** | GitHub Actions workflow runs dry-run eval on every PR; live subset with IOC F1 ≥ 90% and Guard TPR = 100% thresholds on `run-live-eval` label — guards against silent LLM regression |
| **Fully containerized** | 4-service Docker stack: Qdrant + Elasticsearch + FastAPI backend + Streamlit SOC dashboard |
| **Programmatic API** | FastAPI backend: `/api/analyze`, `/api/query-logs`, `/api/navigator-layer`, `/api/formats` — CI/CD ready |
| **Cloud-native** | Single-command Terraform deploy to AWS ECS Fargate behind an Application Load Balancer |
| **Quantified accuracy** | 30-fixture eval suite measuring IOC F1, TTP Recall, Sigma/KQL first-pass rate, FP rate (all 3 formats), latency, and cost |
| **Prompt injection hardened** | 7-category regex guard runs in < 1ms before every LLM call |
| **Zero-hallucination validator** | 9-check YARA-L structural validator with automatic LLM retry loop (up to 3 attempts) |

---

## 🏗️ Architecture

```
                         ┌─────────────────────────────┐
  Threat Report (text) ──►                             │
                         │   FastAPI Backend            │──► POST /api/analyze
  ES Log Query ──────────►   (api/main.py)             │──► POST /api/query-logs
                         │                             │──► POST /api/navigator-layer
                         └──────────┬──────────────────┘
                                    │
                         ┌──────────▼───────────────────────────────────────────┐
                         │          LangGraph State Machine (agent.py)         │
                         │                                                     │
                         │  [Node 0] Prompt Injection Guard                    │
                         │       ↓                                             │
                         │  [Node 1] LLM Threat Intel Extraction               │
                         │       ↓                                             │
                         │  [Node 2] Qdrant RAG Contextualization              │
                         │       ↓              ↓ (parallel fan-out)           │
                         │  [Node 3a] Sigma   [Node 3b] KQL                   │
                         │  (SIEM-agnostic)  (Microsoft Sentinel)              │
                         │       ↓              ↓ (join)                       │
                         │  [Node 3c] YARA-L 2.0 Generation (Llama-3.3-70b)  │
                         │       ↓                                             │
                         │  [Node 4] Structural Validator (9 checks)          │
                         │       ↓ (retry loop on fail, max 3×)               │
                         │  [Node 5] Finalize + Qdrant store                  │
                         └─────────────────────────────────────────────────────┘
                                    │
              ┌─────────────────────┼──────────────────────┐
              ▼                     ▼                      ▼
         Qdrant DB           Elasticsearch          Streamlit SOC
       (vector store,       (log index,              Dashboard
        RAG context)         500+ events)            (app.py)
```

---

## 🐳 Docker Stack — Up in One Command

```bash
# Clone and configure
git clone https://github.com/Laeeq14/Agentic-CTI.git
cd Agentic-CTI
cp .env.example .env          # add your GROQ_API_KEY

# Spin up all 4 services
docker-compose up --build
```

| Service | Port | Purpose |
|---|---|---|
| `qdrant` | 6333 | Vector database — stores threat report embeddings for RAG |
| `elasticsearch` | 9200 | Security log store — indexed attack log events |
| `fastapi-backend` | 8000 | Programmatic API — wraps the LangGraph pipeline |
| `app` (Streamlit) | 8501 | SOC analyst dashboard — calls FastAPI backend |

Health checks and `depends_on` chaining ensure services start in the correct order.

---

## 🔌 API Reference

The FastAPI backend is fully documented at `http://localhost:8000/api/docs` (Swagger UI).

### Analyze a Threat Report
Returns extracted threat intel + RAG context hits + validated rules in **all three formats** (YARA-L 2.0, Sigma, KQL).
```bash
curl -X POST http://localhost:8000/api/analyze \
  -H "Content-Type: application/json" \
  -d '{"text": "APT41 deployed KEYPLUG via spear-phishing. C2: 203.0.113.45, backup.evil-apt41.com. TTPs: T1566.001, T1059.001."}'
# Response fields: extracted_report, rag_context, final_yaral_rule, sigma_rule, kql_query, security_scan
```

When `API_KEY` is set, add the header:
```bash
  -H "X-API-Key: your-api-key"
```

### Query Elasticsearch Logs
Same output format as `/api/analyze` — synthesizes threat intel from live log events then generates all three rule formats.
```bash
curl -X POST http://localhost:8000/api/query-logs \
  -H "Content-Type: application/json" \
  -d '{"query": "event_type:NETWORK_CONNECTION AND dest_ip:185.220.101.47", "index": "agentic-cti-logs", "size": 50}'
```

### Export MITRE ATT&CK Navigator Layer
Two modes — direct TTP list (no LLM call) or pipeline extraction from raw report text:
```bash
# Mode 1: direct TTP list (fast, no Groq call)
curl -X POST http://localhost:8000/api/navigator-layer \
  -H "Content-Type: application/json" \
  -d '{"ttps": ["T1059.001", "T1071.001", "T1041", "T1566.001"], "name": "APT41 Campaign"}'

# Mode 2: extract TTPs from raw reports and build layer (one Groq call per report)
curl -X POST http://localhost:8000/api/navigator-layer \
  -H "Content-Type: application/json" \
  -d '{"reports": ["APT41 deployed KEYPLUG..."], "name": "Multi-report Landscape"}'
# Returns: layer (Navigator v4.9 JSON), ttp_count, total_observations, mode
# Load the 'layer' field directly at https://mitre-attack.github.io/attack-navigator/
```

### List Supported Rule Formats
```bash
curl http://localhost:8000/api/formats
# Returns: format IDs, platform targets, response field names, and descriptions
```

---

## 📊 Elasticsearch Log Ingestion

Load the included 500-event synthetic attack dataset (DNS exfiltration, Cobalt Strike beaconing, Mimikatz, lateral movement via RDP, C2 over HTTPS):

```bash
python data/loader.py --es-url http://localhost:9200 --index agentic-cti-logs
```

Verify:
```bash
curl http://localhost:9200/agentic-cti-logs/_count
# → {"count": 500, ...}
```

Dataset covers: Log4j exploit pattern, Cobalt Strike HTTP beaconing, Mimikatz process launches, RDP lateral movement, HTTPS C2 with known-bad domains.

---

## 🧪 Evaluation Benchmark — 30 Fixture Suite

The pipeline ships with a deterministic evaluation framework and a DeepEval LLM-graded suite.

### Run the Benchmark

```bash
# Dry-run (guard + schema checks only, no LLM calls)
python tests/eval/eval_runner.py --dry-run

# Single fixture live run
python tests/eval/eval_runner.py --fixture F01_apt41_baseline

# Full 30-fixture live run (consumes Groq API quota)
python tests/eval/eval_runner.py --live

# Export HTML report
python tests/eval/eval_runner.py --live --html

# DeepEval LLM-graded suite (Faithfulness, AnswerRelevancy, Hallucination)
python evals/deepeval_suite.py
```

### Fixture Tiers

| Tier | Fixtures | Coverage |
|---|---|---|
| **Tier 1** — Baseline | F01–F06 | APT41, Lazarus, SideWinder, ALPHV, Turla, adversarial injection |
| **Tier 2** — APT Groups | F07–F20 | APT28/Fancy Bear, APT29/Cozy Bear, Sandworm, Kimsuky, MuddyWater, TA505, REvil, Conti, BlackBasta, FIN7, Scattered Spider, Volt Typhoon, Salt Typhoon, APT36/Transparent Tribe |
| **Tier 3** — Edge Cases | F21–F30 | No-IOC reports, no-TTP reports, noisy PDF text, very long reports (25k chars), multi-actor, vendor reports, Log4j mass exploitation, SolarWinds-style supply chain, role-override injection |

### Metrics Tracked

- **IOC Extraction Recall** — did we find all ground-truth IOCs?
- **IOC Extraction Precision** — did we hallucinate any extra IOCs?
- **IOC F1 Score** — harmonic mean of above
- **TTP Extraction Recall** — MITRE ATT&CK technique coverage
- **Schema Conformance Rate** — is the extracted JSON always valid?
- **Guard True-Positive Rate** — does the injection guard block adversarial fixtures?
- **YARA-L First-Pass Rate** — rules passing structural validation on the first attempt (without retry)
- **Sigma First-Pass Rate** — Sigma YAML rules passing structural validation on the first attempt
- **KQL Generation Rate** — percentage of fixtures that produced a usable KQL query
- **Mean FP Rate (YARA-L / Sigma / KQL)** — fraction of 125 benign events matched by the rule; rules exceeding 5% are flagged `needs_review`
- **Mean Pipeline Latency** — wall-clock seconds from input to finalized output; includes any rate-limit backoff sleep
- **Rate-limit Backoff Sleep (`rate_limit_sleep_s`)** — seconds spent sleeping for Retry-After backoff across the run; non-zero values mean `Mean Pipeline Latency` is inflated and the eval report will print the adjusted net inference latency separately
- **Estimated Cost per Analysis** — approximate Groq API cost based on token count heuristics

> Run `python tests/eval/eval_runner.py --live` to generate your own benchmark results.

---

## ☁️ AWS Deployment (Terraform)

Deploy to ECS Fargate behind an Application Load Balancer in **us-east-2 (Ohio)**:

```bash
cd terraform
terraform init
terraform plan -var="groq_api_key=gsk_xxxx"
terraform apply -var="groq_api_key=gsk_xxxx"
```

**Resources provisioned:**
- VPC with public/private subnets across 2 AZs + NAT Gateway
- Application Load Balancer: `/api/*` → FastAPI task, `/*` → Streamlit task
- ECS Fargate cluster with 2 task definitions (FastAPI + Streamlit)
- ECR repositories for both Docker images
- AWS Secrets Manager for `GROQ_API_KEY` — never stored in plaintext
- S3 bucket (versioned, AES-256 encrypted) for threat report uploads
- Least-privilege IAM roles for execution and task permissions
- CloudWatch log groups for both services (14-day retention)

After `apply`, the ALB DNS name is emitted as a Terraform output:
```
alb_dns_name = "agentic-cti-alb-xxxx.us-east-2.elb.amazonaws.com"
```

---

## 🔒 Security Design

| Layer | Mechanism |
|---|---|
| **Prompt injection guard** | 7 threat categories, regex-based, < 1ms, runs before every LLM call |
| **YARA-L validator** | 9 deterministic structural checks; LLM retries on failure (max 3×) |
| **API key management** | `GROQ_API_KEY` (+ optional `GROQ_API_KEY_2/3`) loaded from `.env` locally; AWS Secrets Manager in production. On a 429, the pipeline rotates to the next account before sleeping — see `.env.example` |
| **API key enforcement** | Optional `X-API-Key` header auth on all `/api/*` endpoints — set `API_KEY` env var to enable; transparent no-op in dev mode when unset |
| **Least-privilege IAM** | Separate execution role (pull secrets, write logs) and task role (S3 only) |
| **ES auth** | Controlled by `ES_SECURITY_ENABLED` env var — `false` by default for local dev; set to `true` in `.env` with `ELASTIC_PASSWORD` for production (volume must be cleared on first toggle) |
| **CORS** | Controlled by `CORS_ALLOWED_ORIGINS` env var — defaults to `*` for local dev; set to a comma-separated origin whitelist (e.g. `https://soc.example.com`) for production |
| **CI/CD regression gate** | GitHub Actions dry-run eval on every PR; live subset with F1 ≥ 90% threshold on label trigger |

---

## 🛠️ Local Development Setup

**Prerequisites:** Python 3.11+, Docker Desktop, a [Groq API key](https://console.groq.com)

```bash
# Python environment
python -m venv .venv
.venv\Scripts\activate          # Windows
pip install -r requirements.txt

# Environment — copy the template and fill in your key(s)
cp .env.example .env

# Required: primary Groq account
# GROQ_API_KEY=gsk_xxxx

# Optional: overflow accounts for rate-limit rotation.
# The pipeline rotates to the next key on a 429 before sleeping.
# GROQ_API_KEY_2=gsk_xxxx
# GROQ_API_KEY_3=gsk_xxxx

# Run Streamlit directly (connects to local Qdrant)
streamlit run app.py

# Run FastAPI directly
uvicorn api.main:app --reload --port 8000
```

---

## 📁 Project Structure

```
Agentic-CTI/
|
+-- .github/
|   +-- workflows/
|       +-- eval_gate.yml       # CI/CD: dry-run on every PR; live regression gate on label
|
+-- agent.py                    # LangGraph pipeline — all nodes + graph topology
+-- app.py                      # Streamlit SOC dashboard
+-- prompts.py                  # All LLM system/user prompts (extraction, YARA-L, Sigma, KQL)
+-- validator.py                # YARA-L 2.0 structural validator (9 checks, retry feedback)
+-- sigma_validator.py          # Sigma YAML structural validator (6 checks)
+-- vector_store.py             # Qdrant wrapper — embed, store, RAG search
|
+-- api/
|   +-- main.py                 # FastAPI — /analyze, /query-logs, /navigator-layer, /formats
|   +-- es_client.py            # Elasticsearch client — search_logs(), get_index_stats()
|   +-- Dockerfile              # Multi-stage build for FastAPI service
|
+-- data/
|   +-- loader.py               # Bulk-index NDJSON dataset into Elasticsearch
|   +-- logs/
|       +-- sample_bots_v1.json # 500-event synthetic attack log dataset
|       +-- benign_traffic.json # 125-event benign dataset for FP rate evaluation
|
+-- src/
|   +-- security/
|   |   +-- prompt_guard.py     # 7-category prompt injection guard (<1ms, pre-LLM)
|   +-- navigator/
|   |   +-- navigator_export.py # ATT&CK Navigator v4.9 layer builder
|   +-- ingestion/
|   |   +-- watcher.py          # Async file watcher for watch_inbox/
|   +-- ttp_logsource_map.py    # TTP -> Sigma logsource + KQL table routing map
|
+-- tests/eval/
|   +-- fixtures.py             # 30 ground-truth fixtures across 3 tiers
|   +-- eval_runner.py          # Deterministic eval: IOC F1, TTP recall, FP rate, latency
|   +-- fp_evaluator.py         # False-positive evaluator against benign_traffic.json
|
+-- evals/
|   +-- deepeval_suite.py       # LLM-graded: Faithfulness, AnswerRelevancy, Hallucination
|
+-- terraform/
|   +-- main.tf                 # AWS ECS Fargate, ALB, ECR, S3, Secrets Manager, IAM
|   +-- variables.tf            # Input variables (region, env, cpu, memory)
|   +-- outputs.tf              # ALB DNS, ECR URLs, cluster name
|
+-- docker-compose.yml          # 4-service local stack (ES auth env-var toggled)
+-- Dockerfile                  # Multi-stage build for Streamlit service
+-- requirements.txt            # All dependencies
```

---

## 🤖 Model

- **LLM:** Groq `meta-llama/llama-4-scout-17b-16e-instruct` — extraction, YARA-L generation, log synthesis
- **Embeddings:** `all-MiniLM-L6-v2` (sentence-transformers, local, no API key)
- **Vector DB:** Qdrant (cosine similarity, persistent local volume)
- **Log DB:** Elasticsearch 8.13 (single-node for dev, cluster-ready for prod)
- **API key pool:** Up to 3 Groq accounts (`GROQ_API_KEY`, `GROQ_API_KEY_2`, `GROQ_API_KEY_3`); rotated on 429 via sticky round-robin before Retry-After sleep

---

## 📄 License

MIT
