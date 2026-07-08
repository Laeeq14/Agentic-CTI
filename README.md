# Agentic-CTI 🛡️

**A fully containerized, log-ingesting threat triage engine powered by LangGraph, Elasticsearch, and Groq Llama-3.3-70b.**

This is not an LLM wrapper. It is an end-to-end SOC automation platform that accepts two types of raw security data — unstructured threat advisories *and* live Elasticsearch log streams — and converts both into validated YARA-L 2.0 detection rules ready for deployment in Google SecOps, with a quantifiable extraction F1 score across a 30-fixture benchmark suite.

---

## 📈 Benchmark Results — 30-Fixture Live Evaluation

*Verified 2026-07-08 · Groq `llama-3.3-70b-versatile` · 30 fixtures across 3 tiers (Tier 1: baselines, Tier 2: APT groups, Tier 3: edge cases)*

| Metric | Score |
|---|---|
| **IOC Extraction F1** | **98.8%** |
| **IOC Extraction Recall** | 98.8% |
| **IOC Extraction Precision** | 98.8% |
| **TTP Extraction Recall** | **99.1%** |
| **Threat Actor Match Rate** | 96.4% |
| **YARA-L First-Pass Rate** | **92.9%** |
| **Schema Conformance Rate** | **100.0%** |
| **Prompt Guard True-Positive Rate** | **100.0%** |
| Mean Retry Count (YARA-L generation) | 0.071 |

**Per-Tier IOC F1:**

| Tier | Fixtures | IOC F1 | TTP Recall | Schema |
|---|---|---|---|---|
| Tier 1 — Baseline (F01–F06) | 5 scorable | 100.0% | 100.0% | 100.0% |
| Tier 2 — APT Groups (F07–F20) | 14 fixtures | 100.0% | 100.0% | 100.0% |
| Tier 3 — Edge Cases (F21–F30) | 9 scorable | 96.3% | 97.2% | 100.0% |

> **Notable:** Both adversarial prompt-injection fixtures (F06, F30) were correctly blocked before reaching the LLM — 0 pipeline calls made on malicious input. The two YARA-L retries (F12 TA505, F20 APT36) auto-corrected on the first retry via the validator feedback loop.

---

## ⚡ What Makes This Different

| Capability | Detail |
|---|---|
| **Dual ingestion paths** | Text threat reports *and* live Elasticsearch log queries both produce YARA-L rules through the same pipeline |
| **Fully containerized** | 4-service Docker stack: Qdrant + Elasticsearch + FastAPI backend + Streamlit SOC dashboard |
| **Programmatic API** | FastAPI backend exposes `/api/analyze`, `/api/query-logs`, `/api/health`, `/api/stats` — CI/CD ready |
| **Cloud-native** | Single-command Terraform deploy to AWS ECS Fargate behind an Application Load Balancer |
| **Quantified accuracy** | 30-fixture eval suite (3 tiers) measuring IOC Precision, IOC Recall, IOC F1, TTP Recall, schema conformance, and guard true-positive rate |
| **Prompt injection hardened** | 7-category regex guard runs in < 1ms before every LLM call |
| **Zero-hallucination validator** | 9-check YARA-L structural validator with automatic LLM retry loop (up to 3 attempts) |

---

## 🏗️ Architecture

```
                         ┌─────────────────────────────┐
  Threat Report (text) ──►                             │
                         │   FastAPI Backend            │──► POST /api/analyze
  ES Log Query ──────────►   (api/main.py)             │──► POST /api/query-logs
                         └──────────┬──────────────────┘
                                    │
                         ┌──────────▼──────────────────────────────────────────┐
                         │          LangGraph State Machine (agent.py)         │
                         │                                                     │
                         │  text_report path:                                  │
                         │  [Node 0] Prompt Injection Guard                    │
                         │       ↓                                             │
                         │  [Node 1] LLM Threat Intel Extraction               │
                         │       ↓                                             │
                         │  log_query path (merges here):                      │
                         │  [Node 0.5] Elasticsearch Log Query                 │
                         │  [Node 1.5] LLM Log Synthesis → threat intel JSON   │
                         │       ↓                                             │
                         │  [Node 2] Qdrant RAG Contextualization              │
                         │       ↓                                             │
                         │  [Node 3] YARA-L 2.0 Generation (Llama-3.3-70b)   │
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
```bash
curl -X POST http://localhost:8000/api/analyze \
  -H "Content-Type: application/json" \
  -d '{"text": "APT41 deployed KEYPLUG via spear-phishing. C2: 203.0.113.45, backup.evil-apt41.com. TTPs: T1566.001, T1059.001."}'
```

### Query Elasticsearch Logs
```bash
curl -X POST http://localhost:8000/api/query-logs \
  -H "Content-Type: application/json" \
  -d '{"query": "event_type:NETWORK_CONNECTION AND dest_ip:185.220.101.47", "index": "agentic-cti-logs", "size": 50}'
```

Both endpoints return the same JSON structure: extracted threat intel, RAG context hits, and the validated YARA-L 2.0 rule.

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
- **YARA-L First-Pass Validation Rate** — rules passing on the first attempt

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
| **API key management** | `GROQ_API_KEY` loaded from `.env` locally; AWS Secrets Manager in production |
| **Least-privilege IAM** | Separate execution role (pull secrets, write logs) and task role (S3 only) |
| **ES no-auth** | Security disabled for local dev only; enable `xpack.security` for production |
| **CORS** | Open in development; restrict via environment variable in production |

---

## 🛠️ Local Development Setup

**Prerequisites:** Python 3.11+, Docker Desktop, a [Groq API key](https://console.groq.com)

```bash
# Python environment
python -m venv .venv
.venv\Scripts\activate          # Windows
pip install -r requirements.txt

# Environment
echo "GROQ_API_KEY=gsk_xxxx" > .env

# Run Streamlit directly (connects to local Qdrant)
streamlit run app.py

# Run FastAPI directly
uvicorn api.main:app --reload --port 8000
```

---

## 📁 Project Structure

```
Agentic-CTI/
├── agent.py              # LangGraph pipeline — all nodes + graph construction
├── app.py                # Streamlit SOC dashboard
├── prompts.py            # All LLM system/user prompts
├── validator.py          # YARA-L 2.0 structural validator (9 checks)
├── vector_store.py       # Qdrant wrapper — embed, store, RAG search
│
├── api/
│   ├── main.py           # FastAPI app — /analyze, /query-logs, /health, /stats
│   ├── es_client.py      # Elasticsearch client — search_logs(), get_index_stats()
│   └── Dockerfile        # Multi-stage build for FastAPI service
│
├── data/
│   ├── loader.py         # Bulk-index NDJSON dataset into Elasticsearch
│   └── logs/
│       └── sample_bots_v1.json  # 500-event synthetic attack log dataset
│
├── src/
│   ├── security/
│   │   └── prompt_guard.py  # 7-category injection guard
│   └── ingestion/
│       └── watcher.py       # Async file watcher for watch_inbox/
│
├── tests/eval/
│   ├── fixtures.py       # 30 ground-truth fixtures (3 tiers)
│   └── eval_runner.py    # Deterministic eval: IOC F1, TTP recall, HTML report
│
├── evals/
│   └── deepeval_suite.py # LLM-graded: Faithfulness, AnswerRelevancy, Hallucination
│
├── terraform/
│   ├── main.tf           # AWS ECS Fargate, ALB, ECR, S3, Secrets Manager, IAM
│   ├── variables.tf      # Input variables (region, env, cpu, memory)
│   └── outputs.tf        # ALB DNS, ECR URLs, cluster name
│
├── docker-compose.yml    # 4-service local stack
├── Dockerfile            # Multi-stage build for Streamlit service
└── requirements.txt      # All dependencies
```

---

## 🤖 Model

- **LLM:** Groq `llama-3.3-70b-versatile` — extraction, YARA-L generation, log synthesis
- **Embeddings:** `all-MiniLM-L6-v2` (sentence-transformers, local, no API key)
- **Vector DB:** Qdrant (cosine similarity, persistent local volume)
- **Log DB:** Elasticsearch 8.13 (single-node for dev, cluster-ready for prod)

---

## 📄 License

MIT
