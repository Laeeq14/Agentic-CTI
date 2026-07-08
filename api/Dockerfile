# ── FastAPI Service Dockerfile ───────────────────────────────────────────────
# Lightweight image for the FastAPI backend only.
# Does NOT include Streamlit or heavy torch/vision dependencies.
# Uses the same multi-stage pattern as the root Dockerfile.

# ── Stage 1: dependency installation ────────────────────────────────────────
FROM python:3.11-slim AS builder

WORKDIR /build

RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential \
        curl \
    && rm -rf /var/lib/apt/lists/*

# Copy only requirements first (leverages Docker layer cache)
COPY requirements.txt .
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt

# ── Stage 2: runtime image ───────────────────────────────────────────────────
FROM python:3.11-slim AS runtime

WORKDIR /app

# Copy installed packages from builder stage
COPY --from=builder /install /usr/local

# Runtime system deps
RUN apt-get update && apt-get install -y --no-install-recommends \
        curl \
    && rm -rf /var/lib/apt/lists/*

# Copy application source
COPY . .

# Create runtime directories expected by pipeline
RUN mkdir -p watch_inbox watch_results qdrant_local_db

EXPOSE 8000

# Health check via FastAPI liveness endpoint
HEALTHCHECK --interval=15s --timeout=5s --start-period=60s --retries=5 \
    CMD curl -sf http://localhost:8000/api/health || exit 1

# Run FastAPI via uvicorn
ENTRYPOINT ["uvicorn", "api.main:app", "--host", "0.0.0.0", "--port", "8000"]
