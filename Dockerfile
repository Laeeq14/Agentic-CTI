# ── Stage 1: dependency installation ────────────────────────────────────────
FROM python:3.11-slim AS builder

WORKDIR /build

# System deps needed to compile some packages (qdrant-client, torch)
RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential \
        curl \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt

# ── Stage 2: runtime image ───────────────────────────────────────────────────
FROM python:3.11-slim AS runtime

WORKDIR /app

# Copy installed packages from builder stage
COPY --from=builder /install /usr/local

# System runtime deps only
RUN apt-get update && apt-get install -y --no-install-recommends \
        curl \
    && rm -rf /var/lib/apt/lists/*

# Copy application source
COPY . .

# Create required runtime directories
RUN mkdir -p watch_inbox watch_results qdrant_local_db

# Streamlit config: disable telemetry, set server options
RUN mkdir -p /root/.streamlit && printf \
    "[server]\nheadless = true\nport = 8501\naddress = \"0.0.0.0\"\n\n[browser]\ngatherUsageStats = false\n" \
    > /root/.streamlit/config.toml

EXPOSE 8501

# Health check via Streamlit's built-in health endpoint
HEALTHCHECK --interval=15s --timeout=5s --start-period=30s --retries=3 \
    CMD curl -f http://localhost:8501/_stcore/health || exit 1

ENTRYPOINT ["streamlit", "run", "app.py"]
