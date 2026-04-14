# ── Stage 1: build dependencies ───────────────────────────────────────────────
FROM python:3.12-slim AS builder

WORKDIR /build

# Install build tools needed by some Python packages
RUN apt-get update && apt-get install -y --no-install-recommends gcc && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt


# ── Stage 2: runtime image ────────────────────────────────────────────────────
FROM python:3.12-slim AS runtime

# Non-root user for security
RUN addgroup --system appgroup && adduser --system --ingroup appgroup appuser

WORKDIR /app

# Copy installed packages from builder
COPY --from=builder /install /usr/local

# Copy application code
COPY app/ ./app/

# Run as non-root
USER appuser

EXPOSE 8000

# Tunable via env vars:
#   WORKERS   — number of uvicorn worker processes (default 2)
#   LOG_LEVEL — uvicorn log level (default info)
CMD ["sh", "-c", "uvicorn app.main:app \
     --host 0.0.0.0 \
     --port 8000 \
     --workers ${WORKERS:-2} \
     --log-level ${LOG_LEVEL:-INFO}"]
