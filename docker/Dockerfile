# ─────────────────────────────────────────────────────────────────────────
# Sentinel — AI Model Runtime Integrity Checker
# Multi-stage Docker image
# ─────────────────────────────────────────────────────────────────────────

FROM python:3.11-slim AS builder

WORKDIR /build

# Install build deps & sentinel from PyPI
RUN pip install --no-cache-dir model-integrity-cli==0.1.0

# ─────────────────────────────────────────────────────────────────────────
# Runtime
# ─────────────────────────────────────────────────────────────────────────

FROM python:3.11-slim

# Sentinel doesn't need root — good security practice
RUN groupadd -r sentinel && useradd -r -g sentinel -d /home/sentinel -m sentinel

# Copy the installed package from builder
COPY --from=builder /usr/local/lib/python3.11/site-packages /usr/local/lib/python3.11/site-packages
COPY --from=builder /usr/local/bin/sentinel /usr/local/bin/sentinel

# Make the sentinel directory for persistent state
RUN mkdir -p /home/sentinel/.sentinel && chown -R sentinel:sentinel /home/sentinel/.sentinel

# Volumes for mounting model directories to monitor
VOLUME ["/models", /data, /home/sentinel/.sentinel]

USER sentinel
WORKDIR /home/sentinel

ENTRYPOINT ["sentinel"]
CMD ["--help"]

# ── Usage ───────────────────────────────────────────────────────────────
# docker run --rm -v ./models:/models:ro sentinel run --model-dir /models './run.sh'
# docker run --rm sentinel status
# docker run --rm sentinel --help
