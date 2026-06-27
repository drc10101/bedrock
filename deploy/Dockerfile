FROM python:3.14-slim AS base

# Metadata
LABEL maintainer="InFill Systems, LLC"
LABEL description="Bedrock Core — Identity-based encrypted data framework"
LABEL version="1.0.0"

# Security: run as non-root
RUN groupadd -r bedrock && useradd -r -g bedrock -d /opt/bedrock -s /sbin/nologin bedrock

WORKDIR /opt/bedrock

# Install system deps (cryptography needs libffi, cargo for building)
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    build-essential \
    libffi-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first for layer caching
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application
COPY core/ ./core/

# Create runtime directories
RUN mkdir -p /var/lib/bedrock/audit /etc/bedrock /var/log/bedrock && \
    chown -R bedrock:bedrock /var/lib/bedrock /etc/bedrock /var/log/bedrock /opt/bedrock

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "from bedrock.config import CoreConfig; c = CoreConfig.from_env(); print('healthy')" || exit 1

USER bedrock

ENV BEDROCK_ENV=production
ENV BEDROCK_LOG_LEVEL=INFO
ENV BEDROCK_DEV_MODE=false

EXPOSE 8443

CMD ["python", "-m", "bedrock.server"]