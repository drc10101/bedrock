FROM python:3.12-slim AS base

# Metadata
LABEL maintainer="InFill Systems, LLC"
LABEL description="Bedrock Core — Identity-based encrypted data framework"
LABEL version="0.3.0"
LABEL org.opencontainers.image.source="https://github.com/drc10101/bedrock"
LABEL org.opencontainers.image.title="Bedrock Core"
LABEL org.opencontainers.image.description="Identity-based security framework. Every node is a user. Everything between is encrypted at rest."

# Security: run as non-root
RUN groupadd -r bedrock && useradd -r -g bedrock -d /opt/bedrock -s /sbin/nologin bedrock

WORKDIR /opt/bedrock

# Install system deps (cryptography needs libffi + build tools)
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    build-essential \
    libffi-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy and install the package
COPY core/ /opt/bedrock/core/
RUN pip install --no-cache-dir /opt/bedrock/core

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