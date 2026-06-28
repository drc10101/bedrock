# Production Deployment Guide

## Environment Variables

Bedrock requires these environment variables for production deployment. The `bedrock init` command generates a `.env.template` file with all required variables.

### Required

| Variable | Description | Example |
|----------|-------------|---------|
| `BEDROCK_SIGNING_KEY` | HMAC signing key for license validation. Must be the same across all nodes in a cluster. | A 32+ byte random hex string |
| `BEDROCK_LICENSE_KEY` | Runtime license key (issued by InFill or via `bedrock trial`) | `1:PRODUCTION:...` |

### Stripe Integration (for self-hosted billing)

| Variable | Description |
|----------|-------------|
| `BEDROCK_STRIPE_SECRET_KEY` | Stripe API secret key |
| `BEDROCK_STRIPE_WEBHOOK_SECRET` | Stripe webhook signing secret |
| `BEDROCK_STRIPE_PRODUCT_ID` | Stripe product ID |
| `BEDROCK_STRIPE_PRICE_DEV_INDIVIDUAL` | Price ID for individual dev tier |
| `BEDROCK_STRIPE_PRICE_DEV_TEAM` | Price ID for team dev tier |

## Generating a Production Signing Key

The signing key is used to validate license keys across your cluster. In development, Bedrock derives a key from machine info. In production, you **must** set `BEDROCK_SIGNING_KEY` explicitly.

### Option 1: Random hex key (recommended)

```bash
# Generate a 32-byte random key (256 bits)
python -c "import secrets; print(secrets.token_hex(32))"
# Output: a3f8c2e1...64 chars of hex

# Set it in your environment
export BEDROCK_SIGNING_KEY="a3f8c2e1..."
```

### Option 2: OpenSSL

```bash
openssl rand -hex 32
```

### Option 3: Python key derivation

```python
import hashlib, os
key = hashlib.sha256(os.urandom(64)).hexdigest()
print(key)
```

## Key Rotation

To rotate the signing key:

1. Generate a new key using one of the methods above
2. Update `BEDROCK_SIGNING_KEY` on all nodes simultaneously
3. Re-issue any active license keys signed with the old key
4. Deploy updated license keys to all nodes

**Important:** Changing the signing key invalidates all existing license keys. Plan rotation during a maintenance window.

## Docker Deployment

```yaml
# docker-compose.yml
services:
  bedrock:
    image: bedrock-core:latest
    ports:
      - "8443:8443"
    environment:
      - BEDROCK_SIGNING_KEY=${BEDROCK_SIGNING_KEY}
      - BEDROCK_LICENSE_KEY=${BEDROCK_LICENSE_KEY}
      - BEDROCK_STRIPE_SECRET_KEY=${BEDROCK_STRIPE_SECRET_KEY}
    volumes:
      - bedrock-data:/var/lib/bedrock
    restart: unless-stopped

volumes:
  bedrock-data:
```

## Kubernetes Deployment

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: bedrock-secrets
type: Opaque
stringData:
  signing-key: "<your-signing-key>"
  license-key: "<your-license-key>"
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: bedrock
spec:
  replicas: 3
  template:
    spec:
      containers:
      - name: bedrock
        image: bedrock-core:latest
        env:
        - name: BEDROCK_SIGNING_KEY
          valueFrom:
            secretKeyRef:
              name: bedrock-secrets
              key: signing-key
        - name: BEDROCK_LICENSE_KEY
          valueFrom:
            secretKeyRef:
              name: bedrock-secrets
              key: license-key
```

## Security Checklist

- [ ] `BEDROCK_SIGNING_KEY` is set (not using dev-derived key)
- [ ] Signing key is stored in a secrets manager (Vault, AWS Secrets Manager, etc.)
- [ ] Signing key is not in version control
- [ ] Signing key is not in environment files committed to git
- [ ] TLS is enabled on the API server (`bedrock serve --tls-cert --tls-key`)
- [ ] License key is stored in a secrets manager
- [ ] Stripe keys (if used) are stored in a secrets manager
- [ ] `.env` files are in `.gitignore`
- [ ] Production database uses encrypted storage (SQLite with SQLCipher or external DB)
## Current Server Status (v0.3)

The Bedrock HTTP API server uses Python stdlib `http.server.HTTPServer` with SQLite persistence. This is suitable for development, testing, and low-traffic internal deployments. It is **not yet hardened for public-facing production traffic**.

Known limitations:
- No request timeouts or connection pooling
- No graceful shutdown (Ctrl+C only)
- No rate-limit bypass for health endpoints
- TLS termination is in-process (no reverse proxy integration documented)
- SQLite is single-writer (concurrent writes serialize)
- No automated database migration system

For production deployment behind a reverse proxy (nginx/Caddy), the core crypto, identity, consent, and licensing modules are production-grade. The HTTP transport layer needs hardening or replacement (e.g., FastAPI + uvicorn) for high-traffic scenarios.
