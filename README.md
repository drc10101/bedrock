<p align="center">
  <img src="assets/Bedrock_Logo.png" alt="Bedrock" width="600">
</p>

<h3 align="center">Build your app. Inherit the security.</h3>

<p align="center">
  Bedrock is the security layer your app sits on top of.<br>
  Identity, encryption, consent, and audit — handled from the start.
</p>

<p align="center">
  <a href="https://github.com/drc10101/bedrock/releases/tag/v0.3.0"><img src="https://img.shields.io/badge/version-0.3.0-blue" alt="Version"></a>
  <img src="https://img.shields.io/badge/tests-841-passing-brightgreen" alt="Tests">
  <img src="https://img.shields.io/badge/python-3.11+-blue" alt="Python">
  <img src="https://img.shields.io/badge/license-BSL--1.1-orange" alt="License">
  <img src="https://img.shields.io/badge/trial-free_30_days-success" alt="Free Trial">
</p>

---

**You don't bolt security on after the fact. You build on Bedrock, and your app inherits it.**

New? Read the **[Getting Started Guide](GETTING_STARTED.md)** — a step-by-step walkthrough from install to a working app with identity, encryption, consent, and audit.

Bedrock is a security framework that your application calls into — not a service you route traffic through. When your app uses Bedrock's SDK, every node gets a cryptographic identity, every field write gets encrypted at rest, every cross-silo read requires cryptographic consent, and every action gets written to a tamper-evident audit chain. Your app focuses on business logic. Bedrock handles the security guarantees.

## What Your App Gets

- **Cryptographic identity for every node.** Each service, device, or user in your system gets a signed identity. No anonymous access.
- **Field-level encryption at rest.** Data is encrypted before it hits storage. Siloed by category — medical records, financial data, PII — each in its own encrypted container.
- **Consent-gated data access.** No cross-silo read without a cryptographic consent token. If the patient didn't authorize it, the data doesn't move.
- **Tamper-evident audit chain.** Every write, read, consent grant, and revocation is SHA-256 chained. Detect tampering, prove compliance.
- **Self-healing mesh transport.** Encrypted node-to-node communication with automatic failover and reconnection.
- **License-gated operation.** Runtime enforcement of tier limits — nodes, certificates, features.

Your app calls the SDK. The SDK calls Bedrock Core. The security is there because you built on Bedrock, not because you remembered to add it later.

## How It Works

```
┌─────────────────────────────────────────────────────┐
│                    Your Application                   │
│                                                       │
│   Business logic, routes, UI — whatever you build     │
│                                                       │
├──────────┬──────────┬──────────────────────────────┤
│  Python  │TypeScript│          REST API              │
│   SDK    │   SDK    │                                │
├──────────┴──────────┴──────────────────────────────┤
│                                                       │
│                  Bedrock Core                         │
│                                                       │
│   You inherit: identity, encryption, consent,         │
│   audit, key management, mesh transport               │
│                                                       │
└─────────────────────────────────────────────────────┘
```

Your app makes normal SDK calls — register a node, create a silo, encrypt a field, request consent. Bedrock handles the cryptography, the key derivation, the consent verification, the audit logging. You never touch raw crypto. You never write your own access control. You build on top, and the security is already there.

## Status

Bedrock v0.3 is an active development release. Core modules (crypto, identity, data separation, licensing) are well-tested (857 tests, zero type errors). The API server runs on FastAPI + uvicorn — production-grade connection handling, request timeouts, graceful shutdown, and per-tier rate limiting. See [PRODUCTION_DEPLOYMENT.md](docs/PRODUCTION_DEPLOYMENT.md) for deployment details.

## Quick Start

```bash
# Install
pip install bedrock-core

# Initialize a project
bedrock init ./my-project
cd my-project

# Generate a free 30-day trial license
bedrock trial --licensee "your-email@example.com"

# Start the API server
bedrock serve
```

### From Source

```bash
git clone https://github.com/drc10101/bedrock.git
cd bedrock/core
pip install -e ".[dev]"
pytest

# Or with Docker
docker compose -f deploy/docker-compose.yml up
```

## Use It In Your App

### Python

```python
from bedrock_sdk import BedrockClient

client = BedrockClient(
    base_url="https://bedrock.infill.systems",
    license_key="1:...",
)

# Register your service as a node — it now has a cryptographic identity
node = client.nodes.register(name="my-service", node_type="application")

# Create a data silo — medical records live here, encrypted at rest
silo = client.silos.create(
    name="patient-records",
    display_name="Patient Records",
    categories=["medical", "phi"],
)

# Encrypt a field before storing it — Bedrock handles key derivation
ciphertext = client.encryption.encrypt(
    plaintext="SSN-123-45-6789",
    silo=silo.silo_id,
    record_id="patient-001",
    scope="ssn",
    operation="store",
)

# Request consent before reading cross-silo data — cryptographic proof required
consent = client.consent.request(
    requester_id=node.node_id,
    target_id="patient-001",
    silo_id=silo.silo_id,
    purpose="treatment",
    scope=["ssn", "diagnosis"],
)
```

### TypeScript

```typescript
import { BedrockClient } from "@infill/bedrock-sdk";

const client = new BedrockClient({
  baseUrl: "https://bedrock.infill.systems",
  licenseKey: "1:...",
});

// Same API surface as Python SDK
const node = await client.nodes.register({ name: "my-service" });
const silo = await client.silos.create({ name: "patient-records" });
```

That's it. Your app now has identity, encryption, consent, and audit — because it's built on Bedrock.

## CLI Commands

| Command | Description |
|---------|-------------|
| `bedrock init [dir]` | Initialize a new project (config, keys, env template) |
| `bedrock trial [--licensee]` | Generate a free 30-day trial license |
| `bedrock serve [--host] [--port]` | Start the API server |
| `bedrock keygen [--key-id]` | Generate a signing key |
| `bedrock license issue --tier --licensee` | Issue a license key |
| `bedrock license validate --key` | Validate a license key |
| `bedrock license revoke --key-id` | Revoke a signing key |
| `bedrock health [--json]` | Run health checks |
| `bedrock status` | Show system status and config |

## Licensing

Bedrock is source-available under the [Business Source License 1.1](LICENSE).

### Free Trial

Start with a free 30-day trial — full developer features, 3 local nodes, self-signed certificates. No credit card required.

```bash
bedrock trial --licensee "your-email@example.com"
```

### Pricing

| Tier | Price | Nodes | Certificates | Use Case |
|------|-------|-------|---------------|----------|
| **Trial** | Free (30 days) | 3 | Self-signed | Evaluation and development |
| **Developer** | $99/yr | 3 | Self-signed | Individual development |
| **Professional** | $499/yr | 10 | Self-signed | Team development |
| **Starter** | $5K/yr | 5 | CA-enforced | Production deployment |
| **Business** | $20K/yr | 25 | CA-enforced | Production at scale |
| **Enterprise** | Custom | Unlimited | CA-enforced | Mission-critical deployments |

**Non-production use** (development, testing, evaluation) is free forever under BSL-1.1. **Production deployment** requires a paid license.

### How It Works

1. `bedrock trial` — get a free 30-day license with full developer features
2. Build your app on Bedrock — identity, encryption, consent, audit are inherited
3. When ready for production, purchase a runtime license at [bedrock.dev/pricing](https://bedrock.dev/pricing)
4. Upgrade your license key — no code changes, no reinstallation

## Testing

```bash
# Core tests
cd core && pytest

# Python SDK tests
cd sdk-python && pytest

# TypeScript SDK tests
cd sdk-ts && npm test
```

841 tests pass across core modules (841) and Python SDK (20). Zero type errors.

## Security

See [SECURITY.md](SECURITY.md) for reporting vulnerabilities.

**Do not report security issues through public GitHub issues.**

## License

This software is licensed under the [Business Source License 1.1](LICENSE).

You may use, modify, and redistribute this software for non-production purposes (development, testing, evaluation) free of charge. Production use requires a paid license — see [bedrock.dev/pricing](https://bedrock.dev/pricing).

The BSL converts to an open-source license (typically Apache 2.0) on a predetermined change date — see the LICENSE file for details.