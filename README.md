# Bedrock

**Identity-based security framework. Every node is a user. Everything between is encrypted at rest.**

Bedrock provides the foundational security layer for applications that handle sensitive data — healthcare, finance, defense, and beyond. It enforces identity at every endpoint, encrypts all data at rest, and gates every cross-silo access through cryptographic consent.

## Core Principles

- **Every node is a user.** Each compute endpoint has a cryptographic identity.
- **Encrypted at rest, always.** Data exists in cleartext only at the consuming endpoint, only for the minimum time required.
- **Consent-gated access.** No cross-silo data access without cryptographic proof of consent.
- **Audit everything.** SHA-256 hash chain — tamper-evident, tamper-resistant.
- **Self-hosted first.** No Bedrock-operated infrastructure required.

## Architecture

```
┌─────────────────────────────────────────────────────┐
│                    Application                       │
├──────────┬──────────┬──────────┬────────────────────┤
│  Python  │TypeScript│   CLI    │     REST API       │
│   SDK    │   SDK    │ bedrock  │  (FastAPI/uvicorn) │
├──────────┴──────────┴──────────┴────────────────────┤
│                  Bedrock Core                        │
├──────────┬──────────┬──────────┬──────────┬─────────┤
│Encryption│  Identity │   Data   │  Access  │  Audit  │
│  Engine  │  Fabric   │ Silos    │ Control  │  Chain  │
├──────────┴──────────┴──────────┴──────────┴─────────┤
│              Key Management (HKDF)                   │
├─────────────────────────────────────────────────────┤
│           Self-Healing Mesh Transport                │
└─────────────────────────────────────────────────────┘
```

## Quick Start

```bash
# Install
pip install bedrock-core

# Initialize a project
bedrock init ./my-project
cd my-project

# Generate a signing key
bedrock keygen

# Issue a developer license
bedrock license issue --tier developer --licensee "your-name" --days 365

# Start the API server
bedrock serve
```

### From Source

```bash
git clone https://github.com/infill-systems/bedrock.git
cd bedrock/core
pip install -e ".[dev]"
pytest

# Or with Docker
docker compose -f deploy/docker-compose.yml up
```

## CLI Commands

| Command | Description |
|---------|-------------|
| `bedrock init [dir]` | Initialize a new project (config, keys, env template) |
| `bedrock serve [--host] [--port]` | Start the API server |
| `bedrock keygen [--key-id]` | Generate a signing key |
| `bedrock license issue --tier --licensee` | Issue a license key |
| `bedrock license validate --key` | Validate a license key |
| `bedrock license revoke --key-id` | Revoke a signing key |
| `bedrock health [--json]` | Run health checks |
| `bedrock status` | Show system status and config |

## Licensing

Bedrock uses a two-tier licensing model:

| Tier | Price | Nodes | Use Case |
|------|-------|-------|----------|
| Developer | $99/yr | 3 | Local development, self-signed certs |
| Professional | $499/yr | 10 | Team development, self-signed certs |
| Starter | $5K/yr | 5 | Production, CA-enforced |
| Business | $20K/yr | — | Production, CA-enforced |
| Enterprise | Custom | — | Production, CA-enforced, unlimited |

Developer and Professional tiers are for building and testing. Production Runtime tiers enforce per-node CA-signed certificates and offer unlimited scale.

## Project Structure

```
bedrock/
├── core/                    # Core framework (this repo)
│   ├── bedrock/
│   │   ├── encryption/      # Field-level + E2EE encryption engine
│   │   ├── key_management/  # HKDF key hierarchy, silo key derivation
│   │   ├── data_separation/ # Silos, anonymous IDs, consent gates
│   │   ├── identity/        # Identity Fabric, node attestation, certificates
│   │   ├── audit/           # SHA-256 hash chain
│   │   ├── access_control/  # RBAC, sessions, MFA
│   │   ├── transport/       # TLS, E2EE, downgrade detection
│   │   ├── mesh/            # Self-healing mesh (attack detection, routing)
│   │   ├── storage/         # Encrypted storage backend
│   │   ├── licensing/       # License enforcement, keygen, Stripe integration
│   │   ├── metering/        # Per-tier rate limiting and usage tracking
│   │   ├── server/          # FastAPI REST API server with TLS
│   │   ├── config.py        # CoreConfig, encryption/identity/mesh configs
│   │   ├── health.py        # Health checker for all subsystems
│   │   └── cli.py           # bedrock CLI (init, serve, keygen, license, health, status)
│   └── pyproject.toml
├── sdk-python/              # Python SDK
├── sdk-ts/                  # TypeScript SDK
├── deploy/                  # Docker + deployment configs
├── docs/                    # Architecture, implementation plans, technical notes
├── tests/                   # Core test suite (788 tests)
└── assets/                  # Logo and branding
```

## SDKs

### Python

```python
from bedrock_sdk import BedrockClient

client = BedrockClient(
    base_url="https://bedrock.example.com",
    license_key="BR-DEV-xxxx-xxxx",
)

# Register a node
node = client.nodes.register(name="my-service", node_type="application")

# Create a data silo
silo = client.silos.create(
    name="patient-records",
    display_name="Patient Records",
    categories=["medical", "phi"],
)

# Encrypt a field
ciphertext = client.encryption.encrypt(
    plaintext="SSN-123-45-6789",
    silo=silo.silo_id,
    record_id="patient-001",
    scope="ssn",
    operation="store",
)

# Request consent for cross-silo access
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
  baseUrl: "https://bedrock.example.com",
  licenseKey: "BR-DEV-xxxx-xxxx",
});

// Same API surface as Python SDK
const node = await client.nodes.register({ name: "my-service" });
const silo = await client.silos.create({ name: "patient-records" });
```

## Testing

```bash
# Core tests
cd core && pytest

# Python SDK tests
cd sdk-python && pytest

# TypeScript SDK tests
cd sdk-ts && npm test
```

All 930 tests pass: 788 Python core + 20 Python SDK + 122 TypeScript SDK.

## Security

See [SECURITY.md](SECURITY.md) for reporting vulnerabilities.

**Do not report security issues through public GitHub issues.**

## License

Proprietary. See [LICENSE](LICENSE) for terms.

This software is the confidential and proprietary information of InFill Systems, LLC. You shall not disclose such confidential information and shall use it only in accordance with the terms of the license agreement you entered into with InFill Systems, LLC.