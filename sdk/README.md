# Bedrock Python SDK

Identity-based security framework for developers.

**Every node is a user. Everything between is encrypted at rest.**

## Installation

```bash
pip install bedrock-sdk
```

## Quick Start

```python
from bedrock_sdk import BedrockClient

# Initialize with developer license
client = BedrockClient(mode="developer")

# Register a node
node = client.identity.register("my-server")

# Encrypt data for a silo
ciphertext = client.encryption.encrypt(
    plaintext="Sensitive data",
    silo="medical",
    record_id="rec-001",
)

# Decrypt
plaintext = client.encryption.decrypt(
    ciphertext=ciphertext,
    silo="medical",
    record_id="rec-001",
)

# Request cross-silo consent
consent = client.consent.request(
    source_silo="medical",
    target_silo="research",
    categories=["diagnosis"],
    scope="read",
)

# Audit everything
client.audit.log(
    action="field.encrypt",
    actor_id=node.id,
    target_id="rec-001",
    silo="medical",
)
```

## Modules

| Module | Description |
|--------|-------------|
| `client.identity` | Node registration, certificates, capability scoping |
| `client.encryption` | Field-level encrypt/decrypt, E2EE delivery |
| `client.data` | Silo configuration, compartmentalization, consent |
| `client.audit` | Audit chain write, verify, export |
| `client.access` | RBAC, sessions, MFA |
| `client.transport` | TLS config, E2EE messaging, downgrade detection |

## License Tiers

- **Developer** ($99/yr): 3 local nodes, self-signed certs, development only
- **Starter** ($5K/yr): 5 nodes, CA-signed certs
- **Business** ($20K/yr): 25 nodes, CA-signed certs
- **Enterprise** (custom): Unlimited nodes, HSM support

---

*Trade Secret — InFill Systems, LLC. All rights reserved.*