# BEDROCK

Trade Secret — InFill Systems, LLC
All rights reserved. No public distribution.

Identity-based security framework. Every node is a user. Everything between is encrypted at rest.

## Structure

```
BEDROCK/
├── core/
│   ├── bedrock/
│   │   ├── __init__.py          # Package root, version
│   │   ├── config.py            # CoreConfig, EncryptionConfig, MeshConfig, LicensingConfig
│   │   ├── encryption/          # B-102: Field-level + E2EE encryption engine
│   │   │   ├── __init__.py
│   │   │   ├── engine.py        # EncryptionEngine, FieldEncryptor, E2EEDeliverer
│   │   │   ├── aad.py           # Additional Authenticated Data
│   │   │   └── version.py       # Ciphertext format versioning (v1 Fernet, v2 GCM)
│   │   ├── key_management/      # B-103: HKDF key hierarchy, silo key derivation
│   │   │   ├── __init__.py
│   │   │   └── keys.py          # MasterKey, SiloKey, KeyManager
│   │   ├── data_separation/     # B-104: Silos, anonymous IDs, consent gates
│   │   │   ├── __init__.py
│   │   │   ├── silo.py          # Silo model
│   │   │   ├── anonymous_id.py  # Adjective-animal-noun ID generation
│   │   │   └── consent.py       # Consent-gated cross-silo access
│   │   ├── identity/           # B-105/106/107: Identity Fabric
│   │   │   ├── __init__.py
│   │   │   ├── node.py         # Node, NodeID, NodeState
│   │   │   ├── attestation.py  # Boot-time attestation
│   │   │   ├── certificates.py # Certificate lifecycle (CA-enforced)
│   │   │   └── capabilities.py  # CapabilityScope, DataCategory
│   │   ├── audit/              # B-108: SHA-256 hash chain
│   │   │   ├── __init__.py
│   │   │   └── chain.py        # AuditChain, AuditEntry
│   │   ├── access_control/     # B-109: RBAC, sessions, MFA
│   │   │   ├── __init__.py
│   │   │   └── controller.py  # AccessController, Role, Session
│   │   ├── transport/          # B-110: TLS, E2EE, downgrade detection
│   │   │   ├── __init__.py
│   │   │   └── security.py    # TransportLayer
│   │   ├── mesh/               # B-111: Self-Healing Mesh
│   │   │   ├── __init__.py
│   │   │   ├── detector.py    # AttackDetector, SignalType
│   │   │   ├── state_machine.py # MeshStateMachine (5-state lifecycle)
│   │   │   └── router.py      # MeshRouter (scope-aware routing)
│   │   └── licensing/          # B-308: License enforcement
│   │       ├── __init__.py
│   │       └── enforcement.py  # LicenseEnforcer, License, LicenseTier
│   └── pyproject.toml         # Build config, dependencies, tool settings
├── sdk/                        # B-2xx: Developer toolkit (Python + TypeScript)
├── docs/
│   ├── BEDROCK_ARCHITECTURE_SPEC.md
│   └── BEDROCK_IMPLEMENTATION_PLAN.md
├── tests/
│   ├── conftest.py
│   ├── test_config.py
│   ├── test_aad.py
│   ├── test_ciphertext_format.py
│   ├── test_anonymous_id.py
│   ├── test_node.py
│   ├── test_capabilities.py
│   ├── test_mesh_state_machine.py
│   ├── test_detector.py
│   └── test_licensing.py
└── .gitignore
```

## Quick Start

```bash
cd core
pip install -e ".[dev]"
pytest
```

## Rules

- **No public repos.** This project never touches GitHub, GitLab, or any public host.
- **No cloud sync.** No OneDrive, no Dropbox, no iCloud for this directory.
- **No secrets in code.** Keys and credentials go in .env files (gitignored).
- **Every node is a user.** This is the core principle. Every compute endpoint has an identity, and everything between them is ciphertext.
- **Encrypted at rest, always.** Data exists in clear text only at the consuming endpoint, only for the minimum time required.
- **Self-hosted first.** The architecture must work without any Bedrock-operated infrastructure.

## Relationship to InFill

InFill is the first vertical application built on Bedrock. Healthcare proved the architecture. Bedrock extracts the reusable patterns and opens them to every vertical — banking, investment, insurance, defense, and beyond.