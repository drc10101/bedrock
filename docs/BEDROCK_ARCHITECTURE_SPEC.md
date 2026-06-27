# Bedrock Architecture Specification

**Version:** 1.0.0  
**Status:** Draft  
**Author:** InFill Systems, LLC  
**Classification:** TRADE SECRET — No Public Distribution

---

## 1. Vision

Bedrock is a subscription-based security framework and SDK that lets any organization build applications where **every node on the network is an identity** and **everything in transit and at rest is encrypted**. The only decryptable endpoints are the ones you physically control.

The problem InFill solved for healthcare — zero-trust data exchange, end-to-end encryption, identity-scoped access, and compartmentalized data — exists in banking, investment, insurance, defense, and any enterprise paying cloud providers for security that the cloud architecture itself undermines.

Bedrock extracts and generalizes InFill's proven patterns into a framework any developer can use.

---

## 2. Core Principles

### 2.1 Every Node Is a User

In traditional zero-trust, identities belong to people. Bedrock extends identity to every compute node: servers, containers, IoT devices, edge processors, API gateways. Each node has a cryptographic identity, a scoped capability set, and an audit trail. A compromised router, switch, or load balancer sees only ciphertext because it has no identity scope to decrypt.

### 2.2 Encrypted at Rest, Always

Data exists in plaintext only at the consuming endpoint, only for the minimum time required, only within the scope of an authorized operation. All storage — databases, caches, message queues, object stores, logs — stores ciphertext. Keys are never co-located with the data they encrypt.

### 2.3 No Data Custody by Bedrock

Unlike AWS, Azure, or GCP, Bedrock never holds customer data. The framework runs on the customer's infrastructure. The subscription provides software, updates, and SDK access. There is no Bedrock cloud that sees plaintext. The architecture makes this not a policy but a structural impossibility.

### 2.4 Self-Hosted First

The architecture must work without any Bedrock-operated infrastructure. A managed control plane (Bedrock Cloud) may exist later as a premium tier, but self-hosted is always first-class. No feature may require Bedrock's servers.

### 2.5 Compartmentalized by Default

Data separation is not a configuration option — it is the default. Medical records and personal information in separate silos. Banking transactions and customer identity in separate silos. The framework enforces this at the schema level.

---

## 3. Architecture Layers

### 3.1 Bedrock Core (Runtime)

The runtime that enforces identity, encryption, and compartmentalization. Deployed on customer infrastructure.

| Component | Responsibility |
|-----------|---------------|
| **Identity Fabric** | Node registration, attestation, certificate lifecycle, capability scoping |
| **Encryption Engine** | AES-256-GCM field-level encryption, ECDH-P256 key agreement, HKDF-SHA256 key derivation, key rotation |
| **Data Separation Layer** | Schema-level compartmentalization, silo isolation, anonymous linking |
| **Audit Chain** | Tamper-evident SHA-256 hash chain logging, 6-year retention |
| **Access Control** | RBAC with role-portal mapping, scoped sessions, MFA |
| **Transport Security** | TLS termination, E2EE delivery, AAD-bound encryption |
| **API Gateway** | Request routing, CSRF protection, rate limiting, input sanitization |

**Key patterns proven in InFill:**
- ECDH-P256 raw point multiplication for key agreement (no library ECDH dependency)
- HKDF-SHA256 with context-specific info strings for key derivation
- AES-256-GCM with Additional Authenticated Data (AAD) binding payload metadata to the auth tag
- v2: prefix format for algorithm versioning with backward-compatible legacy decryption
- SQLCipher AES-256 for full-database encryption + field-level GCM for PII columns
- Anonymous ID linking (adjective-animal-noun pseudonyms, 440M combinations)

### 3.2 Bedrock SDK (Developer Toolkit)

APIs, client libraries, and developer tools that let any developer build applications inheriting Bedrock's security posture without writing crypto code.

| Component | Responsibility |
|-----------|---------------|
| **Identity SDK** | Register nodes, manage certificates, scope capabilities |
| **Encryption SDK** | Encrypt/decrypt fields, manage key derivation, handle E2EE flows |
| **Data SDK** | Define silos, configure compartmentalization, query across silos with consent |
| **Audit SDK** | Write to audit chain, verify chain integrity, export for compliance |
| **Access SDK** | RBAC configuration, session management, MFA enrollment |
| **Transport SDK** | E2EE message passing, AAD construction, downgrade detection |
| **Template Library** | Pre-built vertical templates (healthcare, banking, insurance, defense) |

**SDK languages (Phase 1):** Python, TypeScript/JavaScript  
**SDK languages (Phase 2):** Go, Rust, Java

### 3.3 Bedrock Cloud (Future, Premium Tier)

Managed control plane for organizations that don't want to run Core themselves. Higher subscription tier. The architecture never requires it.

| Component | Responsibility |
|-----------|---------------|
| **Control Plane** | Node orchestration, certificate authority, policy distribution |
| **Monitoring** | Health checks, anomaly detection, compliance dashboards |
| **Key Management** | HSM-backed key storage, automated rotation, disaster recovery |

---

## 4. Identity Fabric

### 4.1 Node Identity Model

Every node in a Bedrock network has:

1. **Node ID** — Cryptographic identifier (UUID v7 + ed25519 public key)
2. **Node Certificate** — X.509 certificate signed by the organization's CA, with embedded capability claims
3. **Capability Scope** — What data categories this node can request, process, or store
4. **Audit Trail** — Every action the node takes is appended to an immutable chain
5. **Attestation** — Boot-time attestation proving the node's software state matches a known-good hash

### 4.2 Identity Lifecycle

```
Registration → Attestation → Certificate Issuance → Capability Scoping → Active → Rotation → Revocation
```

- **Registration**: Node submits public key + hardware attestation to the Identity Fabric
- **Attestation**: Fabric verifies the node's boot state against a known-good baseline
- **Certificate Issuance**: CA issues a short-lived certificate (24h default, configurable)
- **Capability Scoping**: Admin assigns data categories the node can access
- **Active**: Node operates within its capability scope
- **Rotation**: Certificates auto-renew before expiry; keys rotate on schedule
- **Revocation**: Compromised nodes are revoked immediately; audit chain records the event

### 4.3 Inter-Node Communication

Nodes communicate through E2EE channels. The sending node encrypts data for the receiving node's public key using ECDH-P256 key agreement. No intermediary — router, switch, load balancer, API gateway — can decrypt the payload because they lack the private key. This is the same pattern InFill uses for PIR delivery, generalized to any node pair.

---

## 5. Encryption Engine

### 5.1 Encryption Standards

| Layer | Algorithm | Key Derivation | Purpose |
|-------|-----------|---------------|---------|
| Database at rest | AES-256 (SQLCipher) | Per-database key | Full database file encryption |
| Field-level PII | AES-256-GCM | HKDF-SHA256 from master key | Individual column encryption |
| Transport (E2EE) | ECDH-P256 + AES-256-GCM | HKDF-SHA256 with info string | Point-to-point encrypted delivery |
| Transport (TLS) | TLS 1.2+ | CA-issued certificates | Network encryption |
| Audit chain | SHA-256 | N/A | Tamper-evident logging |

### 5.2 Key Hierarchy

```
Organization Master Key
├── Database Encryption Key (SQLCipher)
│   └── Full database file encryption
├── Field Encryption Key
│   ├── HKDF(per-silo info) → Silo-specific field keys
│   │   ├── HKDF("bedrock:silo:medical:v1") → Medical silo key
│   │   ├── HKDF("bedrock:silo:identity:v1") → Identity silo key
│   │   └── HKDF("bedrock:silo:transaction:v1") → Transaction silo key
│   └── Each silo key encrypts its own columns
├── E2EE Transport Keys
│   ├── Per-node ECDH P-256 key pairs
│   └── Ephemeral keys for per-message key agreement
└── Audit Chain Key
    └── HMAC-SHA256 for chain integrity
```

### 5.3 Key Rotation

- Organization master key: manual rotation, multi-key support for backward compat
- Database key: rotation requires re-encryption (offline migration)
- Field keys: HKDF derivation means rotation is changing the info string, not re-encrypting all data
- E2EE keys: auto-rotation on certificate renewal; old keys decrypt, new keys encrypt
- Audit chain: new chain starts on rotation; old chain is sealed and archived

### 5.4 Additional Authenticated Data (AAD)

Every encryption operation includes AAD that binds the ciphertext to its context. Tampering with any AAD field causes decryption to fail.

```
AAD format: bedrock:{operation}:{silo}:{record_id}:{scope}:{timestamp}
```

This prevents:
- Moving ciphertext between records (record_id mismatch)
- Changing the scope of decrypted data (scope mismatch)
- Replay attacks (timestamp outside window)

---

## 6. Data Separation Layer

### 6.1 Silo Architecture

Data is partitioned into silos by category. Silos are cryptographically and logically isolated — a breach of one silo reveals only that category of data, never the full picture.

**InFill silos (proven):**
- Patient Profile (PII): name, DOB, SSN, address — encrypted, keyed by anonymous_id
- Medical Record: conditions, medications, allergies — anonymized, no PII
- Account/Auth: username, password hash, role — no medical or profile data

**Banking silos (example):**
- Customer Identity: name, DOB, SSN, address — encrypted
- Transaction History: amounts, timestamps, counterparties — anonymized
- Account/Auth: credentials, MFA, sessions — no financial or identity data

**Investment silos (example):**
- Investor Identity: name, tax ID, address — encrypted
- Portfolio Positions: holdings, strategies, allocations — anonymized
- Account/Auth: credentials, compliance status — no portfolio or identity data

### 6.2 Anonymous Linking

Silo records are linked by anonymous IDs — opaque identifiers that cannot be traced back to a person without access to the identity mapping table, which is itself access-restricted.

Format: `adjective-animal-noun` (lowercase, dashed)
Example: `crimson-arctic-fox`
Combinations: 440M+ (configurable word list sizes)

The mapping table is the single most sensitive table in the system. Access is logged to the audit chain on every read.

### 6.3 Consent-Gated Access

Data does not flow between silos without explicit, time-limited consent from the data owner. In InFill, a patient approves a medical record request (ePRR) and a personal info request (PIR) separately. In Bedrock, this pattern generalizes:

- **Data Request**: Node A requests category X for anonymous_id Y
- **Consent Event**: Data owner approves specific categories for a time window
- **Scoped Delivery**: Only approved categories are delivered, encrypted for the requesting node
- **Audit Record**: Request, consent, delivery, and access are all logged to the audit chain

---

## 7. Subscription Model

### 7.1 Tiers

| Tier | Monthly | Includes | Target |
|------|---------|----------|--------|
| **Developer** | $99 | SDK, documentation, community support | Individual developers, prototyping |
| **Team** | $499 | SDK + Core (5 nodes), email support | Small teams, staging environments |
| **Business** | $1,999 | SDK + Core (25 nodes), priority support, compliance templates | Mid-market companies |
| **Enterprise** | Custom | SDK + Core (unlimited), dedicated support, Bedrock Cloud (future), custom verticals | Large organizations |

### 7.2 What Subscribers Get

- **Bedrock Core**: Runtime binaries, configuration, deployment guides
- **Bedrock SDK**: Client libraries (Python, TypeScript, more later), API documentation, code examples
- **Vertical Templates**: Pre-built configurations for healthcare (InFill-derived), banking, insurance, defense
- **Updates**: Security patches, feature releases, compliance updates
- **Compliance Kits**: HIPAA, SOC 2, PCI-DSS, GLBA, DFARS mapping documents
- **Developer Portal**: Documentation, tutorials, API reference, community forum

### 7.3 What Subscribers Don't Get

- Access to Bedrock source code (unless enterprise with NDA)
- Bedrock-managed infrastructure (self-hosted first)
- Customer data passing through Bedrock servers (architecturally impossible)

---

## 8. Vertical Templates

### 8.1 Healthcare (InFill-Derived)

The first vertical, already proven. Maps directly from InFill:
- Patient/Provider/Partner portals with role separation
- ePRR (medical record request) + PIR (personal info request) consent flows
- E2EE delivery with AAD-bound encryption
- Data separation: PII silo, medical silo, auth silo
- Audit chain for HIPAA compliance

### 8.2 Banking

- Customer/Teller/Auditor portals with role separation
- Transaction request + Identity verification consent flows
- E2EE delivery between branches and data centers
- Data separation: Identity silo, Transaction silo, Auth silo
- Audit chain for PCI-DSS, GLBA, SOX compliance
- Anti-fraud patterns (velocity checks, anomalous access detection) as SDK primitives

### 8.3 Investment / Asset Management

- Investor/Advisor/Compliance portals with role separation
- Portfolio data request + KYC verification consent flows
- E2EE delivery of proprietary strategy data
- Data separation: Identity silo, Portfolio silo, Auth silo
- Audit chain for SEC, FINRA compliance
- Insider trading detection as SDK primitives

### 8.4 Defense / Intelligence

- Operator/Analyst/Command portals with role separation
- Intelligence request + clearance verification consent flows
- E2EE delivery between classification levels
- Data separation: Identity silo, Intelligence silo, Auth silo
- Audit chain for DFARS, CMMC compliance
- Multi-level security patterns as SDK primitives

---

## 9. Threat Model

### 9.1 What Bedrock Protects Against

| Attack Vector | Protection | Mechanism |
|--------------|-----------|-----------|
| Network interception | E2EE + TLS | Payload encrypted for recipient's key; intermediary sees ciphertext |
| Database breach | AES-256 at rest + field-level GCM | Stolen DB file is ciphertext; stolen records are ciphertext without silo keys |
| Server compromise | No plaintext at rest | Memory-only decryption during authorized operations; keys never on disk with data |
| Insider threat | Compartmentalization + audit chain | Admin can't see data outside their scope; every access logged immutably |
| Replay attack | AAD binding + timestamps | Decryption fails if context doesn't match encryption context |
| Key escrow | Customer-held master keys | Bedrock never has the organization master key |
| Downgrade attack | E2EE key registration + warning | Client detects missing E2EE key; warns before falling back to TLS-only |

### 9.2 What Bedrock Does NOT Protect Against

| Attack Vector | Mitigation | Outside Bedrock's Scope |
|--------------|------------|------------------------|
| Endpoint compromise | Physical security, EDR, OS hardening | Customer responsibility |
| Social engineering | MFA, training, phishing-resistant auth | Customer responsibility |
| Supply chain | Dependency auditing, SBOM | Shared (Bedrock provides SBOM; customer verifies) |
| Zero-day exploits | Patching cadence, isolation | Shared (Bedrock patches; customer updates) |
| Physical access to endpoints | Facility security, HSMs | Customer responsibility |

### 9.3 Attack Surface

The attack surface is deliberately minimal:

1. **Node endpoints** — The only place data exists in plaintext. Protected by attestation, MFA, and physical security.
2. **Key storage** — Customer-held master keys. Bedrock never has them.
3. **Identity Fabric CA** — The certificate authority that issues node certificates. Protected by HSM (enterprise) or software keystore (smaller deployments).
4. **Audit chain** — Append-only, SHA-256 hash-chained. Tampering is detectable by verification.

Everything else is ciphertext.

---

## 10. Technology Stack

### 10.1 Core Runtime

| Component | Technology | Rationale |
|-----------|-----------|-----------|
| API Framework | FastAPI (Python) | Proven in InFill, async-native, OpenAPI-compatible |
| Database | SQLite (SQLCipher) | Proven in InFill; PostgreSQL adapter for scale |
| Reverse Proxy | Caddy | Proven in InFill, automatic TLS, simple config |
| Encryption | cryptography (Python), Web Crypto API (browser) | Proven ECDH+GCM stack from InFill E2EE |
| Identity | X.509 + Ed25519 | Standard, well-audited, HSM-compatible |
| Audit | SHA-256 hash chain | Proven in InFill, tamper-evident |

### 10.2 SDK

| Language | Library | Rationale |
|----------|---------|-----------|
| Python | bedrock-sdk | Core ecosystem, FastAPI integration, data science |
| TypeScript | @bedrock/sdk | Frontend (React/Next.js), Node.js backend |
| Go | bedrock-go | Infrastructure, Kubernetes, high-performance (Phase 2) |
| Rust | bedrock-rs | Embedded, WASM, performance-critical (Phase 2) |
| Java | bedrock-jvm | Enterprise legacy, Android (Phase 2) |

### 10.3 Deployment Targets

- **Bare metal** — Customer's servers, full control
- **Private cloud** — Customer's VPC, customer's keys
- **Hybrid** — Core on-premises, read replicas in customer's cloud VPC
- **Bedrock Cloud** (future) — Managed Core, customer's keys still

---

## 11. Relationship to InFill

InFill is the first vertical application built on Bedrock. The extraction path:

1. **Phase 1**: Identify InFill components that are vertical-agnostic (encryption, identity, audit, data separation)
2. **Phase 2**: Generalize those components into Bedrock Core with configuration-driven verticals
3. **Phase 3**: Build the SDK wrapping Core's APIs
4. **Phase 4**: Re-implement InFill on top of Bedrock Core + Healthcare Template
5. **Phase 5**: Build Banking, Investment, Defense templates

InFill remains a separate product. Bedrock is the platform it runs on.

---

## 12. Glossary

| Term | Definition |
|------|-----------|
| **Node** | Any compute endpoint with a Bedrock identity (server, container, device, gateway) |
| **Silo** | A cryptographically isolated data partition (PII, Transaction, Auth, etc.) |
| **Anonymous ID** | Opaque identifier linking silo records without revealing identity |
| **Capability Scope** | The set of data categories a node is authorized to access |
| **Consent Event** | An explicit, time-limited approval from a data owner for scoped data access |
| **AAD** | Additional Authenticated Data — context bound to ciphertext that prevents tampering |
| **E2EE** | End-to-End Encryption — data encrypted at origin, decrypted only at destination |
| **Identity Fabric** | The system managing node identities, certificates, and capability scopes |
| **Vertical Template** | A pre-built configuration for a specific industry (healthcare, banking, etc.) |

---

*This document is a trade secret of InFill Systems, LLC. Unauthorized distribution is prohibited.*