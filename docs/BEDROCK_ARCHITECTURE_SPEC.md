# Bedrock Architecture Specification

**Version:** 1.2.0  
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

The runtime that enforces identity, encryption, compartmentalization, and self-healing network resilience. Deployed on customer infrastructure.

|| Component | Responsibility |
|-----------|---------------|
| **Identity Fabric** | Node registration, attestation, certificate lifecycle, capability scoping |
| **Encryption Engine** | AES-256-GCM field-level encryption, ECDH-P256 key agreement, HKDF-SHA256 key derivation, key rotation |
| **Data Separation Layer** | Schema-level compartmentalization, silo isolation, anonymous linking |
| **Audit Chain** | Tamper-evident SHA-256 hash chain logging, 6-year retention |
| **Access Control** | RBAC with role-portal mapping, scoped sessions, MFA |
| **Transport Security** | TLS termination, E2EE delivery, AAD-bound encryption |
| **Self-Healing Mesh** | Attack detection, node isolation, automatic rerouting, re-attestation, network reconstitution |
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

## 7. Self-Healing Mesh

### 7.1 Concept

Traditional networks are static -- they trust their topology until an operator manually reconfigures them. Bedrock networks are **living systems**: every node monitors its neighbors, detects attack patterns, and automatically isolates compromised paths while rerouting traffic through healthy nodes. The network doesn't just resist attacks; it *reconfigures around them*.

This is only possible because of the Identity Fabric. When every node has a cryptographic identity, a capability scope, and an attestation baseline, the network can make trust decisions **without human intervention** -- and those decisions are auditable and reversible.

### 7.2 Attack Detection Heuristics

Each node runs a lightweight local detector that observes its own traffic and neighbor behavior. Detection does not require a central orchestrator -- it is distributed and consensus-driven.

**Detection signals:**

| Signal | Type | Threshold | Action |
|--------|------|-----------|--------|
| Credential stuffing | Auth | >N failed auth attempts from a node in T seconds | Flag node, increase challenge difficulty |
| Lateral movement | Auth | Node requesting access outside its capability scope | Isolate node, reroute through alternate path |
| Unusual data volume | Data | Outbound volume >X standard deviations from baseline | Throttle, alert, demand re-attestation |
| Unexpected attestation state | Identity | Boot hash mismatch or attestation failure | Quarantine node immediately, revoke certificate |
| Path anomaly | Network | Traffic rerouted through unexpected intermediaries | Alert, validate path integrity |
| Certificate anomaly | Identity | Expired, revoked, or unsigned certificate | Drop connection, flag node |
| Replay / AAD mismatch | Crypto | Decryption AAD doesn't match encryption AAD | Drop payload, flag source node |
| Silent node | Health | No heartbeat for T seconds from previously active node | Mark unreachable, reroute around |

**Consensus model:** A node must be flagged by ≥2 independent neighbors before isolation takes effect. Single-flag events raise alerts but do not trigger isolation. This prevents a single compromised node from isolating a healthy peer (false positive resistance).

### 7.3 Node States

Every node in the mesh operates in one of five states:

```
ACTIVE → SUSPECT → QUARANTINED → HEALING → ACTIVE
              ↓                        ↑
              └────── REVOKED ──────────┘
```

| State | Description | Can Route? | Can Decrypt? |
|-------|-------------|-----------|-------------|
| **Active** | Normal operation, attestation valid, all health checks passing | Yes | Yes |
| **Suspect** | Flagged by ≥1 neighbor, under observation. Traffic still passes but is monitored | Yes (monitored) | Yes (AAD logged) |
| **Quarantined** | Flagged by ≥2 neighbors or attestation failed. Isolated from mesh. No routing, no decryption | No | No |
| **Healing** | Re-attesting after quarantine. Certificate renewal in progress. Partial routing (relay only, no decryption) | Relay only | No |
| **Revoked** | Permanently removed. Certificate revoked, audit chain records reason. | No | No |

### 7.4 Isolation Protocol

When a node is quarantined:

1. **Certificate Revocation Broadcast** — The CA immediately publishes a CRL entry and pushes to all nodes. No quarantined node can establish new E2EE sessions because its certificate is revoked.
2. **Path Rerouting** — Neighbors recalculate routes excluding the quarantined node. Because every node has identity and capability scope, rerouting is deterministic: pick the next-healthiest node that has the same capability scope for the required data category.
3. **Key Invalidation** — E2EE keys derived from the quarantined node's certificate are invalidated. Any in-flight messages encrypted for that node become undecryptable (by design -- the data should never have been in transit to a compromised node).
4. **Audit Record** — The isolation event, including detection signals and flagging neighbors, is appended to the audit chain. Full forensic trail.

### 7.5 Healing Protocol

A quarantined node can heal and rejoin the mesh:

1. **Re-attestation** — Node must prove its current software state matches a known-good baseline. This is the same boot-time attestation from the Identity Fabric, but triggered as a recovery condition.
2. **Certificate Renewal** — New certificate with a new serial number. Old certificate remains on the CRL permanently.
3. **Capability Scope Review** — Admin (or policy engine) reviews and re-confirms the node's capability scope before re-issuance. This is the human-in-the-loop checkpoint for severe incidents.
4. **Healing State** — Node enters healing state, where it can relay traffic but cannot decrypt data. This proves it can route correctly before it regains full trust.
5. **Promotion to Active** — After a configurable healing period (default: 1 hour) with no further flags, the node is promoted back to Active. All state transitions are logged to the audit chain.

### 7.6 Network Topology

Bedrock networks are **mesh-capable**, not rigid hierarchies:

- **Full mesh** (small deployments): Every node can route to every other node. Maximum resilience, minimum latency.
- **Partial mesh** (medium deployments): Nodes form redundant clusters with multiple inter-cluster bridges. Single bridge failure does not partition the network.
- **Hub-spoke with redundancy** (large deployments): Multiple hubs per capability scope. Hub failure triggers automatic spoke reassignment to a surviving hub.

**Topology rules enforced by the mesh:**

1. No single point of failure — every path has ≥1 alternate route
2. No node routes data outside its capability scope — a medical-scope node never relays transaction data, even in quarantine recovery
3. Route preference: same-scope direct > same-scope relay > cross-scope relay with consent > deny
4. Topology is not static — nodes join, leave, and reroute continuously based on health and capability

### 7.7 Self-Healing in Practice: Attack Scenarios

**Scenario 1: Credential stuffing on a banking portal**
- Node detects >50 failed auth attempts in 60 seconds
- Flags the source IP/node as Suspect
- Second neighbor corroborates → source node Quarantined
- Traffic reroutes through healthy nodes
- Audit chain records the full attack timeline
- After attack subsides and re-attestation, source IP may be healed (if legitimate node under brute force) or revoked (if confirmed malicious)

**Scenario 2: Man-in-the-middle on a load balancer**
- Load balancer compromised, begins intercepting traffic
- AAD mismatch: encryption context doesn't match decryption context at endpoints
- Endpoints flag the load balancer node
- Certificate is revoked, E2EE keys invalidated
- Traffic reroutes around the compromised node
- Compromised node sees only ciphertext it can no longer decrypt

**Scenario 3: DDoS against a healthcare gateway**
- Gateway node overwhelmed, heartbeat stops
- Neighbors mark node as unreachable
- Traffic reroutes through alternate gateways (partial mesh topology provides redundancy)
- When attack subsides, gateway re-attests and re-enters healing state
- If gateway is truly compromised (not just overwhelmed), attestation fails and it's revoked

**Scenario 4: Insider threat attempts lateral movement**
- Authenticated admin node attempts to access transaction silo data (outside its capability scope)
- Access control denies the request and flags the node as Suspect
- If node persists, second flag promotes to Quarantined
- Admin's certificate is revoked, audit chain records the attempted violation
- Even with valid credentials, the node cannot access data outside its scope because the Encryption Engine requires the correct capability scope in the AAD

### 7.8 Self-Healing Mesh vs. Traditional Approaches

| Feature | Traditional Zero-Trust | Traditional Mesh VPN | **Bedrock Self-Healing Mesh** |
|---------|----------------------|---------------------|-------------------------------|
| Node identity | User identities only | Node addresses (IP/DNS) | Cryptographic identity per node with capability scope |
| Attack detection | Central SIEM, manual response | None (topology is static) | Distributed, consensus-driven, automatic |
| Compromised node | Manual investigation | Manual reconfiguration | Auto-isolate, reroute, audit trail |
| Data in transit | TLS (decrypt at load balancer) | VPN tunnel (decrypt at gateway) | E2EE (only endpoints decrypt) |
| Rerouting | Manual DNS/load balancer change | Manual reconfiguration | Automatic, identity-aware, scope-preserving |
| Recovery | Manual verification, manual restore | Manual reconfiguration | Re-attestation, certificate renewal, healing state, auto-promotion |
| Audit trail | Separate SIEM product | Separate logging | Built-in, immutable, hash-chained |

---

## 8. Licensing Model

### 8.1 Philosophy

Bedrock generates revenue at two stages of the customer lifecycle:

1. **Developer License** -- Low-cost, broad adoption. Developers learn Bedrock, build prototypes, integrate into products. Price is a rounding error compared to developer time.

2. **Production Runtime** -- Per-node pricing when the product ships. The customer is already making money. Switching costs are enormous. Node pricing scales with their growth -- we grow when they grow.

The developer license is the funnel. The runtime license is the revenue engine. The SDK is never sold separately -- it's how you use what you've licensed.

### 8.2 Developer License (Annual)

For individual developers and small teams building with Bedrock. Includes everything needed to develop, test, and prototype. Does NOT include production deployment rights.

| Tier | Annual | Dev Seats | Production Nodes | Includes |
|------|--------|-----------|-------------------|----------|
| **Developer** | $99 | 1 | 0 (dev/test only) | SDK, documentation, community support, local dev mode (up to 3 local nodes for testing) |
| **Team** | $499 | 5 | 0 (dev/test only) | SDK, documentation, email support, local dev mode, 1 vertical template |

**What Developer License includes:**
- **Bedrock SDK**: Full client libraries (Python, TypeScript), API documentation, code examples
- **Local dev mode**: Up to 3 nodes on localhost for development and testing (no production deployment)
- **Vertical templates**: 1 included (Team), healthcare template available for purchase ($199/year standalone)
- **Updates**: Security patches, minor version updates
- **Developer Portal**: Documentation, tutorials, API reference, community forum

**What Developer License does NOT include:**
- Production deployment rights (requires Runtime License)
- Bedrock source code (unless Enterprise with NDA)
- Production CA certificate issuance (dev mode uses self-signed)
- Compliance kits (available as add-on)

### 8.3 Production Runtime License (Annual)

For organizations deploying Bedrock in production. Per-node pricing enforced by the Identity Fabric -- the CA will not issue certificates beyond the licensed node count. No phone-home required; the license key unlocks the node ceiling in the local CA.

| Tier | Annual | Nodes | Vertical Templates | Support | Target |
|------|--------|-------|--------------------|---------|--------|
| **Starter** | $5,000 | 5 | 1 (healthcare) | Email | Small companies, single vertical |
| **Business** | $20,000 | 25 | All 4 | Priority | Mid-market, multiple verticals |
| **Enterprise** | Custom | Unlimited | All + custom | Dedicated | Large organizations, defense |

**Node pricing economics:**

| Deployment Scale | Nodes | Starter | Business | Enterprise |
|-----------------|-------|---------|----------|------------|
| Small clinic / fintech startup | 5 | $5,000 | — | — |
| Regional hospital / mid-size bank | 25 | — | $20,000 | — |
| Hospital system / national bank | 100 | — | $80,000 | Custom |
| Defense / Fortune 500 | 500+ | — | — | Custom |

**Add-ons (annual):**
- Additional vertical template (Starter only): $5,000/year each
- Compliance kit (HIPAA, SOC 2, PCI-DSS, GLBA, DFARS): $3,000/year each (included in Business+)
- Additional SDK language (Go, Rust, Java): included when available
- Bedrock Cloud (future): premium tier for managed control plane

**What Runtime License includes:**
- Everything in Developer License
- **Production deployment rights**: Full CA certificate issuance, Self-Healing Mesh, production-grade configuration
- **Bedrock Core**: Runtime binaries, configuration, deployment guides, systemd/supervisor configs
- **Node enforcement**: CA refuses certificates beyond licensed count (structural, not DRM)
- **Self-Healing Mesh**: Full production mesh with consensus isolation, rerouting, healing
- **Vertical Templates**: Industry-specific silo configs, consent flows, compliance mappings
- **Updates**: Security patches, feature releases, compliance updates, version upgrades
- **Compliance Kits**: Regulatory mapping documents per vertical (Business+)

### 8.4 Enforcement Architecture

The license is enforced structurally, not by phone-home or obfuscation:

1. **CA-enforced node limit**: The organization's CA (which runs on their infrastructure) reads the license key and will not issue certificates beyond the licensed node count. You cannot add a 6th node on a Starter license because the CA won't sign the certificate.

2. **No phone-home required**: The CA runs locally. Air-gapped deployments work. Defense customers can operate without internet connectivity.

3. **Dev mode vs production**: Developer licenses generate self-signed certificates valid only on localhost. Production certificates require a Runtime license key to activate the CA.

4. **Tamper resistance**: Bypassing the CA means running without the Identity Fabric, which means running without the Self-Healing Mesh, which means running without Bedrock -- you have a crypto library, not the framework. The license protects the entire architecture, not a single function.

5. **Audit trail**: Every certificate issuance, renewal, and revocation is logged to the audit chain. License compliance is verifiable without external access.

### 8.5 Revenue Projections

| Year | Developer Licenses | Runtime Licenses | ARR Target |
|------|-------------------|-----------------|------------|
| Year 1 | 200 x $99 = $19,800 | 10 Starter + 5 Business = $175,000 | ~$195K |
| Year 2 | 500 x $99 = $49,500 | 30 Starter + 15 Business = $525,000 | ~$575K |
| Year 3 | 1,000 x $99 = $99,000 | 75 Starter + 30 Business + 3 Enterprise = $1.35M | ~$1.45M |

Developer license revenue is modest. It exists to fund adoption and create switching costs. Runtime license revenue is the business.

### 8.6 What Subscribers Don't Get

- Access to Bedrock source code (unless Enterprise with NDA)
- Bedrock-managed infrastructure (self-hosted first; Bedrock Cloud is future premium tier)
- Customer data passing through Bedrock servers (architecturally impossible)
- Production deployment rights on a Developer license

---

## 9. Vertical Templates

### 9.1 Healthcare (InFill-Derived)

The first vertical, already proven. Maps directly from InFill:
- Patient/Provider/Partner portals with role separation
- ePRR (medical record request) + PIR (personal info request) consent flows
- E2EE delivery with AAD-bound encryption
- Data separation: PII silo, medical silo, auth silo
- Audit chain for HIPAA compliance

### 9.2 Banking

- Customer/Teller/Auditor portals with role separation
- Transaction request + Identity verification consent flows
- E2EE delivery between branches and data centers
- Data separation: Identity silo, Transaction silo, Auth silo
- Audit chain for PCI-DSS, GLBA, SOX compliance
- Anti-fraud patterns (velocity checks, anomalous access detection) as SDK primitives

### 9.3 Investment / Asset Management

- Investor/Advisor/Compliance portals with role separation
- Portfolio data request + KYC verification consent flows
- E2EE delivery of proprietary strategy data
- Data separation: Identity silo, Portfolio silo, Auth silo
- Audit chain for SEC, FINRA compliance
- Insider trading detection as SDK primitives

### 9.4 Defense / Intelligence

- Operator/Analyst/Command portals with role separation
- Intelligence request + clearance verification consent flows
- E2EE delivery between classification levels
- Data separation: Identity silo, Intelligence silo, Auth silo
- Audit chain for DFARS, CMMC compliance
- Multi-level security patterns as SDK primitives

---

## 10. Threat Model

### 10.1 What Bedrock Protects Against

|| Attack Vector | Protection | Mechanism |
|--------------|-----------|-----------|
| Network interception | E2EE + TLS | Payload encrypted for recipient's key; intermediary sees ciphertext |
| Database breach | AES-256 at rest + field-level GCM | Stolen DB file is ciphertext; stolen records are ciphertext without silo keys |
| Server compromise | No plaintext at rest | Memory-only decryption during authorized operations; keys never on disk with data |
| Insider threat | Compartmentalization + audit chain | Admin can't see data outside their scope; every access logged immutably |
| Replay attack | AAD binding + timestamps | Decryption fails if context doesn't match encryption context |
| Key escrow | Customer-held master keys | Bedrock never has the organization master key |
| Downgrade attack | E2EE key registration + warning | Client detects missing E2EE key; warns before falling back to TLS-only |
| Network attack (DDoS, credential stuffing, lateral movement) | Self-healing mesh | Nodes detect attack patterns, isolate compromised nodes by consensus, reroute traffic through healthy paths, demand re-attestation before healing |
| Man-in-the-middle | AAD binding + E2EE + self-healing mesh | Intermediary sees only ciphertext; AAD mismatch triggers node isolation and rerouting |
| Compromised infrastructure node | Attestation + certificate revocation + mesh isolation | Boot-time attestation catches software tampering; compromised node quarantined, certificate revoked, traffic rerouted automatically |

### 10.2 What Bedrock Does NOT Protect Against

| Attack Vector | Mitigation | Outside Bedrock's Scope |
|--------------|------------|------------------------|
| Endpoint compromise | Physical security, EDR, OS hardening | Customer responsibility |
| Social engineering | MFA, training, phishing-resistant auth | Customer responsibility |
| Supply chain | Dependency auditing, SBOM | Shared (Bedrock provides SBOM; customer verifies) |
| Zero-day exploits | Patching cadence, isolation | Shared (Bedrock patches; customer updates) |
| Physical access to endpoints | Facility security, HSMs | Customer responsibility |

### 10.3 Attack Surface

The attack surface is deliberately minimal:

1. **Node endpoints** — The only place data exists in plaintext. Protected by attestation, MFA, and physical security.
2. **Key storage** — Customer-held master keys. Bedrock never has them.
3. **Identity Fabric CA** — The certificate authority that issues node certificates. Protected by HSM (enterprise) or software keystore (smaller deployments).
4. **Audit chain** — Append-only, SHA-256 hash-chained. Tampering is detectable by verification.

Everything else is ciphertext.

---

## 11. Technology Stack

### 11.1 Core Runtime

|| Component | Technology | Rationale |
|-----------|-----------|-----------|
| API Framework | FastAPI (Python) | Proven in InFill, async-native, OpenAPI-compatible |
| Database | SQLite (SQLCipher) | Proven in InFill; PostgreSQL adapter for scale |
| Reverse Proxy | Caddy | Proven in InFill, automatic TLS, simple config |
| Encryption | cryptography (Python), Web Crypto API (browser) | Proven ECDH+GCM stack from InFill E2EE |
| Identity | X.509 + Ed25519 | Standard, well-audited, HSM-compatible |
| Audit | SHA-256 hash chain | Proven in InFill, tamper-evident |
| Self-Healing Mesh | gossip protocol + weighted voting | Distributed detection, no single point of failure, consensus before isolation |

### 11.2 SDK

| Language | Library | Rationale |
|----------|---------|-----------|
| Python | bedrock-sdk | Core ecosystem, FastAPI integration, data science |
| TypeScript | @bedrock/sdk | Frontend (React/Next.js), Node.js backend |
| Go | bedrock-go | Infrastructure, Kubernetes, high-performance (Phase 2) |
| Rust | bedrock-rs | Embedded, WASM, performance-critical (Phase 2) |
| Java | bedrock-jvm | Enterprise legacy, Android (Phase 2) |

### 11.3 Deployment Targets

- **Bare metal** — Customer's servers, full control
- **Private cloud** — Customer's VPC, customer's keys
- **Hybrid** — Core on-premises, read replicas in customer's cloud VPC
- **Bedrock Cloud** (future) — Managed Core, customer's keys still

---

## 12. Relationship to InFill

InFill is the first vertical application built on Bedrock. The extraction path:

1. **Phase 1**: Identify InFill components that are vertical-agnostic (encryption, identity, audit, data separation)
2. **Phase 2**: Generalize those components into Bedrock Core with configuration-driven verticals
3. **Phase 3**: Build the SDK wrapping Core's APIs
4. **Phase 4**: Re-implement InFill on top of Bedrock Core + Healthcare Template
5. **Phase 5**: Build Banking, Investment, Defense templates

InFill remains a separate product. Bedrock is the platform it runs on.

---

## 13. Glossary

|| Term | Definition |
|------|------------|
| **Node** | Any compute endpoint with a Bedrock identity (server, container, device, gateway) |
| **Silo** | A cryptographically isolated data partition (PII, Transaction, Auth, etc.) |
| **Anonymous ID** | Opaque identifier linking silo records without revealing identity |
| **Capability Scope** | The set of data categories a node is authorized to access |
| **Consent Event** | An explicit, time-limited approval from a data owner for scoped data access |
| **AAD** | Additional Authenticated Data — context bound to ciphertext that prevents tampering |
| **E2EE** | End-to-End Encryption — data encrypted at origin, decrypted only at destination |
| **Identity Fabric** | The system managing node identities, certificates, and capability scopes |
| **Vertical Template** | A pre-built configuration for a specific industry (healthcare, banking, etc.) |
| **Self-Healing Mesh** | The distributed network resilience layer that detects attacks, isolates compromised nodes, and reroutes traffic automatically |
| **Node State** | The trust status of a node: Active, Suspect, Quarantined, Healing, or Revoked |
| **Consensus** | Requirement that ≥2 independent neighbors flag a node before isolation takes effect |

---

*This document is a trade secret of InFill Systems, LLC. Unauthorized distribution is prohibited.*