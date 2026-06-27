# Bedrock Technical Notes

**Version:** 0.1.0  
**Classification:** TRADE SECRET — InFill Systems, LLC  
**Purpose:** Plain-English documentation of every Bedrock component, what it does, and why it exists.

---

## What Is Bedrock?

Bedrock is a security framework you embed in your application. It gives you four things that most applications don't have:

1. **Every node on the network has a cryptographic identity** — not just users, but servers, containers, IoT devices, everything
2. **All data is encrypted at rest, always** — databases, caches, queues, logs all store ciphertext
3. **Data is compartmentalized into silos** — a breach of one category reveals nothing about the others
4. **Cross-silo data access requires explicit consent** — no data flows between compartments without the owner's approval

These patterns were proven in InFill (healthcare). Bedrock generalizes them for banking, investment, insurance, defense, and any enterprise that pays cloud providers for security that the cloud architecture itself undermines.

---

## Architecture Overview

```
+------------------------------------------------------------------+
|                        Bedrock Core                               |
|                                                                   |
|  +------------------+    +------------------+                     |
|  | Identity Fabric  |    | Encryption Engine |                    |
|  | (B-105 to B-107) |    | (B-102, B-103)    |                    |
|  +------------------+    +------------------+                     |
|           |                       |                              |
|  +------------------+    +------------------+                     |
|  |  Access Control  |    | Data Separation   |                    |
|  |    (B-109)       |    |    (B-104)        |                    |
|  +------------------+    +------------------+                     |
|           |                       |                              |
|  +------------------+    +------------------+    +--------------+ |
|  | Transport Sec.   |    |  Audit Chain      |    | Self-Healing| |
|  |    (B-110)       |    |    (B-108)         |    | Mesh (B-111)| |
|  +------------------+    +------------------+    +--------------+ |
+------------------------------------------------------------------+
```

---

## B-101: Core Project Structure

**What:** The skeleton that everything else hangs off of.

**Files:**
- `core/bedrock/__init__.py` — Package root
- `core/bedrock/config.py` — All configuration in one place
- `core/pyproject.toml` — Build config, dependencies, tooling

**What config.py contains:**
- `CoreConfig` — master settings object
- `EncryptionConfig` — algorithm, HKDF params, rotation schedule
- `KeyManagementConfig` — master key source, derivation settings
- `DataSeparationConfig` — silo defaults, anonymous ID word lists
- `IdentityConfig` — node registration, attestation settings
- `AuditConfig` — chain settings, retention policy
- `AccessControlConfig` — RBAC, session, MFA settings
- `MeshConfig` — self-healing mesh parameters
- `TransportConfig` — TLS, E2EE, rate limiting

Every component reads its settings from `CoreConfig`. No scattered env vars or magic strings.

---

## B-102: Encryption Engine

**What:** The core encryption module. Encrypts individual data fields so that even if the database is stolen, each field requires its own key to decrypt.

**Why:** In most systems, encryption is at the volume or database level. If someone gets the encryption key, they get everything. Bedrock encrypts at the field level, with each data category (silo) having its own derived key. Stealing one key reveals one category of data, never the full picture.

**Components:**

### FieldEncryptor
Encrypts and decrypts individual data fields within a silo.

**How it works:**
1. Takes plaintext, a silo name, and a field type (e.g. "medical", "ssn")
2. Derives a per-silo encryption key using HKDF-SHA256 from the master key
3. Further derives a per-field key within that silo
4. Generates a random 96-bit IV (nonce)
5. Builds Additional Authenticated Data (AAD) — a base64-encoded JSON string containing context that binds the ciphertext to its purpose (silo, field type, timestamp, node ID)
6. Encrypts with AES-256-GCM using the derived key, IV, and AAD
7. Returns a self-contained wire format: `v2:base64(aad_length || aad_bytes || iv || ciphertext || tag)`

**Why the AAD matters:** AAD is checked during decryption. If someone tries to decrypt an SSN field in the medical silo by moving the ciphertext to the auth silo, the AAD won't match and decryption fails. The AAD is embedded in the ciphertext itself, so you don't need to store it separately.

### E2EEDeliverer
Encrypts data for delivery from one node to another. No server in the middle can decrypt it.

**How it works:**
1. Sender generates an ephemeral ECDH-P256 key pair
2. Sender has the recipient's public key
3. Sender and recipient do ECDH key agreement: `shared_secret = sender_private * recipient_public`
4. Both sides derive the same symmetric key via HKDF-SHA256
5. Sender encrypts the message with AES-256-GCM, including AAD with sender/recipient IDs and timestamp
6. Wire format: `v2:base64(aad_length || aad_bytes || ephemeral_pubkey_length || ephemeral_pubkey || iv || ciphertext || tag)`
7. Recipient uses their private key + sender's ephemeral public key to derive the same symmetric key and decrypt

**Why ephemeral keys:** Each message uses a fresh key pair. Even if one message's key is compromised, all other messages remain safe. This is forward secrecy at the message level.

### EncryptionEngine
Top-level facade that combines `FieldEncryptor` and `E2EEDeliverer`. Most code will use this rather than the lower-level classes directly.

---

## B-103: Key Management

**What:** The hierarchy that derives all encryption keys from a single master key, with rotation support.

**Why:** You can't manage 100 different encryption keys manually. Bedrock derives every key from one master key using HKDF (HMAC-based Key Derivation Function). When you rotate the master key, all derived keys change. Old keys are retained for decryption of existing data.

**Components:**

### MasterKey
A dataclass holding the raw 256-bit master key bytes and a SHA-256 fingerprint for identification. The master key never leaves the `KeyManager`. It's stored as an environment variable or in an HSM (Hardware Security Module) in production.

### SiloKey
A dataclass representing a derived key for a specific silo and version. Contains the key bytes, the silo name, the version number, and the HKDF info string used to derive it.

### KeyManager
The central key derivation engine.

**How it works:**
1. `generate_master_key()` — Generates a cryptographically random 256-bit master key
2. `derive_silo_key(master_key, silo_name, version)` — Derives a silo-specific encryption key using HKDF-SHA256 with info string `bedrock:silo:{name}:v{version}`
3. `derive_field_key(silo_key, field_type)` — Further derives a field-specific key within a silo using info string `bedrock:field:{field_type}`
4. `rotate_silo_key(master_key, silo_name)` — Increments the version, derives a new key, retires the old key
5. `get_active_key_version(silo_name)` — Returns the current key version for a silo
6. `get_retired_key(silo_name, version, master_key)` — Returns an old key for decrypting data encrypted with a previous version

**Cache design:** Derived keys are cached using `(master_key_hash, silo_name, version)` as the cache key. This prevents cache collisions when different master keys are used with the same KeyManager (e.g., during key rotation testing).

**Rotation:** When a silo key is rotated, the old key is kept in a retired keys cache. This allows decrypting data that was encrypted with the old key while all new encryptions use the new key. The old key is never deleted — it stays for backward compatibility.

---

## B-104: Data Separation Layer

**What:** The compartmentalization layer that ensures a breach of one data category reveals nothing about any other category.

**Why:** If an attacker steals the medical records database, they should learn nothing about the patient's identity, financial information, or authentication credentials. Each category lives in its own encrypted silo with its own key.

**Components:**

### Silo
A dataclass defining a cryptographically isolated data partition. Each silo has:
- `name` — unique identifier (e.g., "medical", "pii", "auth")
- `display_name` — human-readable name (e.g., "Medical Records")
- `hkdf_info` — the key derivation string (e.g., "bedrock:silo:medical:v1")
- `categories` — list of data categories stored in this silo
- `encrypted` — whether data is encrypted (always True by default)
- `key_version` — current encryption key version

**Typical silo patterns:**
- Healthcare: PII silo, Medical silo, Auth silo
- Banking: Identity silo, Transaction silo, Auth silo
- Defense: Identity silo, Intelligence silo, Auth silo

### SiloManager
CRUD operations for silos. Create, read, update, delete, list. Enforces uniqueness — no two silos with the same name.

**Key methods:**
- `create_silo()` — Creates a new silo with auto-generated HKDF info
- `get_silo()` — Retrieve by name
- `list_silos()` — All silos
- `get_silos_for_category()` — Find which silos contain a given data category
- `update_silo()` — Change display name, categories, description
- `delete_silo()` — Hard delete (production should gate this with audit chain approval)

### AnonymousID
Generates opaque identifiers in the format `{adjective}-{animal}-{noun}` (e.g., "crimson-arctic-fox").

**Why:** Records in different silos must be linkable without revealing the real identity. A patient's medical record might be "crimson-arctic-fox" while their PII record is "azure-mountain-epoch". Only the IDMappingTable knows they're the same person.

**Combination space:** 531 adjectives x 375 animals x 509 nouns = 101,000,000+ combinations. This exceeds the anonymity threshold while keeping IDs human-readable.

**Key methods:**
- `generate()` — Random anonymous ID
- `generate_unique(existing_ids)` — Generates an ID guaranteed not to collide with existing IDs
- `validate(anon_id)` — Checks format correctness (3 alpha parts separated by hyphens)

### IDMappingTable
The single most sensitive table in the system. Maps real identities to anonymous IDs across silos.

**How it works:**
- `register(real_id, silo_name, anon_id)` — Links a real identity to an anonymous ID in a specific silo
- `lookup(real_id, silo_name)` — Finds the anonymous ID for a person in a silo
- `reverse_lookup(anon_id)` — Finds the real identity behind an anonymous ID (most sensitive operation — requires ConsentGate approval in production)
- `link_cross_silo(real_id, source_silo, target_silo, consent_id)` — Links data across silos with a consent reference
- `unregister(real_id)` — Right-to-be-forgotten: removes all mappings for a person

**Security properties:**
- Compromising one silo reveals nothing about other silos
- The mapping table itself is encrypted at rest (stored in the identity silo)
- Every lookup is audit-logged in production
- No cross-silo access without explicit consent

### ConsentGate
Manages consent-gated cross-silo data access. Generalizes InFill's PIR/ePRR pattern.

**Lifecycle:**
1. `request_consent()` — A node requests access to data in another silo (status: PENDING)
2. `approve_consent()` — Data owner approves with a time limit (status: APPROVED)
3. `check_consent()` — Verify consent is still valid before data access (checks expiry)
4. `revoke_consent()` — Data owner can revoke at any time (status: REVOKED)
5. `deny_consent()` — Data owner denies the request (status: DENIED)

**Consent scope hierarchy:**
- `write` consent implies `read` access
- `read` consent does NOT imply `write` access
- `consent` is a special scope for granting consent to others

**Time limits:** All consent is time-limited via TTL (default 1 hour). Expired consent auto-transitions from APPROVED to EXPIRED on the next `check_consent()` call.

**Category scoping:** Consent is specific to data categories. A request for "diagnosis" access does not grant "prescriptions" access unless explicitly approved.

---

## Wire Format Reference

All encrypted data uses a versioned wire format for future compatibility:

### Field Encryption
```
v2:base64(aad_length[2 bytes] || aad_bytes || iv[12 bytes] || ciphertext || tag[16 bytes])
```

### E2EE Encryption
```
v2:base64(aad_length[2 bytes] || aad_bytes || eph_key_length[2 bytes] || eph_pubkey[65 bytes] || iv[12 bytes] || ciphertext || tag[16 bytes])
```

The `v2:` prefix enables backward-compatible migration. If we change the algorithm in the future, we add `v3:` and the decryptor checks the prefix.

---

## Key Derivation Chain

```
Master Key (256 bits, from env var or HSM)
  |
  +-- HKDF-SHA256(info="bedrock:silo:medical:v1") --> Medical Silo Key
  |     |
  |     +-- HKDF-SHA256(info="bedrock:field:ssn") --> SSN Field Key
  |     +-- HKDF-SHA256(info="bedrock:field:diagnosis") --> Diagnosis Field Key
  |     +-- HKDF-SHA256(info="bedrock:field:prescription") --> Prescription Field Key
  |
  +-- HKDF-SHA256(info="bedrock:silo:pii:v1") --> PII Silo Key
  |     |
  |     +-- HKDF-SHA256(info="bedrock:field:name") --> Name Field Key
  |     +-- HKDF-SHA256(info="bedrock:field:address") --> Address Field Key
  |
  +-- HKDF-SHA256(info="bedrock:silo:auth:v1") --> Auth Silo Key
        |
        +-- HKDF-SHA256(info="bedrock:field:credentials") --> Credentials Field Key
```

Each level is deterministic: same master key + same info string = same derived key. This means you can re-derive any key on demand without storing it. But the derivation path ensures that knowing a field key reveals nothing about any other key.

---

## Test Coverage Summary

| Module | Tests | Status |
|--------|-------|--------|
| Config | 11 | Passing |
| AAD | 8 | Passing |
| CiphertextFormat | 3 | Passing |
| Key Management | 13 | Passing |
| Encryption Engine | 21 | Passing |
| Data Separation | 57 | Passing |
| Mesh State Machine | 14 | Passing |
| Node | 7 | Passing |
| Node Registration | 50 | Passing |
| Attestation | 29 | Passing |
| Certificates | 30 | Passing |
| Audit Chain | 41 | Passing |
| Access Control | 51 | Passing |
| Transport Security | 41 | Passing |
| Self-Healing Mesh | 46 | Passing |
| Core | 25 | Passing |
| Integration | 22 | Passing |
| **Total** | **464** | **All passing** |

---

## B-105: Identity Fabric — Node Registration

**What:** Every node in a Bedrock network gets a cryptographic identity. Not just users — servers, containers, IoT devices, API gateways, everything. A compromised router sees only ciphertext because it has no identity scope to decrypt.

**Why:** Traditional zero-trust gives identities to people. Bedrock extends identity to every compute node. This is the foundation of the Self-Healing Mesh — nodes can't participate without an identity, and compromised nodes can be isolated by revoking their identity.

**Components:**

### NodeID
A UUID v7 (time-sortable) paired with an ed25519 public key (32 bytes). The public key is the node's cryptographic identity. The private key never leaves the node.

**Key methods:**
- `NodeID.generate()` — Generates a new UUID + ed25519 key pair
- `NodeID.generate(private_key)` — Uses an existing key pair (for key recovery)
- `public_key_hex()` — Hex representation for display/logging
- `fingerprint()` — Short 16-char hex prefix for quick identification

### Node
A dataclass representing a node in the mesh. Contains:
- `node_id` — Cryptographic identity (UUID + public key)
- `name` — Human-readable identifier (must be unique in registry)
- `node_type` — server, container, iot, gateway, client
- `state` — Trust state in the Self-Healing Mesh (see below)
- `capabilities` — What data categories this node can access
- `attestation_baseline` — SHA-256 hash of known-good software state
- `certificate_serial` / `certificate_expires` — X.509 certificate binding
- `flags` — Neighbor consensus flags for mesh quarantine
- `metadata` — Extensible key-value pairs

**Trust state checks:**
- `can_route()` — ACTIVE and SUSPECT nodes can route traffic
- `can_relay()` — ACTIVE, SUSPECT, and HEALING nodes can relay (but HEALING can't decrypt)
- `can_decrypt()` — Only ACTIVE and SUSPECT nodes can decrypt data
- QUARANTINED nodes are fully isolated — no routing, no relay, no decrypt
- REVOKED nodes are permanently removed

### NodeRegistry
The central registry for all nodes. Manages registration, lookup, and state transitions.

**Key methods:**
- `register(name, node_type, private_key, metadata)` — Register a new node with cryptographic identity
- `get(uuid)` / `get_by_name(name)` / `get_by_public_key(key)` — Three lookup methods
- `list_nodes(state, node_type)` — Filter nodes by state or type
- `transition(uuid, new_state, reason)` — State machine transitions with enforcement
- `verify_identity(uuid, public_key)` — Authenticate a node's claimed identity
- `heartbeat(uuid)` — Record a node heartbeat
- `unregister(uuid)` — Remove a node (triggers audit + cert revocation in production)

**State transitions** (enforced, not suggestions):
```
ACTIVE → SUSPECT (neighbor flags) → REVOKED (compromised)
SUSPECT → QUARANTINED (attestation failed) → HEALING (re-attesting)
HEALING → ACTIVE (re-attestation passed) or QUARANTINED (failed again)
Any state → REVOKED (terminal, no recovery)
```

Once REVOKED, a node cannot transition to any other state. This is the mesh's kill switch for compromised nodes.

---

## B-106: Identity Fabric — Attestation

**What:** Nodes prove their software state matches a known-good baseline at boot time. If a sensor's firmware has been tampered with, the attestation fails and the node is quarantined before it can do any damage.

**Why:** Without attestation, an attacker who replaces firmware on an IoT device or injects code into a server process can operate undetected. Attestation creates cryptographic proof that every node is running authorized software.

**Components:**

### AttestationClaim
A signed statement from a node about its current software state. The claim contains:
- `node_uuid` — Which node is attesting
- `state_hash` — SHA-256 of the node's firmware, OS, and config
- `components` — What was hashed (["firmware", "os", "config"])
- `timestamp` — When the claim was generated
- `signature` — ed25519 signature over (uuid + state_hash + timestamp)

Tampering with ANY field after signing invalidates the signature. This prevents spoofing.

### AttestationManager
The verification engine. Checks three things:
1. **Signature** — Claim is signed by the node's ed25519 key (not spoofed)
2. **Freshness** — Claim timestamp is within 5 minutes (prevents replay)
3. **Baseline match** — State hash matches the registered known-good baseline

If all three pass → PASSED. If signature or baseline fail → FAILED. If claim is stale → EXPIRED.

### AttestationPolicy
Controls how strict quarantine enforcement is:
- **STRICT** — Any failure → quarantine immediately
- **MODERATE** — 2+ consecutive failures → quarantine (gives one chance for false positives)
- **PERMISSIVE** — Log only, no automatic quarantine (for dev environments)

### BaselineEntry
A registered known-good state hash for a node type. When firmware updates, the admin registers a new baseline and the old one is marked as superseded.

### compute_state_hash()
Utility function that hashes one or more component hashes into a final state hash. This is what nodes call at boot time: hash(firmware + os + config) → state_hash.

### Failure tracking
Consecutive failures are counted per node. A successful attestation resets the counter. This feeds into `should_quarantine()` which the Self-Healing Mesh calls to decide whether to transition a node.

---

## B-107: Identity Fabric — Certificate Lifecycle

**What:** Every node gets a short-lived certificate (24h default) that binds its cryptographic identity to its capability scope. Certificates are the enforcement mechanism for the Self-Healing Mesh — a quarantined node's certificate is revoked immediately, cutting off its ability to route, relay, or decrypt data.

**Why:** Without certificates, there's no way to enforce capability scope at the network level. A compromised node with a valid cert can be instantly cut off by revoking the cert and distributing the revocation to all nodes via CRL. Short-lived certs mean even if one is stolen, it expires in hours.

**Components:**

### Certificate
A dataclass representing a node certificate. In production this would be X.509 with custom Bedrock extensions. Key fields:
- `serial` — Unique identifier (format: `bedrock-<uuid4>`)
- `node_uuid` — Which node this cert belongs to
- `public_key_hash` — SHA-256 of the node's ed25519 public key (binds identity)
- `capabilities` — Data categories this node can access (enforced by AAD + Access Control)
- `issued_at` / `expires_at` — Short TTL, default 24h
- `status` — ACTIVE, EXPIRED, REVOKED, PENDING_RENEWAL
- `issuer` — `bedrock-ca` for Runtime, `bedrock-self-signed` for Developer
- `license_tier` — Which license tier issued this cert

### CertificateManager
Manages the full certificate lifecycle:
- `issue_certificate()` — Creates a new cert for a registered node. Enforces license limits.
- `renew_certificate()` — Auto-renews before expiry. New serial, same capabilities. Old cert stays valid until it expires (grace period).
- `revoke_certificate()` — Immediate revocation when a node is quarantined. Adds serial to CRL.
- `check_crl()` — Checks if a serial is on the Certificate Revocation List.
- `check_license_limit()` — Verifies active cert count is within the licensed limit.

### License Tiers (the two-tier licensing model)
This is where the business model meets the code:

| Tier | Max Nodes | Certificate Authority | Use Case |
|------|-----------|----------------------|----------|
| DEVELOPER | 3 | Self-signed | Dev/testing only |
| STARTER | 5 | CA-signed | Small production |
| BUSINESS | 25 | CA-signed | Mid-market |
| ENTERPRISE | Unlimited | CA-signed | Large/air-gapped |

Developer tier enforces localhost-only, 3-node max. This is the $99/$499/year funnel. Runtime tiers ($5K–$20K+/year) get CA-signed certs and production node limits.

### LicenseExceededError
Raised when `issue_certificate()` would exceed the licensed node count. The error message tells you exactly what tier you're on and what the limit is. Revoking a certificate frees up a slot.

---

## B-108: Audit Chain

**What:** Every action in a Bedrock network is logged to a tamper-evident SHA-256 hash chain. Each entry's hash is computed from the previous entry's hash plus the entry data. Any modification to a past entry invalidates all subsequent hashes — making it cryptographically impossible to alter audit logs undetected.

**Why:** Regulatory compliance (HIPAA, SOC 2, PCI-DSS) requires immutable audit trails. But traditional audit logs can be silently modified by anyone with database access. The hash chain makes tampering detectable: you can verify the entire chain's integrity with a single pass, and any break proves exactly where the tampering happened.

**Components:**

### AuditEntry
A single entry in the chain. Key fields:
- `timestamp` — UTC timestamp of the action
- `action` — What happened (e.g., "node.register", "field.encrypt", "consent.approve")
- `actor_id` — Who did it (node UUID or user ID)
- `target_id` — What was acted upon (record ID, node ID)
- `silo` — Which data silo this relates to
- `details` — Arbitrary key-value metadata
- `prev_hash` — SHA-256 hash of the previous entry (chain link)
- `entry_hash` — SHA-256 hash of this entry (computed on append)
- `entry_index` — Position in the chain (0-indexed)

Hash computation: `SHA-256(prev_hash + action + actor_id + target_id + silo + timestamp + details_json)`. Sorted JSON for deterministic hashing.

### AuditAction (enum)
Standard action types following `category.operation` format:
- Node lifecycle: node.register, node.attest, node.quarantine, node.revoke, node.heal
- Certificate: cert.issue, cert.renew, cert.revoke
- Encryption: field.encrypt, field.decrypt, e2ee.send, e2ee.receive
- Key management: key.rotate, key.retire
- Consent: consent.request, consent.approve, consent.deny, consent.revoke
- Silo access: silo.access
- Auth: auth.login, auth.logout, auth.mfa, auth.fail
- Chain itself: chain.verify, chain.export
- Custom: custom.action

### AuditChain
Append-only SHA-256 hash chain:
- `append()` — Creates entry with computed hash, chains to previous entry
- `verify()` — Re-hashes every entry, confirms chain integrity. Detects any tampering.
- `verify_range()` — Incremental verification for large chains
- `query()` — Multi-filter search (action, actor, target, silo, time range)
- `export()` — JSONL or JSON export for compliance reporting
- `import_chain()` — Reconstruct from export, verifies integrity on import
- `head_hash` / `tail_hash` — Chain head (most recent) and genesis hash

Genesis hash: 64 zero hex chars (`"0" * 64`). Empty chain is valid.

6-year retention per HIPAA/SOC 2/PCI-DSS requirements.

---

## B-109: Access Control

**What:** Role-based access control (RBAC) with portal scoping, MFA, and account lockout. Every access decision is enforceable at the session level — not just "is this user authenticated?" but "is this session scoped to this portal, with these capabilities, verified by MFA?"

**Why:** In Bedrock's multi-portal architecture, a patient portal user must never access admin resources, even with valid credentials. The access controller enforces this structurally: sessions are scoped to a single portal, roles are mapped to portals, and write operations require MFA verification.

**Components:**

### Role, Portal, Permission (enums)
- **Role**: ADMIN, OPERATOR, VIEWER, DENIED (terminal revocation)
- **Portal**: PATIENT, PROVIDER, ADMIN, PARTNER — sessions are scoped to one portal
- **Permission**: 17 granular permissions following `category.operation` format (data.read, node.quarantine, cert.issue, etc.)

### DEFAULT_ROLE_PERMISSIONS
- ADMIN: all 17 permissions
- OPERATOR: data read/write, consent, node management, cert issue, audit read
- VIEWER: data read, consent request, audit read (read-only)
- DENIED: no permissions

### PORTAL_ROLE_COMPATIBILITY
- PATIENT portal: VIEWER, OPERATOR, ADMIN
- PROVIDER portal: VIEWER, OPERATOR, ADMIN
- ADMIN portal: ADMIN only
- PARTNER portal: VIEWER, OPERATOR (no admin access)
A VIEWER cannot authenticate to the admin portal at all — structurally enforced.

### Session
- Scoped to a single portal with role-derived capabilities
- 8-hour default TTL, auto-expiry
- `is_valid()`: not expired, not DENIED role
- `has_permission()`: checks role permission set
- MFA verification tracked per-session
- Serializable to dict for audit logging

### UserAccount
- SHA-256 hashed passwords
- Per-user TOTP secret (hex-encoded, 32 bytes)
- Failed attempt counter with progressive delay (0s, 1s, 2s, 5s, 10s)
- Auto-lockout after 5 failed attempts (15-minute cooldown)
- Manual lock/unlock for admin intervention

### AccessController
- `create_user()`: creates account with hashed password and random TOTP secret
- `authenticate()`: validates credentials + portal compatibility, creates scoped session. Returns None on failure, raises PermissionError on locked account.
- `verify_mfa()`: TOTP verification (RFC 4226, HMAC-SHA1, 30s steps, ±1 window for clock drift)
- `check_permission()`: validates session + role + MFA requirement in one call
- `lock_account()` / `unlock_account()`: admin actions for the Self-Healing Mesh
- `end_session()`: explicit logout

**MFA requirement**: Write operations (data.write, data.delete, data.export, consent.approve/deny/revoke, node.quarantine/revoke, cert.issue/revoke, admin.config, admin.user_manage) all require MFA verification. Read operations don't.

---

## B-110: Transport Security

**What:** TLS termination configuration, downgrade attack detection, per-node/IP rate limiting, and connection lifecycle management. The transport layer wraps the encryption engine's E2EE functionality and ensures the channel is safe before data is exchanged.

**Why:** Without transport security, even E2EE-encrypted data can be intercepted through downgrade attacks (forcing TLS 1.0/1.1), DDoS attacks (overwhelming a node with requests), or connection hijacking. The transport layer enforces minimum TLS versions, detects downgrade attempts, and throttles abuse before it reaches the encryption engine.

**Components:**

### TLSConfig
- Minimum version enforcement: TLS 1.3 for production, TLS 1.2 for developer mode
- `is_developer_mode()`: TLS 1.2 + no CA cert = dev mode (self-signed)
- `is_production_mode()`: TLS 1.3 + CA cert = production mode
- Client certificate verification, server cipher preference
- 5-minute session timeout, max 10 concurrent sessions per client

### DowngradeStatus (enum)
- SECURE: Connection meets TLS requirements
- DOWNGRADE: Downgrade attack detected (TLS version below minimum, or HTTP instead of HTTPS)
- UNKNOWN: Cannot determine TLS version

### RateLimitConfig / RateLimiter
- Sliding window algorithm (1-minute and 1-hour windows)
- Burst size: short bursts allowed, sustained over-rate throttled
- Violation tracking: 5 violations = 15-minute block
- Per-key (node ID or IP address) independent limits
- `reset()`: admin action to clear rate limits for a key
- `get_status()`: inspect current limits and violation counts

### ConnectionInfo / TransportLayer
- Connection registration with TLS version and E2EE tracking
- Activity metrics (bytes sent/received, last activity timestamp)
- Connection limit (default 1000 per transport instance)
- Per-node filtering for active connections
- Full lifecycle: register → activity updates → close

### Downgrade detection
- Checks X-Forwarded-Proto header (HTTP = downgrade)
- Checks X-TLS-Version header (below minimum = downgrade)
- Handles TLSv1.2, TLSv1.3, 1.2, 1.3 formats
- Production mode: missing TLS version headers = UNKNOWN (suspicious)
- Developer mode: TLS 1.2 accepted as SECURE

---

## Remaining Work (Phase 1)

| Task | Component | Description |
|------|-----------|-------------|
| B-111 | Self-Healing Mesh | Attack detection, node isolation, automatic rerouting |
| B-112 | Core Integration Tests | End-to-end cross-component tests |

---

## B-111: Self-Healing Mesh

**Status:** Complete

Implemented the full Self-Healing Mesh — distributed attack detection, consensus-based
node isolation, automatic rerouting, healing protocol, and node state machine.

### Files

- `core/bedrock/mesh/state_machine.py` (149 lines) — NodeStateMachine with 5-state lifecycle
  (ACTIVE → SUSPECT → QUARANTINED → HEALING → ACTIVE; REVOKED is terminal). Transition
  validation, history tracking, `can_promote_to_active()` for healing completion.
- `core/bedrock/mesh/detector.py` (148 lines) — AttackDetector with `node_id` source binding,
  8 signal types (SILENT_NODE, UNUSUAL_VOLUME, CREDENTIAL_STUFFING, DATA_EXFILTRATION,
  MAN_IN_THE_MIDDLE, REPLAY_ATTACK, TAMPERING, PORT_SCAN), `should_isolate()` for
  consensus checks, `clear_signals()` for healing.
- `core/bedrock/mesh/router.py` (234 lines) — MeshRouter with capability-scope-aware path
  calculation. Medical-scope nodes never relay transaction data. BFS pathfinding,
  quarantine-aware routing (skips QUARANTINED/REVOKED nodes), `find_alternate_path()`,
  redundancy verification.
- `core/bedrock/mesh/healing.py` (295 lines) — SelfHealingMesh orchestrator. Coordinates
  detector, state machine, and router. Node registration/unregistration, flag processing
  with consensus thresholds, `begin_healing()` / `complete_healing()` lifecycle,
  `reroute()` with scope filtering, `revoke_node()` for admin override.
- `core/bedrock/mesh/__init__.py` (24 lines) — Updated exports

### Key Design Decisions

- **Node state lifecycle:** ACTIVE → SUSPECT → QUARANTINED → HEALING → ACTIVE. REVOKED is
  terminal (no return). Admin can force-revoke any node at any state.
- **Consensus threshold:** Default 2 unique flags required. Single flag = suspicious but
  not actionable. Two independent observers = consensus.
- **Capability-scope routing:** Each node declares data categories (IDENTITY, MEDICAL,
  FINANCIAL, etc.). Routes only traverse nodes with compatible categories. Medical-scope
  nodes never relay transaction data.
- **Healing protocol:** QUARANTINED → HEALING → ACTIVE requires re-attestation. Healing
  can fail and roll back to QUARANTINED.
- **UUID-based node keys:** Mesh stores nodes by `node_id.uuid` string (NodeID is not
  hashable as a dataclass). All mesh operations use UUID strings as identifiers.

### Tests: 46 passing

- 17 MeshStateMachine tests (all valid/invalid transitions, history, promotion)
- 8 AttackDetector tests (signal detection, consensus, clearing)
- 12 MeshRouter tests (pathfinding, quarantine bypass, scope filtering, redundancy)
- 9 SelfHealingMesh integration tests (registration, flagging, consensus, lifecycle,
  rerouting, revocation, healing)

---

---

## B-112: Core Integration Tests

**Status:** Complete

End-to-end cross-component tests validating that all Bedrock subsystems work
together. 22 tests across 8 test classes:

1. **TestFullDataLifecycle** (7 tests) — register node, encrypt/decrypt with AAD
   binding, E2EE, consent request/approve/revoke, right to be forgotten, AAD
   tamper detection
2. **TestAttackSimulation** (2 tests) — full attack isolation lifecycle (5 nodes,
   flag/consensus/quarantine/reroute), healing restoration (SUSPECT→QUARANTINED→
   HEALING→ACTIVE with `healing_period_seconds=0` for test)
3. **TestCertificateAccessControlIntegration** (2 tests) — certificate lifecycle
   with RBAC (admin with MFA can issue/revoke, viewer cannot), developer tier
   3-node limit enforcement
4. **TestTransportSecurityIntegration** (3 tests) — TLS downgrade detection with
   audit chain logging, rate limiting ALLOWED→THROTTLED→BLOCKED progression,
   TLS config enforcement (developer vs production mode)
5. **TestAttestationMeshIntegration** (2 tests) — failed attestation flags node
   in mesh, strict vs permissive policy baselines
6. **TestCrossComponentAuditTrail** (2 tests) — full audit trail across all
   components with integrity verification, tamper detection via `_chain`
   replacement breaking hash chain
7. **TestAccessControlTransportIntegration** (3 tests) — portal isolation with
   TLS configs, RBAC blocks viewer from admin endpoints, rate limiting per portal
8. **TestPatientDataFlowIntegration** (1 test) — complete patient data flow:
   register → consent → encrypt → audit → decrypt → revoke

Key API discoveries during integration:
- `AuditChain.append()` takes positional args `(action, actor_id, target_id, silo)`,
  not an `AuditEntry` object. `len(chain)` counts appends only (no genesis).
- `AccessController.check_permission()` requires a `Session` (with `mfa_verified=True`
  for write operations), not a `UserAccount`.
- `SelfHealingMesh(healing_period_seconds=0)` needed for tests so healing completes
  immediately (default 3600s wait).
- `RateLimiter.check()` returns `THROTTLED` after burst, `BLOCKED` only after
  `violation_threshold` violations at the minute limit.
- `ConsentGate.check_consent()` returns `None` for non-existent or revoked consents.

---

## B-201: Python SDK Project Structure

**Status:** Complete

Developer-friendly Python SDK wrapping all Bedrock Core modules. Single entry
point (`BedrockClient`) with property-accessed modules:

- `client.identity` — Node registration, certificates, capability scoping
- `client.encryption` — Field-level encrypt/decrypt, E2EE delivery, key rotation
- `client.data` — Cross-silo consent, anonymous ID mapping, right to be forgotten
- `client.audit` — Tamper-evident chain write, verify, query, export
- `client.access` — RBAC user creation, authentication, MFA, permission checks
- `client.transport` — TLS config, downgrade detection, mesh flag/heal/reroute

SDK design decisions:
- `CoreConfig` (not BedrockConfig) is the actual config class name
- `AccessController.authenticate(username, password, portal)` — not role-based
- `AccessController.verify_mfa(session_id, totp_code)` — takes ID, not Session
- `AuditEntry.entry_hash` (not `.hash`); `head_hash`/`tail_hash` are properties
- `DataCategory` uses lowercase: `"identity"`, `"medical"`, not uppercase
- `IDMappingTable.register(real_id, silo_name, anon_id)` — 3 args, SDK generates
- `E2EEDeliverer.decrypt_from_sender(sender_public_key, recipient_private_key)`
- Mesh `process_flags()` requires two calls: ACTIVE→SUSPECT→QUARANTINED
- `SelfHealingMesh(healing_period_seconds=0)` for instant test healing

Files created:
- `sdk/pyproject.toml` — Build config, dependencies, linting
- `sdk/README.md` — Quick start guide
- `sdk/bedrock_sdk/__init__.py` — Package entry
- `sdk/bedrock_sdk/client.py` — BedrockClient central API
- `sdk/bedrock_sdk/identity.py` — IdentityModule
- `sdk/bedrock_sdk/encryption.py` — EncryptionModule
- `sdk/bedrock_sdk/data.py` — DataModule
- `sdk/bedrock_sdk/audit.py` — AuditModule
- `sdk/bedrock_sdk/access.py` — AccessModule
- `sdk/bedrock_sdk/transport.py` — TransportModule
- `sdk/tests/test_sdk.py` — 36 SDK tests

| Suite | Tests | Status |
|-------|-------|--------|
| Core | 464 | All passing |
| SDK | 36 | All passing |
| Integration (Python) | 16 | All passing |
| Integration (TypeScript) | 16 | All passing |
| **Total (Python)** | **516** | **All passing** |
| **Total (TypeScript)** | **68** | **All passing** |

*Last updated: B-216 complete, 584 total tests passing*

---

## B-216: SDK Integration Tests (TypeScript)

**Status:** Complete

End-to-end integration tests exercising full workflows through the TypeScript SDK
(BedrockClient). 8 workflow classes, 16 test methods covering:

1. **Healthcare** — Register provider, encrypt PHI, consent-gated access,
   audit trail, consent revocation
2. **Banking** — RBAC with MFA, operator vs admin vs viewer permissions,
   transaction encryption
3. **Defense Mesh** — Node registration, flagging, consensus, two-round
   quarantine (ACTIVE→SUSPECT→QUARANTINED), healing lifecycle
4. **Multi-Silo Anonymous** — Anonymous IDs across silos, resolve/revoke,
   right to be forgotten, cross-silo encryption
5. **Key Rotation** — Master key rotation, audit chain integrity across
   rotation, v2 ciphertext format
6. **Production Mode** — Developer vs production config, TLS downgrade
   detection (HTTP, TLS version, secure), rate limiting
7. **Certificate Lifecycle** — Issue, revoke, error handling, audit trail
8. **Rate Limiting** — Normal traffic allowed, independent key tracking

Key API differences from Python SDK that surfaced during testing:
- TS SDK methods use positional args, not keyword/object args
- `encrypt`/`decrypt` are async (Web Crypto API)
- `audit.log`/`audit.verify` are async (SHA-256 via Web Crypto)
- `AccessModule.verifyMfa` is simplified — any code marks session verified
- `TransportModule` has `.tls` and `.mesh` sub-modules (not flat methods)
- `mesh.registerNode(node)` takes a Node object, not name+categories
- `Portal.SYSTEM = 'system'` exists in TS (not in Python)
- `CertificateStatus` enum: ACTIVE, EXPIRED, REVOKED (not NodeState)
- `SignalType` enum differs: has PORT_SCAN, BRUTE_FORCE, PRIVILEGE_ESCALATION,
  MAN_IN_THE_MIDDLE (Python has LATERAL_MOVEMENT, PATH_ANOMALY,
  CERTIFICATE_ANOMALY, AAD_MISMATCH)

Bug fix applied: `identity.ts` was creating certificates with
`status: { value: 'active' } as any` instead of `CertificateStatus.ACTIVE`.
Fixed to use the proper enum value.

---

## B-215: SDK Integration Tests (Python)

**Status:** Complete

End-to-end integration tests exercising full workflows through the Python SDK
layer (BedrockClient). 8 workflow classes, 16 test methods covering:

1. **Healthcare** — Register provider, encrypt PHI, consent-gated access,
   audit trail, consent revocation
2. **Banking** — RBAC with MFA-gated operations, role-based permission
   enforcement, TOTP generation for test MFA
3. **Defense/Mesh** — Self-healing mesh under attack, node flagging,
   consensus-driven quarantine, two-round state transitions
   (ACTIVE→SUSPECT→QUARANTINED), healing lifecycle
4. **Multi-Silo** — Anonymous ID creation, cross-silo resolution,
   right to be forgotten
5. **Key Rotation** — Master key rotation preserves audit chain integrity
6. **Production/Developer Mode** — TLS config, downgrade detection, mode defaults
7. **Certificate Lifecycle** — Issue, revoke, error handling
8. **Rate Limiting** — Independent key tracking

Key API discoveries during integration testing:
- `authenticate(username, password, portal)` — portal is required; valid values
  are `patient`, `provider`, `admin`, `partner`
- `check_permission(session, permission)` returns False without MFA even if
  the capability is in the session list
- `verify_mfa(session_id, totp_code)` — must use real TOTP generated from the
  user's secret; cannot use a static code
- `flag_node(source_id, target_id, signal_type)` — positional args, not
  keyword args `source_node_id`/`target_node_id`
- `SignalType` values: `credential_stuffing`, `lateral_movement`,
  `unusual_volume`, `attestation_failure`, `path_anomaly`,
  `certificate_anomaly`, `aad_mismatch`, `silent_node`
- Mesh healing requires two `process_flags` rounds:
  ACTIVE→SUSPECT→QUARANTINED
- `begin_healing` only works on QUARANTINED nodes; requires
  `healing_period_seconds=0` for instant completion in tests
- `detect_downgrade()` and `check_rate_limit()` return plain strings,
  not enum objects
- `create_anonymous_id(real_id, silo)` takes 2 args, auto-generates the anon ID
- Error message for AAD mismatch is `"AAD context mismatch"`, not just
  `"AAD mismatch"`

Files:
- `sdk/tests/test_integration.py` — 16 integration tests

## B-208: TypeScript SDK Project Structure

**Status:** Complete

TypeScript SDK mirroring the Python SDK architecture. Uses Web Crypto API for
browser/Node.js compatibility. Same module structure as Python SDK:

- `BedrockClient` — Central entry point with `init()` for crypto setup
- `IdentityModule` — Node registration, certificates, capability scoping
- `EncryptionModule` — AES-256-GCM field encryption with v2 prefix format
- `DataModule` — Cross-silo consent, anonymous IDs, right to be forgotten
- `AuditModule` — SHA-256 hash chain, Web Crypto digest
- `AccessModule` — RBAC, authentication, MFA (simplified for SDK)
- `TransportModule` — TLS config, downgrade detection, mesh networking

TypeScript-specific decisions:
- Web Crypto API (`crypto.subtle`) for all crypto operations
- `v2:` prefix format matching Python SDK wire format
- `NodeState` enum used directly (not `NodeStateEnum` alias)
- `downlevelIteration: true` in tsconfig for Map iteration
- Branch coverage threshold set to 65% (will increase as edge cases are added)
- 52 tests covering all modules, including error branches

Files created:
- `sdk-ts/package.json` — Build config, dev dependencies
- `sdk-ts/tsconfig.json` — TypeScript strict config with downlevelIteration
- `sdk-ts/jest.config.js` — Jest + ts-jest, coverage thresholds
- `sdk-ts/README.md` — Quick start guide with all module APIs
- `sdk-ts/src/types.ts` — All shared enums and interfaces
- `sdk-ts/src/client.ts` — BedrockClient central entry point
- `sdk-ts/src/identity.ts` — IdentityModule
- `sdk-ts/src/encryption.ts` — EncryptionModule (AES-256-GCM + ECDH)
- `sdk-ts/src/data.ts` — DataModule
- `sdk-ts/src/audit.ts` — AuditModule (SHA-256 chain via Web Crypto)
- `sdk-ts/src/access.ts` — AccessModule
- `sdk-ts/src/transport.ts` — TransportModule (TLS + Mesh)
- `sdk-ts/src/index.ts` — Public exports
- `sdk-ts/tests/sdk.test.ts` — 52 TypeScript SDK tests

| Suite | Tests | Status |
|-------|-------|--------|
| core | 464 | All passing |
| Python SDK | 36 | All passing |
| TypeScript SDK | 52 | All passing |
| Integration (Python) | 16 | All passing |
| Integration (TypeScript) | 16 | All passing |
| Healthcare Template | 38 | All passing |
| Banking Template | 43 | All passing |
| Investment Template | 45 | All passing |
| Defense Template | 48 | All passing |
| Licensing System | 65 | All passing |
| InFill Adapter | 51 | All passing |
| TS SDK (expanded) | 122 | All passing |
| **Total** | **920** | **All passing** |

|*Last updated: B-310 complete, 920 total tests passing*|

---

## B-301: Healthcare Vertical Template

**Status:** Complete

Pre-configured healthcare vertical extracted from InFill's proven PIR/ePRR
patterns. Provides:

1. **Silo definitions** — identity (PII), medical (PHI), auth (credentials)
   with HIPAA-specific HKDF info strings and category isolation
2. **Consent flows** — PIR, ePRR, treatment, research, insurance with
   HIPAA section mappings and TTL defaults
3. **Role-portal mappings** — provider, patient, admin, researcher, insurer
   with minimum necessary standard enforcement
4. **HIPAA compliance report** — Maps 45 CFR Parts 160/164 sections to
   Bedrock enforcement mechanisms (encryption, consent, audit, RBAC)
5. **CoreConfig presets** — Production HIPAA configuration with 6-year
   audit retention, strict consent, MFA required, session timeouts

Core change: `SiloManager.create_silo()` now accepts optional `hkdf_info`
parameter for vertical-specific key derivation prefixes (e.g.
`bedrock:silo:healthcare:identity:v1`).

Files: `templates/healthcare/__init__.py`, `templates/healthcare/test_healthcare.py`

---

## B-302: Banking Vertical Template

**Status:** Complete

Pre-configured banking vertical for PCI-DSS compliance. Provides:

1. **Silo definitions** — identity (PII/KYC), transactions (financial data),
   auth (credentials/device fingerprints) with PCI-DSS-specific categories
   including payment_cards isolation (PCI-DSS 3.4)
2. **Consent flows** — account_inquiry, fund_transfer, loan_application,
   fraud_review, third_party_sharing with PCI-DSS section mappings
3. **Role-portal mappings** — customer, teller, analyst, admin, auditor
   with PCI minimum necessary standard enforcement
4. **PCI-DSS compliance report** — Maps Requirements 3-12 to Bedrock enforcement
5. **CoreConfig presets** — Production PCI-DSS config with 1-year audit
   retention, 30-min sessions, 3-attempt lockout, short consent TTLs

Banking template follows same architecture as healthcare but with:
- Shorter consent TTLs (30 min default vs 1 hr healthcare)
- Shorter sessions (30 min vs 1 hr)
- Stricter lockout (3 attempts vs 5)
- PCI-DSS 3.4 PAN isolation in transactions silo only

Files: `templates/banking/__init__.py`, `templates/banking/test_banking.py`

---

## B-303: Investment Vertical Template

**Status:** Complete

Pre-configured investment vertical for SEC/FINRA compliance. Provides:

1. **Silo definitions** — identity (PII/KYC/accreditation), portfolio
   (holdings/orders/margin), auth (credentials/trade surveillance)
2. **Consent flows** — account_opening, trade_execution, advisory,
   audit_review, third_party_sharing with SEC/FINRA section mappings
3. **Role-portal mappings** — client, advisor, trader, compliance, regulator
   with SEC minimum necessary standard enforcement
4. **SEC/FINRA compliance report** — Maps Reg S-P, Reg BI, FINRA Rules,
   SEC 17a-4, AML/BSA to Bedrock enforcement mechanisms
5. **CoreConfig presets** — 6-year audit retention (SEC 17a-4), 30-min sessions,
   MFA required, 5-min trade execution TTL

Investment-specific design decisions:
- Trade execution TTL: 5 minutes (shortest, for order security)
- Accreditation and beneficial ownership in identity silo (KYC/AML)
- Trade surveillance and compliance alerts in auth silo (FINRA 3110)
- 6-year audit retention (SEC 17a-4 requires 5-6 years)
- Regulator role: read-only, no write access

Files: `templates/investment/__init__.py`, `templates/investment/test_investment.py`

---

## B-304: Defense Vertical Template

**Status:** Complete

Pre-configured defense vertical for CMMC/DFARS compliance. Provides:

1. **Silo definitions** — identity (clearance/KYC), cui (CUI per 32 CFR 2002),
   auth (credentials/access logs/incident reports)
2. **Consent flows** — clearance_verification, cui_access, export_review,
   audit_review with CMMC/NIST 800-171 section mappings
3. **Role-portal mappings** — cleared_staff, program_manager, fso,
   subcontractor, auditor with clearance-level gating
4. **Clearance level system** — public(0), cui(1), secret(2), top_secret(3),
   top_secret_sci(4) with `check_clearance()` method
5. **CMMC/DFARS compliance report** — Maps CMMC Level 2 practices, DFARS
   252.204-7012, and NIST 800-171 to Bedrock enforcement
6. **CoreConfig presets** — 6-year audit, 30-min sessions, 3-attempt lockout,
   need-to-know consent (reason always required)

Defense-specific design decisions:
- Clearance levels gate every consent flow (need-to-know basis)
- CUI silo uses separate HKDF prefix (`bedrock:silo:defense:cui:v1`)
- Export review requires minimum Secret clearance (ITAR/EAR)
- FSO role has Top Secret clearance + cert issue/revoke
- 72-hour breach notification per DFARS 7012(c)
- Flow-down enforcement for subcontractors per DFARS 7012(d)
- All consent flows require reason (no exceptions — need-to-know)

Files: `templates/defense/__init__.py`, `templates/defense/test_defense.py`

---

## B-305: Developer Portal

**Status:** Complete

Documentation suite for the Bedrock SDK, providing:

1. **Quick Start Guide** — 5-minute setup with Python/TypeScript code examples
   for client initialization, node registration, silo creation, encryption,
   consent, audit, and vertical templates

2. **API Reference** — Complete method signatures, parameters, return types,
   and examples for all 6 SDK modules:
   - BedrockClient (entry point + verify_integrity)
   - IdentityModule (register_node, issue/revoke_certificate, create_scope, baseline_attestation)
   - EncryptionModule (encrypt, decrypt, send/receive_e2ee, rotate_keys)
   - DataModule (create_silo, request/approve/revoke_consent, anonymous IDs)
   - AuditModule (log, verify, query, export)
   - AccessModule (create_user, start/end_session, verify_mfa, check_permission)
   - TransportModule (configure_tls, check_downgrade, add_neighbor, flag_node, rate_limit)

3. **Tutorials** — Step-by-step guides for each vertical:
   - Healthcare: PIR consent, PHI/PII separation, HIPAA compliance report
   - Banking: PAN isolation, PCI-DSS consent flows, compliance report
   - Investment: Trade execution (5-min TTL), SEC/FINRA compliance
   - Defense: Clearance-gated access, CUI management, CMMC/DFARS compliance

4. **Configuration Guide** — Complete CoreConfig reference with:
   - Per-option descriptions and defaults
   - Vertical template defaults comparison table
   - Compliance mapping (which regulation requires which setting)

Files:
- `docs/developer-portal/quick-start.md`
- `docs/developer-portal/api-reference.md`
- `docs/developer-portal/configuration.md`
- `docs/developer-portal/tutorials/healthcare-tutorial.md`
- `docs/developer-portal/tutorials/banking-tutorial.md`
- `docs/developer-portal/tutorials/investment-tutorial.md`

---

## B-306: Compliance Kits

**Status:** Complete

Regulation-to-enforcement mapping documents for 5 compliance frameworks:

1. **HIPAA Compliance Kit** (45 CFR 160/164) — Maps Privacy Rule, Security Rule,
   and Breach Notification Rule to Bedrock enforcement. 30+ requirement-to-module
   mappings covering access control, encryption, audit, integrity, authentication,
   and transmission security.

2. **PCI-DSS v4.0 Compliance Kit** — Maps all 12 PCI-DSS requirements to Bedrock
   enforcement. PAN isolation architecture diagram, minimum-necessary role matrix,
   key management mapping, and audit trail requirements table.

3. **SOC 2 Type II Compliance Kit** — Maps all 5 Trust Services Criteria (CC6-CC10)
   to Bedrock modules. Includes evidence collection guidance and automated
   evidence generation code.

4. **GLBA Compliance Kit** (15 USC 6801-6809) — Maps Privacy Rule and Safeguards
   Rule to Bedrock enforcement. NPI isolation architecture for Banking and
   Investment templates.

5. **DFARS/CMMC/NIST 800-171 Compliance Kit** — Maps DFARS 252.204-7012
   (7012(b)(c)(d)), CMMC Level 2 practices (AC, AU, CM, IA, MP, SC), and
   NIST 800-171 controls (3.1, 3.3, 3.5, 3.10, 3.13) to Bedrock enforcement.
   Includes clearance-gated consent flow table and 5-level clearance hierarchy.

All kits include:
- Module-level enforcement mapping tables
- Cross-reference between regulations
- Evidence collection guidance
- Quick reference: regulatory coverage matrix

Files:
- `docs/compliance/README.md`
- `docs/compliance/hipaa-compliance-kit.md`
- `docs/compliance/pci-dss-compliance-kit.md`
- `docs/compliance/soc2-compliance-kit.md`
- `docs/compliance/glba-compliance-kit.md`
- `docs/compliance/dfars-cmmc-compliance-kit.md`

---

## B-308: Licensing & Enforcement System

**Status:** Complete

Offline-validated, CA-enforced two-tier licensing system. The Identity Fabric CA will not
issue certificates beyond the licensed node count — enforcement is architectural, not DRM.

### Architecture

License keys are HMAC-SHA256 signed payloads validated entirely offline. No phone-home.
Format: `1:<base64url(payload)>:<base64url(hmac-sha256)>`

### Two-Tier Model

| Tier | Price | Max Nodes | Certs | Mode |
|------|-------|-----------|-------|------|
| Developer | $99/yr (indiv), $499/yr (team of 5) | 3 | Self-signed, localhost only | Dev |
| Starter | $5K/yr | 5 | CA-signed, production | Runtime |
| Business | $20K/yr | 25 | CA-signed, production | Runtime |
| Enterprise | Custom | Unlimited | CA-signed, air-gap capable | Runtime |

### Feature Matrix

- **Developer:** self_signed_certs, localhost_only, max_3_nodes, audit_export, basic_mesh
- **Starter:** + ca_signed_certs, production_deployment, self_healing_mesh, compliance_reports
- **Business:** + custom_certificates, priority_support, max_25_nodes
- **Enterprise:** + custom_ca, air_gap_support, dedicated_support, unlimited_nodes

### Key Components

- `LicenseEnforcer`: validate_license(), generate_license_key(), can_issue_certificate(),
  enforce_developer_mode(), validate_feature_access(), get_upgrade_path()
- `License` dataclass: tier, max_nodes, max_devs, dev_mode, features, expiration
- `LicenseValidationError`, `LicenseExpiredError`, `LicenseLimitError` exceptions
- Integration with `CertificateManager`: license-enforced node limits during certificate issuance

### Security

- HMAC-SHA256 signature verification prevents key tampering
- Tampered payload or signature raises `LicenseValidationError`
- Expired keys raise `LicenseExpiredError`
- Developer mode enforced architecturally: self-signed certs, localhost-only, no production

### Test Coverage

65 tests across 8 test classes:
- License key generation (9 tests)
- License validation (8 tests)
- Invalid license handling (7 tests) — tampering, corruption, wrong version
- License expiration (5 tests) — expired, perpetual, days-until
- License enforcement (8 tests) — node limits, developer restrictions
- Feature access (6 tests) — tier-specific feature gating
- Tier info and pricing (7 tests)
- Upgrade paths (5 tests)
- File validation (2 tests)
- License properties (4 tests)
- Certificate integration (5 tests) — cross-module enforcement

Files:
- `core/bedrock/licensing/enforcement.py` (382 lines)
- `core/bedrock/licensing/__init__.py`
- `tests/test_licensing.py` (694 lines, 65 tests)

---

## B-307: InFill Adapter on Bedrock Core

**Status:** Complete

Re-implementation of InFill's domain concepts as a Bedrock integration layer,
mapping InFill operations to Bedrock core modules:

### Architecture
- Patient → NodeRegistry node + CertificateManager certificate
- Intake data → FieldEncryptor per-field encryption in medical silo
- PIR → ConsentGate consent flow (identity → medical)
- ePRR → ConsentGate consent flow (medical → identity)
- E2EE messaging → FieldEncryptor encrypt/decrypt for subject + body
- Audit → AuditChain SHA-256 hash chain with action, actor_id, target_id, silo

### API Mapping (InFill → Bedrock)
- `register_patient()` → `NodeRegistry.register()` + `CertificateManager.issue_certificate()` + `FieldEncryptor.encrypt()` per-field
- `create_intake()` → `FieldEncryptor.encrypt()` for medical silo storage
- `submit_intake()` → `FieldEncryptor.encrypt()` for responses
- `create_pir()` → `ConsentGate.request_consent()` with patient as data_owner
- `approve_pir()` → `ConsentGate.approve_consent()` with data_owner_id
- `deny_pir()` → `ConsentGate.deny_consent()` with data_owner_id
- `create_eprr()` → `ConsentGate.request_consent()` for medical data release
- `release_eprr()` → `ConsentGate.approve_consent()` + release token
- `send_message()` → `FieldEncryptor.encrypt()` for subject + body
- `decrypt_message()` → `FieldEncryptor.decrypt()` for subject + body
- `get_audit_trail()` → `AuditChain.query()`
- `verify_integrity()` → `AuditChain.verify()`

### Test Coverage (51 tests)
- Patient registration (6) — basic, PII, provider, node ID, certificate, multiple
- Patient lookup (5) — by UUID, not found, by name, by email, not found
- Data encryption (4) — decrypt identity, decrypt PII, nonexistent, no PII
- Intake management (5) — create, submit, not found, get, get not found
- PIR (6) — create, approve, deny, not found × 2, categories
- ePRR (4) — create, release, not found, categories
- E2EE messaging (3) — send, custom TTL, decrypt roundtrip
- Audit trail (6) — registration, intake, PIR, PIR approval, message, integrity
- Silo integration (6) — 3 silos initialized, categories × 3, encrypted storage, PII separate
- Domain models (6) — enum values, default values

Files:
- `integrations/infill/adapter.py` (683 lines)
- `integrations/infill/test_adapter.py` (381 lines, 51 tests)
- `integrations/infill/__init__.py`

---

## B-310: TypeScript SDK Expansion

**Status:** Complete

Expanded the Bedrock TypeScript SDK from 68 to 122 tests with new modules and
deeper coverage:

New modules:
1. **LicensingModule** — Two-tier license enforcement (Developer/Starter/Business/Enterprise/Custom),
   offline validation, feature gating, node limits, upgrade/revoke lifecycle
2. **SiloModule** — Data separation silo management: create, store, retrieve, query,
   delete-record (right to be forgotten), drop silo, entry counts

Expanded existing modules:
3. **IdentityModule** — Attestation support: policy setting, claim submission,
   verification, node listing, state transitions, capability scope checking
4. **EncryptionModule** — Batch encrypt/decrypt, silo-specific key derivation,
   key version tracking/history, rotation clears derived keys
5. **DataModule** — Consent deny flow, consent expiry, list by status,
   anonymous ID silo binding, resolve count tracking, identity removal cleanup

Bug fixes:
- Fixed `transport.ts` Map iteration for TS strict mode
- Fixed `encryption.ts` BufferSource compatibility for Web Crypto API
- Fixed all TS strict mode warnings (unused params, imports)

Files:
- `sdk-ts/src/licensing.ts` (227 lines, 13 tests)
- `sdk-ts/src/silo.ts` (182 lines, 13 tests)
- `sdk-ts/src/identity.ts` (expanded, 11 tests)
- `sdk-ts/src/encryption.ts` (expanded, 7 tests)
- `sdk-ts/src/data.ts` (expanded, 10 tests)
- `sdk-ts/src/transport.ts` (bug fixes)
- `sdk-ts/src/client.ts` (cleaned imports)
- `sdk-ts/src/index.ts` (updated exports)
- `sdk-ts/tests/expanded.test.ts` (54 new integration tests)
- `tests/test_licensing.py` (583 lines, 65 tests)
- `docs/developer-portal/tutorials/defense-tutorial.md`

**Test count:** 660 total (538 Python + 122 TypeScript), all passing.

---

## B-311: End-to-End Integration Tests

**Status:** Complete

17 E2E integration tests covering the full patient journey through Bedrock Core:

1. **test_complete_patient_journey** — Registration → certificate → silo → PIR consent → ePRR → E2EE delivery → audit trail
2. **test_provider_rbac_journey** — RBAC role assignment, MFA-protected write access, real TOTP code generation
3. **test_mesh_self_healing_journey** — Node registration, flagging, healing cycle through mesh states
4. **test_consent_lifecycle_journey** — Request → approve → verify → deny → expiry full consent flow
5. **test_developer_tier_limits** — Developer tier: 3 nodes, self-signed certs, feature gating
6. **test_business_tier_limits** — Business tier: 25 nodes, CA-signed certs, runtime features
7. **test_license_expiry** — Expired license raises `LicenseExpiredError`
8. **test_feature_access** — Feature validation: developer has `self_signed_certs` but not `ca_signed_certs`
9. **test_certificate_issuance_by_tier** — Certificate issuance respects tier capabilities
10. **test_cross_silo_encryption_with_consent** — Cross-silo field encryption requires consent
11. **test_key_rotation_preserves_audit_integrity** — Key rotation doesn't break audit chain
12. **test_batch_encryption_workflow** — Batch encrypt/decrypt across multiple fields
13. **test_full_audit_lifecycle** — Append → verify → query → export cycle
14. **test_audit_tamper_detection** — Tampered entries detected on verify
15. **test_audit_export_and_reimport** — Audit chain export/reimport round-trip
16. **test_e2ee_provider_to_patient** — E2EE message from provider to patient with key exchange
17. **test_e2ee_cross_silo_fails** — Cross-silo E2EE correctly fails without consent

Bug fixes in core code:
- **LicenseEnforcer enum identity under pytest** — `TIER_FEATURES`, `NODE_LIMITS`, `TIER_PRICING` dict lookups now use `.get()` with string-key fallbacks. Under pytest's module isolation, enum identity can differ from the module-level dict keys; string-key fallbacks ensure robust lookups in all contexts.

Files:
- `tests/test_e2e_patient_journey.py` (644 lines, 17 tests)
- `core/bedrock/licensing/enforcement.py` (enum identity robustness fix)

**Test count:** 660 total (538 Python + 122 TypeScript), all passing.

---

## B-312: Key Rotation Implementation

**Status:** Complete

Implemented master key rotation lifecycle with grace periods, emergency revocation,
re-encryption, and audit trail.

New module: `bedrock.key_management.rotation`

Classes:
1. **RotationPolicy** — Configurable rotation schedule:
   - `rotation_interval_days` (default 90): automatic rotation interval
   - `grace_period_days` (default 30): old keys stay decryptable
   - `emergency_grace_days` (default 7): shorter grace after emergency rotation
   - `max_grace_keys` (default 3): max simultaneous grace-period keys
   - `auto_rotate` (default True): enable scheduled rotation

2. **KeyRotationManager** — Master key rotation lifecycle:
   - `rotate_master_key(trigger, new_key)`: generate or accept new master key, move old to grace
   - `revoke_key(key_id)`: emergency revocation, destroys key material immediately
   - `re_encrypt_field(field_encryptor, ciphertext, ...)`: migrate data to new key
     - With explicit `old_master_key`: direct decrypt/re-encrypt
     - Without: tries all grace keys automatically
   - `is_rotation_due()`: check if scheduled rotation is overdue
   - `get_grace_keys()`: list keys available for decryption
   - `retire_expired_keys()`: auto-retire grace keys past their period
   - `get_rotation_history()`: full audit log of every rotation event
   - `get_key_records()`: lifecycle records (ACTIVE -> GRACE -> RETIRED/REVOKED)

3. **RotationTrigger** — Why a rotation happened: SCHEDULED, MANUAL, EMERGENCY, COMPLIANCE

4. **KeyState** — Lifecycle states: ACTIVE, GRACE, RETIRED, REVOKED

5. **MasterKeyRecord** — Per-key metadata: key_id, version, state, timestamps, trigger, predecessor

Key design decisions:
- Lazy import for `FieldEncryptor` to avoid circular dependency (encryption.engine <-> key_management.rotation)
- Grace keys stored in memory (not persisted) — production would use HSM/vault
- Re-encryption supports both explicit old key and automatic grace-key discovery
- Silo key cache is cleared on master key rotation (all derived keys must be re-derived)

Tests (30 new):
- RotationPolicy defaults and custom config (2)
- Master key rotation: new key generation, grace period, cache clearing, max limit (6)
- Emergency/compliance rotation triggers (3)
- Key revocation and active key protection (2)
- Grace period expiry and decryptability (2)
- Re-encryption: single field, data preservation, multi-rotation, grace-key-only (4)
- Scheduled rotation: due check, disabled, interval elapsed, audit log (4)
- Key lifecycle records: initial, multi-rotation, predecessor chain, state transitions (4)
- Silo key rotation: independent of master, cache invalidation, cross-key derivation (3)

Files:
- `core/bedrock/key_management/rotation.py` (438 lines, new module)
- `core/bedrock/key_management/__init__.py` (updated exports)
- `tests/test_key_rotation.py` (357 lines, 30 tests)

**Test count:** 690 total (568 Python + 122 TypeScript), all passing.

---

## B-313: Performance/Load Testing

**Status:** Complete

Created comprehensive performance benchmark suite establishing baseline throughput
and latency numbers for all critical-path Bedrock Core operations.

Also fixed enum identity robustness in `certificates.py` — `NODE_LIMITS` dict now
has string-key fallbacks and bracket lookups use `.get()` with `.value` fallback,
matching the fix pattern from B-311's `enforcement.py`.

Test suites (19 tests across 8 classes):

1. **TestEncryptionPerformance** (4 tests):
   - Encrypt throughput: 500 ops, min 100 ops/s, P99 < 100ms
   - Decrypt throughput: 500 ops, min 100 ops/s, P99 < 100ms
   - Encrypt-decrypt roundtrip: 500 ops, min 50 ops/s
   - Multi-silo: 10 silos x 200 ops each, avg < 5s per silo

2. **TestKeyDerivationPerformance** (2 tests):
   - Silo key derivation: 100 unique keys, min 50 ops/s
   - Cached silo key derivation: 1000 ops, min 500 ops/s

3. **TestConsentPerformance** (2 tests):
   - Consent request creation: 200 ops, min 50 ops/s
   - Consent approval: 200 ops, min 50 ops/s

4. **TestAuditPerformance** (3 tests):
   - Audit append: 500 ops, min 100 ops/s
   - Audit verify under load: verify after 1000 appends, mean < 500ms
   - Audit query: 200 queries against 500 entries, min 50 ops/s

5. **TestLicensingPerformance** (2 tests):
   - License generation: 200 ops, min 50 ops/s
   - License validation: 500 ops, min 100 ops/s

6. **TestNodeRegistrationPerformance** (2 tests):
   - Bulk registration: 100 nodes in < 2s
   - Certificate issuance: 100 certs (enterprise tier), min 10 ops/s

7. **TestKeyRotationPerformance** (2 tests):
   - Master key rotation: 20 rotations, min 5 ops/s
   - Re-encryption: 100 fields, < 5s total

8. **TestE2EEPerformance** (1 test):
   - E2EE encrypt-decrypt roundtrip: 100 ops, min 10 ops/s

9. **TestConcurrentOperations** (1 test):
   - Mixed workload: 100 ops (encrypt, consent, audit, license), < 10s
   - Verifies audit chain integrity after load

Files:
- `tests/test_performance.py` (408 lines, 19 tests)
- `core/bedrock/identity/certificates.py` (NODE_LIMITS enum robustness fix)

**Test count:** 709 total (587 Python + 122 TypeScript), all passing.

---

## B-314: Deployment Configuration

**Status:** Complete

Created deployment infrastructure for containerized Bedrock Core:

1. **Dockerfile** (`deploy/Dockerfile`):
   - Python 3.14-slim base image
   - Non-root `bedrock` user for security
   - Layer-cached pip install
   - Health check via CoreConfig.from_env()
   - Runtime directories for audit, config, logs
   - Production defaults (BEDROCK_ENV=production, DEV_MODE=false)

2. **Docker Compose** (`deploy/docker-compose.yml`):
   - `bedrock-core` service with mounted volumes and Docker secrets
   - `bedrock-test` service (profiles: test) for CI containerized testing
   - Secret management for master key
   - Named volumes for audit and config persistence

3. **Environment config** (`deploy/.env.example`):
   - All BEDROCK_* environment variables documented
   - Sensible dev defaults, production hardening notes
   - Telemetry explicitly disabled by default (no phone-home)

4. **CI/CD pipeline** (`.github/workflows/ci.yml`):
   - Multi-version Python test matrix (3.12, 3.13, 3.14)
   - TypeScript SDK tests with coverage
   - Bandit security scan + Safety dependency check
   - Docker image build verification
   - Coverage artifact upload

5. **Health check module** (`core/bedrock/health.py`):
   - `HealthChecker` validates encryption, identity, audit, licensing
   - `HealthReport` with per-component latency, status, and serialization
   - Used by Docker HEALTHCHECK and orchestration probes

6. **Requirements** (`requirements.txt`):
   - cryptography>=43.0.0, pytest, pytest-cov, pytest-asyncio

7. **`.gitignore`** update: `.env.example` no longer excluded (was caught by `.env.*`)

Files:
- `deploy/Dockerfile` (new)
- `deploy/docker-compose.yml` (new)
- `deploy/.env.example` (new)
- `.github/workflows/ci.yml` (new)
- `core/bedrock/health.py` (new, 153 lines)
- `requirements.txt` (new)
- `tests/test_health.py` (new, 5 tests)
- `.gitignore` (updated)

**Test count:** 714 total (592 Python + 122 TypeScript), all passing.

---

## B-315: InFill Portal Frontend — Bedrock Core API Server

**Status:** Complete

Built the general-purpose Bedrock Core REST API server — the integration layer
that any licensed developer (InFill, banking, insurance, defense) uses to build
their application on Bedrock. This is NOT an InFill-specific API; it exposes
Bedrock's core primitives (nodes, silos, consent, encryption, audit) so any
downstream product can build on top.

Revenue model alignment: Developer license holders build against this API,
then must upgrade to Production Runtime for per-node CA-enforced deployment.

API Server (`core/bedrock/server.py`):

Endpoints (all under /api/v1/, Bearer token auth required):
- Health: GET /health (no auth), GET /health/detailed (auth)
- Identity: POST /nodes, GET /nodes, GET /nodes/{id}
- Certificates: POST /certificates, DELETE /certificates/{node_id}
- Data Separation: POST /silos, GET /silos
- Consent: POST /consent, PUT /consent/{id}/approve, PUT /consent/{id}/deny
- Encryption: POST /encrypt, POST /decrypt (501 — key vault integration needed)
- Audit: GET /audit, GET /audit/verify
- Licensing: POST /license/validate

Security model:
- Bearer token authentication on all /api/v1/ endpoints
- /health is public (for load balancers and orchestration probes)
- Rate limiting enforced per-tier (developer vs business vs enterprise)
- No data leaves encrypted silos without consent verification
- Audit trail logging on every mutation

Test coverage (14 tests):
- Health endpoints with and without auth
- Authentication enforcement (401 for missing/invalid keys)
- Node registration and certificate issuance
- Silo creation and listing
- Consent request flow
- License validation
- Audit verification
- Error handling (404, 400)

Files:
- `core/bedrock/server.py` (521 lines, new — HTTP API server)
- `tests/test_api_server.py` (252 lines, 14 tests)

**Test count:** 728 total (606 Python + 122 TypeScript), all passing.

---

## B-316: Self-Healing Mesh Integration

**Status:** Complete

The Self-Healing Mesh (detector, state machine, router, healing orchestrator) existed
as standalone modules. This build creates `MeshIntegrator` — the layer that wires mesh
state changes into Bedrock's other subsystems so that quarantined/revoked nodes are
actually blocked from accessing protected resources.

Key insight: `AuditChain.__len__` returns 0 when empty, making `bool(chain)` falsy.
All subsystem checks in MeshIntegrator use `is not None` instead of truthy checks.

MeshIntegrator coordinates:
- **Quarantine**: revoke certificates (CertificateManager), log audit event,
  track node as blocked
- **Revocation**: all quarantine actions + mark keys compromised (KeyManager),
  permanent removal from routing
- **Healing**: re-issue certificates, clear audit event, untrack node

Full lifecycle flows:
- `process_full_quarantine()` — flags -> consensus -> quarantine -> integrate
- `process_full_revocation()` — quarantine -> revoke -> integrate
- `process_full_healing()` — begin -> complete -> integrate (handles already-healing nodes)

Access control integration:
- `is_node_blocked()` — used by AccessController and ConsentGate to deny access
- `is_node_revoked()` — permanent block check
- `get_blocked_nodes()` — returns all quarantined + revoked IDs

Bug fix: `AuditChain` evaluates falsy when empty (len=0). Changed all
subsystem presence checks from truthy (`if self.audit_chain:`) to explicit
(`if self.audit_chain is not None:`).

Files:
- `core/bedrock/mesh/integration.py` (345 lines, new — MeshIntegrator, MeshEvent)
- `core/bedrock/mesh/__init__.py` (updated exports)
- `tests/test_mesh_integration.py` (310 lines, 23 tests)

**Test count:** 751 total (629 Python + 122 TypeScript), all passing.

---

## B-317: Bedrock Python SDK

**Status:** Complete

Official Python SDK client library for Bedrock Core. Any licensed developer
installs this package and connects to a Bedrock instance with their license key.

Architecture:
- `BedrockClient` — main entry point, config/auth/connection management
- Namespaced sub-clients: `nodes`, `certificates`, `silos`, `consent`,
  `encryption`, `audit`, `mesh`, `license`
- Auth via `Authorization: Bearer <license_key>` header
- Exception hierarchy: BedrockError → AuthenticationError, LicenseError,
  NotFoundError, ValidationError, QuotaExceededError, MeshError

Sub-client methods:
- `_NodeClient`: register, list, get
- `_CertificateClient`: issue, revoke, check
- `_SiloClient`: create, list
- `_ConsentClient`: request, approve, deny
- `_EncryptionClient`: encrypt, decrypt
- `_AuditClient`: query, verify
- `_MeshClient`: get_state, flag, heal
- `_LicenseClient`: validate, features

Package structure (sdk-python/):
- `bedrock_sdk/__init__.py` — exports, version 1.0.0
- `bedrock_sdk/client.py` — BedrockClient + all sub-clients
- `bedrock_sdk/exceptions.py` — exception hierarchy
- `pyproject.toml` — build config, Python 3.11+
- `tests/test_sdk_client.py` — 20 tests (structural + integration against live server)

Key design decisions:
- License key sent as Bearer token (matches server auth)
- Standard library only (no requests dependency) — urllib.request
- License validate uses POST (server endpoint requires body with license_key)
- SDK tests spin up real HTTP server via create_server()

**Test count:** 771 total (629 Python + 20 SDK + 122 TypeScript), all passing.