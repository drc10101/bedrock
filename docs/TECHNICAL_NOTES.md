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
| Core | 25 | Passing |
| **Total** | **233** | **All passing** |

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

## Remaining Work (Phase 1)

| Task | Component | Description |
|------|-----------|-------------|
| B-107 | Identity Fabric — Certificate Lifecycle | X.509 cert issuance, renewal, revocation |
| B-108 | Audit Chain | Tamper-evident SHA-256 hash chain, 6-year retention |
| B-109 | Access Control | RBAC, role-portal mapping, scoped sessions, MFA |
| B-110 | Transport Security | TLS termination, E2EE delivery, rate limiting |
| B-111 | Self-Healing Mesh | Attack detection, node isolation, automatic rerouting |
| B-112 | Core Integration Tests | End-to-end cross-component tests |

---

*Last updated: B-104 complete, 159 tests passing*