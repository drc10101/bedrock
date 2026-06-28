# Bedrock SDK — API Reference

Complete method reference for the Bedrock Python SDK and TypeScript SDK.

---

## BedrockClient

The central entry point. Wraps all modules with developer-friendly defaults.

### Constructor

```python
BedrockClient(mode="developer", config=None, license_key="")
```

```typescript
new BedrockClient({ mode?: "developer" | "production", config?: CoreConfig, licenseKey?: string })
```

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `mode` | `str` | `"developer"` | `"developer"` (3 nodes, self-signed) or `"production"` (CA-signed, full enforcement) |
| `config` | `CoreConfig` | `None` | Advanced configuration. If provided, `mode` is derived from `config.licensing.tier` |
| `license_key` | `str` | `""` | Production license key |

### Properties

| Property | Type | Description |
|----------|------|-------------|
| `mode` | `str` | Current operating mode |
| `identity` | `IdentityModule` | Node registration, certificates, capability scoping |
| `encryption` | `EncryptionModule` | Field-level encrypt/decrypt, E2EE delivery, key management |
| `data` | `DataModule` | Silo config, consent-gated access, anonymous IDs |
| `audit` | `AuditModule` | Write events, verify integrity, export for compliance |
| `access` | `AccessModule` | RBAC, sessions, MFA |
| `transport` | `TransportModule` | TLS config, E2EE messaging, mesh networking |

### Methods

#### `verify_integrity() -> bool`

Verify the entire audit chain integrity. Returns `True` if all SHA-256 chain hashes are valid and unmodified.

```python
is_valid = client.verify_integrity()
```

---

## IdentityModule

Node registration, certificate lifecycle, capability scoping, and attestation.

### Methods

#### `register_node(name, role, portal) -> Node`

Register a new node in the identity mesh.

```python
node = client.identity.register_node(
    name="dr-smith",
    role="provider",      # Role string: "provider", "admin", "partner", etc.
    portal="patient",      # Portal: "patient", "provider", "admin", "partner"
)
```

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `name` | `str` | required | Human-readable node name |
| `role` | `str` | `"viewer"` | Role for RBAC |
| `portal` | `str` | `"patient"` | Which portal the node logs in through |

Returns: `Node` object with `.id`, `.state`, `.name`

#### `issue_certificate(node_id, scope) -> Certificate`

Issue a certificate for a node, scoping its capabilities.

```python
cert = client.identity.issue_certificate(
    node_id=node.id,
    scope=CapabilityScope(
        categories=[DataCategory.DEMOGRAPHICS, DataCategory.CONTACT],
        silo_names=["identity", "medical"],
    ),
)
```

| Parameter | Type | Description |
|-----------|------|-------------|
| `node_id` | `str` | The node ID to issue a certificate for |
| `scope` | `CapabilityScope` | What data categories and silos the node can access |

Returns: `Certificate` with `.id`, `.status`, `.scope`

#### `revoke_certificate(cert_id) -> bool`

Revoke a certificate. The node loses all scoped access.

```python
success = client.identity.revoke_certificate(cert_id=cert.id)
```

#### `create_scope(categories, silo_names) -> CapabilityScope`

Create a capability scope for certificate issuance.

```python
scope = client.identity.create_scope(
    categories=[DataCategory.DEMOGRAPHICS, DataCategory.CONTACT],
    silo_names=["identity", "medical"],
)
```

#### `baseline_attestation(node_id) -> bool`

Create an attestation baseline for a node. Used for tamper detection.

```python
client.identity.baseline_attestation(node_id=node.id)
```

---

## EncryptionModule

Field-level encryption with silo-bound AAD, E2EE message delivery, and key management.

### Methods

#### `encrypt(data, silo_name, context) -> str`

Encrypt data bound to a specific silo with authenticated associated data (AAD).

```python
ciphertext = client.encryption.encrypt(
    data="Type 2 Diabetes",
    silo_name="medical",
    context={"patient_id": "P-12345", "action": "diagnosis"},
)
```

| Parameter | Type | Description |
|-----------|------|-------------|
| `data` | `str` | Plaintext to encrypt |
| `silo_name` | `str` | Target silo name (determines HKDF key) |
| `context` | `dict` | AAD context for authenticated encryption |

Returns: Base64-encoded ciphertext string

#### `decrypt(ciphertext, silo_name, context) -> str`

Decrypt data that was encrypted for a specific silo.

```python
plaintext = client.encryption.decrypt(
    ciphertext=ciphertext,
    silo_name="medical",
    context={"patient_id": "P-12345", "action": "diagnosis"},
)
```

| Parameter | Type | Description |
|-----------|------|-------------|
| `ciphertext` | `str` | Base64-encoded ciphertext |
| `silo_name` | `str` | Silo the data was encrypted for |
| `context` | `dict` | Must match the encryption context exactly |

Returns: Decrypted plaintext string

Raises: `AADMismatchError` if context does not match

#### `send_e2ee(sender_id, recipient_id, message) -> str`

Send an end-to-end encrypted message between two nodes.

```python
encrypted_msg = client.encryption.send_e2ee(
    sender_id="node-alpha",
    recipient_id="node-beta",
    message="Confidential treatment plan",
)
```

#### `receive_e2ee(encrypted_message, recipient_id) -> str`

Receive and decrypt an E2EE message.

```python
plaintext = client.encryption.receive_e2ee(
    encrypted_message=encrypted_msg,
    recipient_id="node-beta",
)
```

#### `rotate_keys() -> str`

Rotate the master encryption key. Returns the new key ID.

```python
new_key_id = client.encryption.rotate_keys()
```

---

## DataModule

Silo configuration, cross-silo consent management, and anonymous ID mapping.

### Methods

#### `create_silo(name, display_name, categories, ...) -> Silo`

Create an encrypted data silo with HKDF-derived keys.

```python
silo = client.data.create_silo(
    name="medical",
    display_name="Medical Records",
    categories=["diagnosis", "prescriptions", "lab_results"],
    description="Protected Health Information (PHI) silo",
)
```

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `name` | `str` | required | Unique silo identifier |
| `display_name` | `str` | required | Human-readable name |
| `categories` | `list[str]` | `[]` | Data categories stored in this silo |
| `description` | `str` | `""` | Description of the silo's purpose |
| `encrypted` | `bool` | `True` | Whether the silo is encrypted at rest |
| `hkdf_info` | `str` | `None` | Custom HKDF info string (default: `bedrock:silo:{name}:v1`) |

#### `request_consent(requesting_node_id, source_silo, target_silo, categories, scope, reason) -> ConsentEvent`

Request cross-silo data access consent.

```python
consent = client.data.request_consent(
    requesting_node_id=node.id,
    source_silo="identity",
    target_silo="medical",
    categories=["demographics", "contact"],
    scope="read",
    reason="Patient intake requires demographics",
)
```

| Parameter | Type | Description |
|-----------|------|-------------|
| `requesting_node_id` | `str` | Node requesting access |
| `source_silo` | `str` | Silo containing the data |
| `target_silo` | `str` | Silo requesting access |
| `categories` | `list[str]` | Specific data categories requested |
| `scope` | `str` | `"read"` or `"write"` |
| `reason` | `str` | Reason for access (required in strict mode) |

Returns: `ConsentEvent` with `.id`, `.status`

#### `approve_consent(consent_id) -> ConsentEvent`

Approve a pending consent request.

```python
client.data.approve_consent(consent_id=consent.id)
```

#### `revoke_consent(consent_id) -> ConsentEvent`

Revoke an approved consent request.

```python
client.data.revoke_consent(consent_id=consent.id)
```

#### `create_anonymous_id(real_id, silo_name) -> str`

Create an anonymous ID mapping (right to be forgotten support).

```python
anon_id = client.data.create_anonymous_id(
    real_id="patient-12345",
    silo_name="medical",
)
```

#### `resolve_anonymous_id(anon_id, silo_name) -> str`

Resolve an anonymous ID back to the real ID.

```python
real_id = client.data.resolve_anonymous_id(
    anon_id=anon_id,
    silo_name="medical",
)
```

#### `forget_id(real_id) -> bool`

Delete all anonymous ID mappings for a real ID (right to be forgotten).

```python
client.data.forget_id(real_id="patient-12345")
```

---

## AuditModule

Tamper-evident SHA-256 hash chain for compliance logging.

### Methods

#### `log(action, actor_id, target_id, silo, details) -> str`

Log an event to the audit chain. Returns the event ID.

```python
event_id = client.audit.log(
    action="data.read",
    actor_id=node.id,
    target_id="patient-12345",
    silo="medical",
    details={"categories": ["diagnosis"]},
)
```

| Parameter | Type | Description |
|-----------|------|-------------|
| `action` | `str` | Action type (e.g., `"data.read"`, `"data.write"`, `"consent.approve"`) |
| `actor_id` | `str` | ID of the node performing the action |
| `target_id` | `str` | ID of the target entity |
| `silo` | `str` | Silo context |
| `details` | `dict` | Optional additional details |

#### `verify() -> bool`

Verify the entire audit chain integrity.

```python
is_valid = client.audit.verify()
```

#### `query(action=None, actor_id=None, silo=None, limit=100) -> list`

Query audit events by action, actor, or silo.

```python
events = client.audit.query(action="data.read", limit=10)
```

#### `export(format="jsonl") -> str`

Export the entire audit chain for compliance review.

```python
export_data = client.audit.export(format="jsonl")
```

---

## AccessModule

Role-based access control, session management, and MFA.

### Methods

#### `create_user(username, password, role) -> str`

Create a user account. Returns user ID.

```python
user_id = client.access.create_user(
    username="dr-smith",
    password="secure-password-here",
    role="provider",
)
```

#### `start_session(user_id, password) -> Session`

Start an authenticated session.

```python
session = client.access.start_session(
    user_id=user_id,
    password="secure-password-here",
)
```

#### `end_session(user_id) -> bool`

End an active session.

```python
client.access.end_session(user_id=user_id)
```

#### `verify_mfa(user_id, code) -> bool`

Verify a TOTP MFA code.

```python
is_valid = client.access.verify_mfa(
    user_id=user_id,
    code="123456",
)
```

#### `check_permission(user_id, permission) -> bool`

Check if a user has a specific permission.

```python
has_access = client.access.check_permission(
    user_id=user_id,
    permission="data.read",
)
```

#### `lock_user(user_id) -> bool`

Lock a user account (e.g., after failed login attempts).

#### `unlock_user(user_id) -> bool`

Unlock a previously locked user account.

---

## TransportModule

TLS configuration, E2EE messaging, mesh networking, and self-healing mesh.

### Methods

#### `configure_tls(min_version="1.3", ...) -> TLSConfig`

Configure TLS settings for secure transport.

```python
tls_config = client.transport.configure_tls(
    min_version="1.3",
    cipher_suites=["AES_256_GCM_SHA384"],
    verify_peer=True,
)
```

#### `check_downgrade() -> DowngradeStatus`

Check for TLS downgrade attacks.

```python
status = client.transport.check_downgrade()
if status != DowngradeStatus.SECURE:
    print("WARNING: TLS downgrade detected!")
```

#### `add_neighbor(node_id, endpoint) -> bool`

Add a mesh neighbor for routing.

```python
client.transport.add_neighbor(
    node_id="node-beta",
    endpoint="https://bedrock.infill.systems",
)
```

#### `flag_node(node_id, signal_type, reporter_id) -> HealingResult`

Flag a node for suspicious behavior. Triggers the self-healing mesh protocol.

```python
result = client.transport.flag_node(
    node_id="node-suspicious",
    signal_type=SignalType.BRUTE_FORCE,
    reporter_id=node.id,
)
print(f"Node state: {result.new_state}")  # "suspect"
```

#### `get_healing_state(node_id) -> str`

Get the current healing state of a node.

```python
state = client.transport.get_healing_state(node_id="node-suspicious")
# Returns: "active", "suspect", "quarantined", "healing", "recovered"
```

#### `rate_limit(node_id, endpoint) -> RateLimitResult`

Check rate limiting for a node/endpoint combination.

```python
result = client.transport.rate_limit(
    node_id="node-alpha",
    endpoint="/api/data",
)
```

---

## Types Reference

### Node

```python
class Node:
    id: str           # Unique node identifier
    name: str         # Human-readable name
    state: NodeState   # "active", "suspended", "revoked"
    role: str         # RBAC role
    portal: str       # Portal assignment
```

### Certificate

```python
class Certificate:
    id: str                # Certificate ID
    node_id: str           # Owning node
    status: CertificateStatus  # "active", "revoked", "expired"
    scope: CapabilityScope # What the node can access
    issued_at: datetime    # Issuance timestamp
    expires_at: datetime   # Expiration timestamp
```

### ConsentEvent

```python
class ConsentEvent:
    id: str                # Consent event ID
    requesting_node_id: str # Node requesting access
    source_silo: str       # Data source silo
    target_silo: str       # Data target silo
    categories: list[str]  # Data categories requested
    scope: str             # "read" or "write"
    status: ConsentStatus  # "pending", "approved", "revoked", "expired"
    reason: str            # Reason for access
    created_at: datetime   # Creation timestamp
    ttl_seconds: int       # Time-to-live in seconds
```

### Silo

```python
class Silo:
    name: str              # Silo identifier
    display_name: str      # Human-readable name
    categories: list[str]  # Data categories in this silo
    encrypted: bool        # Whether encrypted at rest
    hkdf_info: str         # HKDF derivation info
    description: str       # Purpose description
```

### HealingResult

```python
class HealingResult:
    node_id: str           # Affected node ID
    new_state: str         # "active", "suspect", "quarantined", "healing", "recovered"
    consensus: bool        # Whether mesh consensus was reached
    timestamp: datetime    # State change timestamp
```

### SignalType

```python
class SignalType:
    CREDENTIAL_STUFFING = "credential_stuffing"
    PORT_SCAN = "port_scan"
    BRUTE_FORCE = "brute_force"
    PRIVILEGE_ESCALATION = "privilege_escalation"
```

### DataCategory

```python
class DataCategory:
    DEMOGRAPHICS = "demographics"
    CONTACT = "contact"
    SSN = "ssn"
    FINANCIAL = "financial"
    MEDICAL = "medical"
    INSURANCE = "insurance"
    CREDENTIALS = "credentials"
    SESSIONS = "sessions"
    # ... (extensible per vertical)
```

---

## CoreConfig Reference

```python
from bedrock.config import CoreConfig, EncryptionConfig, IdentityConfig, ...

config = CoreConfig(
    environment="production",       # "development" or "production"
    encryption=EncryptionConfig(
        algorithm="aes-256-gcm",   # AES-256-GCM (default)
        key_derivation="hkdf-sha256",  # HKDF-SHA256 (default)
    ),
    data_separation=DataSeparationConfig(
        silo_strict_mode=True,      # Enforce silo boundaries strictly
        consent_default_ttl_seconds=3600,  # 1 hour default consent
        consent_max_ttl_seconds=86400,     # 24 hour max consent
        consent_require_reason=True,  # Require reason for all consent
    ),
    audit=AuditConfig(
        retention_years=7,          # Audit retention period
        chain_export_format="jsonl",  # Export format
    ),
    access_control=AccessControlConfig(
        mfa_required=True,         # Require MFA for all access
        session_ttl_seconds=3600,  # 1 hour session
        session_max_ttl_seconds=28800,  # 8 hours max
        lockout_max_attempts=5,    # Lock after 5 failed attempts
        lockout_duration_seconds=900,  # 15 minute lockout
        rate_limit_enabled=True,
        rate_limit_requests_per_minute=60,
    ),
    licensing=LicensingConfig(
        tier="production",         # "developer" or "production"
        dev_mode=False,            # Allow self-signed certs
    ),
)
```