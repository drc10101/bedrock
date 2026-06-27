# Bedrock SDK — Quick Start Guide

**Bedrock** is a two-tier licensed security framework where every node is a user identity and everything between is encrypted at rest. This guide gets you running in 5 minutes.

---

## Installation

```bash
pip install bedrock-sdk
```

For TypeScript:

```bash
npm install @bedrock/sdk
```

---

## Initialize the Client

```python
from bedrock_sdk import BedrockClient

# Developer mode: 3 local nodes, self-signed certificates
client = BedrockClient(mode="developer")

# Production mode: CA-signed certificates, full enforcement
client = BedrockClient(mode="production", license_key="BED-XXXX-XXXX")
```

```typescript
import { BedrockClient } from "@bedrock/sdk";

// Developer mode
const client = new BedrockClient({ mode: "developer" });

// Production mode
const client = new BedrockClient({
  mode: "production",
  licenseKey: "BED-XXXX-XXXX",
});
```

---

## Register a Node

Every participant in the system is a **node** — a unique identity with certificates, capabilities, and a mesh address.

```python
# Register a healthcare provider
node = client.identity.register_node(
    name="dr-smith",
    role="provider",
    portal="patient",  # which portal they log in through
)

print(f"Node ID: {node.id}")
print(f"State: {node.state}")  # NodeState.ACTIVE
```

```typescript
const node = await client.identity.registerNode({
  name: "dr-smith",
  role: "provider",
  portal: "patient",
});

console.log(`Node ID: ${node.id}`);
console.log(`State: ${node.state}`); // "active"
```

---

## Create Silos (Data Isolation)

Silos are encrypted data compartments. Data in one silo cannot be read by another without explicit consent.

```python
# Create a medical records silo
medical = client.data.create_silo(
    name="medical",
    display_name="Medical Records",
    categories=["diagnosis", "prescriptions", "lab_results", "vitals"],
    description="Protected Health Information (PHI) silo",
)

# Create an identity silo (separate from medical)
identity = client.data.create_silo(
    name="identity",
    display_name="Patient Identity",
    categories=["demographics", "contact", "ssn", "insurance"],
    description="PII silo — never mixed with PHI",
)
```

```typescript
const medical = client.data.createSilo({
  name: "medical",
  displayName: "Medical Records",
  categories: ["diagnosis", "prescriptions", "lab_results", "vitals"],
  description: "Protected Health Information (PHI) silo",
});

const identity = client.data.createSilo({
  name: "identity",
  displayName: "Patient Identity",
  categories: ["demographics", "contact", "ssn", "insurance"],
  description: "PII silo — never mixed with PHI",
});
```

---

## Encrypt and Decrypt Data

Field-level encryption with silo-bound AAD (Authenticated Associated Data). Each silo gets its own HKDF-derived key.

```python
# Encrypt a diagnosis in the medical silo
ciphertext = client.encryption.encrypt(
    data="Type 2 Diabetes",
    silo_name="medical",
    context={"patient_id": "P-12345", "action": "diagnosis"},
)

# Decrypt it back
plaintext = client.encryption.decrypt(
    ciphertext=ciphertext,
    silo_name="medical",
    context={"patient_id": "P-12345", "action": "diagnosis"},
)

print(plaintext)  # "Type 2 Diabetes"
```

```typescript
const ciphertext = await client.encryption.encrypt(
  "Type 2 Diabetes",
  "medical",
  { patient_id: "P-12345", action: "diagnosis" }
);

const plaintext = await client.encryption.decrypt(
  ciphertext,
  "medical",
  { patient_id: "P-12345", action: "diagnosis" }
);

console.log(plaintext); // "Type 2 Diabetes"
```

---

## Request Cross-Silo Consent

Cross-silo access requires explicit, auditable consent with a time-to-live.

```python
# Request consent for identity data to flow to medical silo
consent = client.data.request_consent(
    requesting_node_id=node.id,
    source_silo="identity",
    target_silo="medical",
    categories=["demographics", "contact"],
    scope="read",
    reason="Patient intake form requires demographics",
)

print(f"Consent status: {consent.status}")  # ConsentStatus.PENDING

# Approve it
client.data.approve_consent(consent.id)
print(f"Consent status: {consent.status}")  # ConsentStatus.APPROVED
```

```typescript
const consent = client.data.requestConsent({
  requestingNodeId: node.id,
  sourceSilo: "identity",
  targetSilo: "medical",
  categories: ["demographics", "contact"],
  scope: "read",
  reason: "Patient intake form requires demographics",
});

console.log(`Consent status: ${consent.status}`); // "pending"

client.data.approveConsent(consent.id);
console.log(`Consent status: ${consent.status}`); // "approved"
```

---

## Audit Logging

Every action is logged to a tamper-evident SHA-256 hash chain.

```python
# Log a data access event
event_id = client.audit.log(
    action="data.read",
    actor_id=node.id,
    target_id="patient-12345",
    silo="medical",
    details={"categories": ["diagnosis"], "consent_id": consent.id},
)

# Verify the entire audit chain
is_valid = client.verify_integrity()
print(f"Audit chain valid: {is_valid}")  # True

# Query audit events
events = client.audit.query(action="data.read", limit=10)
for event in events:
    print(f"  {event.action} by {event.actor_id} on {event.timestamp}")
```

```typescript
const eventId = await client.audit.log(
  "data.read",
  node.id,
  "patient-12345",
  "medical",
  { categories: ["diagnosis"], consentId: consent.id }
);

const isValid = await client.audit.verify();
console.log(`Audit chain valid: ${isValid}`); // true

const events = client.audit.query({ action: "data.read", limit: 10 });
events.forEach(e => {
  console.log(`  ${e.action} by ${e.actorId} on ${e.timestamp}`);
});
```

---

## Access Control (RBAC + MFA)

```python
# Create a user with a role
user_id = client.access.create_user(
    username="dr-smith",
    password="secure-password-here",
    role="provider",
)

# Start a session with MFA
session = client.access.start_session(
    user_id=user_id,
    password="secure-password-here",
)

# MFA verification
mfa_ok = client.access.verify_mfa(
    user_id=user_id,
    code="123456",  # TOTP code
)
print(f"MFA verified: {mfa_ok}")

# Check permissions
has_perm = client.access.check_permission(
    user_id=user_id,
    permission="data.read",
)
```

---

## Self-Healing Mesh

```python
# Add a neighbor to the mesh
client.transport.add_neighbor(
    node_id="node-abc",
    endpoint="https://mesh.example.com:8443",
)

# Flag a suspicious node
client.transport.flag_node(
    node_id="node-suspicious",
    signal_type="brute_force",
    reporter_id=node.id,
)

# Check healing state
state = client.transport.get_healing_state(node_id="node-suspicious")
print(f"Healing state: {state}")
```

---

## Using Vertical Templates

Templates give you pre-configured silos, consent flows, and compliance mappings for specific industries.

```python
from templates.healthcare import HealthcareTemplate

# Create a healthcare-ready Bedrock instance
template = HealthcareTemplate(mode="developer")
config = template.get_config()
client = BedrockClient(config=config)

# Create all 3 healthcare silos at once
silos = template.create_silos(client.data._silo_manager)

# Start a PIR consent flow (Patient Information Request)
consent = template.request_pir(
    patient_id="P-12345",
    reason="Annual physical requires medical history review",
)

# Generate a HIPAA compliance report
report = template.hipaa_compliance_report()
for section, mapping in report["mappings"]["hipaa"].items():
    print(f"  {section}: {mapping['enforcement']}")
```

Available templates:
- **HealthcareTemplate** — HIPAA 45 CFR 160/164, PIR/ePRR consent flows
- **BankingTemplate** — PCI-DSS v4.0, PAN isolation, 3-attempt lockout
- **InvestmentTemplate** — SEC/FINRA, 5-min trade TTL, 6-year audit retention
- **DefenseTemplate** — CMMC Level 2, DFARS 252.204-7012, clearance-gated access

---

## What's Next

- [API Reference](./api-reference.md) — Full method signatures and parameters
- [Tutorials](./tutorials/) — Step-by-step guides for common patterns
- [Compliance Kits](../compliance/) — Regulation-to-enforcement mapping docs
- [Configuration Guide](./configuration.md) — CoreConfig options explained