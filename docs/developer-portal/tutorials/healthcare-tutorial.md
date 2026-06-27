# Tutorial: Healthcare Application with Bedrock

Build a HIPAA-compliant patient data system using the Healthcare Template.

**What you'll learn:**
- Setting up a Bedrock client with the Healthcare Template
- Creating silos for PHI/PII separation
- Managing PIR (Patient Information Request) consent flows
- Logging HIPAA-compliant audit trails
- Generating a HIPAA compliance report

---

## Prerequisites

```bash
pip install bedrock-sdk
```

---

## Step 1: Initialize with Healthcare Template

```python
from bedrock_sdk import BedrockClient
from templates.healthcare import HealthcareTemplate

# Create a healthcare-configured client
template = HealthcareTemplate(mode="developer")
config = template.get_config()

# Verify HIPAA-specific defaults
print(f"Environment: {config.environment}")           # development
print(f"Audit retention: {config.audit.retention_years} years")  # 7
print(f"MFA required: {config.access_control.mfa_required}")    # True
print(f"Session TTL: {config.access_control.session_ttl_seconds}s")  # 3600

# Initialize client with healthcare config
client = BedrockClient(config=config)
```

---

## Step 2: Create Healthcare Silos

The Healthcare Template provides 3 pre-configured silos:

| Silo | Categories | Purpose |
|------|-----------|---------|
| `identity` | demographics, contact, ssn, insurance | PII — never mixed with PHI |
| `medical` | diagnosis, prescriptions, lab_results, vitals | PHI — isolated from PII |
| `auth` | credentials, sessions, mfa, audit_logs | Authentication — isolated from both |

```python
# Create all healthcare silos at once
silos = template.create_silos(client.data._silo_manager)

for name, silo in silos.items():
    print(f"  {name}: {silo.display_name}")
    print(f"    Categories: {', '.join(silo.categories)}")
    print(f"    Encrypted: {silo.encrypted}")
    print(f"    HKDF: {silo.hkdf_info}")
```

---

## Step 3: Register Healthcare Staff

```python
# Register a provider (doctor)
provider = client.identity.register_node(
    name="dr-jane-smith",
    role="provider",
    portal="provider",
)

# Register a patient
patient = client.identity.register_node(
    name="patient-12345",
    role="patient",
    portal="patient",
)

# Issue certificates with healthcare-scoped capabilities
from bedrock.identity.capabilities import CapabilityScope, DataCategory

provider_scope = client.identity.create_scope(
    categories=[
        DataCategory.DEMOGRAPHICS,
        DataCategory.CONTACT,
        DataCategory.DIAGNOSIS,
        DataCategory.PRESCRIPTIONS,
    ],
    silo_names=["identity", "medical"],
)
provider_cert = client.identity.issue_certificate(
    node_id=provider.id,
    scope=provider_scope,
)

patient_scope = client.identity.create_scope(
    categories=[DataCategory.DEMOGRAPHICS, DataCategory.CONTACT],
    silo_names=["identity"],
)
patient_cert = client.identity.issue_certificate(
    node_id=patient.id,
    scope=patient_scope,
)
```

---

## Step 4: Encrypt Patient Data

```python
# Encrypt PHI in the medical silo
diagnosis_cipher = client.encryption.encrypt(
    data="Type 2 Diabetes, diagnosed 2024-03-15",
    silo_name="medical",
    context={
        "patient_id": patient.id,
        "provider_id": provider.id,
        "action": "diagnosis",
    },
)

# Encrypt PII in the identity silo
name_cipher = client.encryption.encrypt(
    data="Jane Doe",
    silo_name="identity",
    context={
        "patient_id": patient.id,
        "action": "demographics",
    },
)

# The medical silo ciphertext CANNOT be decrypted with identity context
# This is enforced by AAD (Authenticated Associated Data)
try:
    client.encryption.decrypt(
        ciphertext=diagnosis_cipher,
        silo_name="identity",  # Wrong silo!
        context={"patient_id": patient.id, "action": "diagnosis"},
    )
except Exception as e:
    print(f"Cross-silo decryption blocked: {e}")  # AAD mismatch
```

---

## Step 5: PIR Consent Flow

The Patient Information Request (PIR) is the primary consent flow in healthcare. It allows a provider to request access to a patient's data across silos.

```python
# Provider requests PIR — access patient identity data from medical context
pir_consent = template.request_pir(
    patient_id=patient.id,
    reason="Annual physical requires medical history review",
)

print(f"PIR consent status: {pir_consent.status}")  # PENDING

# Patient approves the PIR
client.data.approve_consent(consent_id=pir_consent.id)
print(f"PIR consent status: {pir_consent.status}")  # APPROVED

# Now the provider can decrypt identity data in the medical context
demographics = client.encryption.decrypt(
    ciphertext=name_cipher,
    silo_name="identity",
    context={"patient_id": patient.id, "action": "demographics"},
)
print(f"Patient demographics: {demographics}")
```

---

## Step 6: Audit Trail

Every data access is logged to a tamper-evident SHA-256 hash chain.

```python
# Log the PIR approval
client.audit.log(
    action="consent.approve",
    actor_id=patient.id,
    target_id=provider.id,
    silo="identity",
    details={
        "consent_id": pir_consent.id,
        "flow_type": "pir",
        "categories": ["demographics", "contact"],
    },
)

# Log the data access
client.audit.log(
    action="data.read",
    actor_id=provider.id,
    target_id=patient.id,
    silo="medical",
    details={
        "consent_id": pir_consent.id,
        "categories": ["diagnosis"],
    },
)

# Verify chain integrity
is_valid = client.verify_integrity()
print(f"Audit chain valid: {is_valid}")  # True

# Query audit events
events = client.audit.query(action="data.read", limit=10)
for event in events:
    print(f"  {event.action} by {event.actor_id} -> {event.target_id}")
```

---

## Step 7: HIPAA Compliance Report

```python
report = template.hipaa_compliance_report()

print(f"Template: {report['template']}")
print(f"Version: {report['version']}")
print(f"Regulation: {report['regulation']}")
print(f"Silos: {', '.join(report['silos'])}")
print(f"Consent flows: {', '.join(report['consent_flows'])}")
print()

print("HIPAA Section Mappings:")
for section, mapping in report["mappings"]["hipaa"].items():
    print(f"  {section}:")
    print(f"    Description: {mapping['description']}")
    print(f"    Silos: {', '.join(mapping['silos'])}")
    print(f"    Enforcement: {mapping['enforcement']}")

print()
print("Enforcement Summary:")
for mechanism, description in report["enforcement_summary"].items():
    print(f"  {mechanism}: {description}")
```

---

## Step 8: Anonymous IDs (Right to Be Forgotten)

```python
# Create an anonymous ID for a patient
anon_id = client.data.create_anonymous_id(
    real_id=patient.id,
    silo_name="medical",
)
print(f"Anonymous ID: {anon_id}")  # e.g., "anon-a1b2c3d4..."

# Resolve it back when needed (with consent)
real_id = client.data.resolve_anonymous_id(
    anon_id=anon_id,
    silo_name="medical",
)
print(f"Real ID: {real_id}")  # patient.id

# Right to be forgotten — delete all mappings
client.data.forget_id(real_id=patient.id)
# All anonymous mappings for this patient are now deleted
```

---

## What's Next

- [Banking Template Tutorial](./banking-tutorial.md)
- [Investment Template Tutorial](./investment-tutorial.md)
- [Defense Template Tutorial](./defense-tutorial.md)
- [API Reference](../api-reference.md)