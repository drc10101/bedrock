# Getting Started with Bedrock

This guide walks through building a real application on Bedrock. By the end, your app will have cryptographic identities, field-level encryption, consent-gated data access, and a tamper-evident audit chain — all inherited from Bedrock, none written by you.

## Prerequisites

- Python 3.11 or later
- pip

## Step 1: Install and Initialize

```bash
pip install bedrock-core

bedrock init ./my-health-app
cd my-health-app
```

`bedrock init` creates your project directory with:

```
my-health-app/
  bedrock.env        # Environment template (keys, config)
  bedrock.db         # SQLite database (created on first run)
```

## Step 2: Get a License

You need a license key to run Bedrock. A free 30-day trial gives you full developer features, 3 local nodes, and self-signed certificates.

```bash
bedrock trial --licensee "you@yourdomain.com"
```

This writes your license key to `bedrock.env`. For production, you'd purchase a license at [bedrock.dev/pricing](https://bedrock.dev/pricing) and replace the trial key — no code changes needed.

## Step 3: Start the Server

```bash
bedrock serve
```

The API server starts on `http://localhost:8443`. This is what your app talks to. In production, you'd put this behind a reverse proxy with TLS termination.

## Step 4: Connect Your App

### Python

```bash
pip install bedrock-sdk
```

```python
from bedrock_sdk import BedrockClient

client = BedrockClient(
    base_url="http://localhost:8443",
    license_key="1:...",  # From bedrock.env
)
```

### TypeScript

```bash
npm install @infill/bedrock-sdk
```

```typescript
import { BedrockClient } from "@infill/bedrock-sdk";

const client = new BedrockClient({
  baseUrl: "http://localhost:8443",
  licenseKey: "1:...",  // From bedrock.env
});
```

You're connected. Everything from here is SDK calls — your app never touches raw cryptography.

## Step 5: Register Your Services as Nodes

Every service, device, or user in your system gets a cryptographic identity. This is the foundation — everything else builds on it.

```python
# Your patient intake service
intake = client.nodes.register(name="patient-intake", node_type="provider")

# Your clinical records service
records = client.nodes.register(name="clinical-records", node_type="provider")

# A patient identity
patient = client.nodes.register(name="patient-001", node_type="patient")
```

Each node gets a UUID, a public/private key pair, and a signed certificate. You didn't generate any of that — Bedrock did.

```python
print(intake["node_id"])       # "a3f1..."
print(intake["node_type"])     # "provider"
```

## Step 6: Create Data Silos

Data silos are encrypted containers. Each silo has a category (medical, financial, PII) and its own encryption keys. Data in one silo cannot be read by another without consent.

```python
# Medical records — contains diagnoses, prescriptions, lab results
medical = client.silos.create(
    name="medical-records",
    display_name="Medical Records",
    categories=["medical", "phi"],
)

# Billing — contains charges, insurance claims, payment info
billing = client.silos.create(
    name="billing-records",
    display_name="Billing Records",
    categories=["financial", "phi"],
)
```

Data siloed by purpose. Medical data stays in the medical silo. Billing data stays in the billing silo. They cannot leak into each other.

## Step 7: Encrypt Data Before Storing

When your app writes data, Bedrock encrypts it before it hits storage. Each field is encrypted with a key derived from the silo, record ID, and scope — you never manage keys.

```python
# Encrypt a diagnosis before saving to your database
ciphertext = client.encryption.encrypt(
    plaintext="Type 2 Diabetes, diagnosed 2024-01-15",
    silo=medical["silo_id"],
    record_id=patient["node_id"],
    scope="diagnosis",
    operation="store",
)

# Store the ciphertext in your database (Postgres, DynamoDB, whatever)
# db.save("diagnoses", {"id": patient["node_id"], "value": ciphertext["ciphertext"]})
```

Your database now stores ciphertext. Even if someone gets access to the database, they see encrypted blobs. Only a node with valid consent can decrypt.

## Step 8: Decrypt Data

When your app needs to read data back, Bedrock decrypts it — but only if the node has valid consent.

```python
# Decrypt the diagnosis for authorized viewing
plaintext = client.encryption.decrypt(
    ciphertext=ciphertext["ciphertext"],
    silo=medical["silo_id"],
    record_id=patient["node_id"],
    scope="diagnosis",
    operation="read",
)

print(plaintext["plaintext"])
# "Type 2 Diabetes, diagnosed 2024-01-15"
```

## Step 9: Request Consent for Cross-Silo Access

This is the core differentiator. A provider in the billing silo cannot read medical data unless the patient has granted cryptographic consent. No consent token, no data.

```python
# Patient grants consent for billing to access their diagnosis
# (In a real app, the patient would initiate this through your UI)
consent = client.consent.request(
    requester_id=intake["node_id"],      # Who's asking
    target_id=patient["node_id"],         # Whose data
    silo_id=medical["silo_id"],           # Which silo
    purpose="billing",                    # Why
    scope=["diagnosis"],                  # What fields
)

# The requesting service approves
client.consent.approve(consent_id=consent["consent_id"])
```

Now the billing service can access diagnosis data from the medical silo — but only the specific fields covered by the consent token, and only for the stated purpose. Every access is logged to the audit chain.

## Step 10: Verify the Audit Chain

Every operation — registration, encryption, decryption, consent grant, consent denial — is written to a SHA-256 hash chain. You can verify the chain has not been tampered with.

```python
# Query recent audit entries
entries = client.audit.query(limit=10)

for entry in entries["entries"]:
    print(f"{entry['timestamp']}  {entry['action']}  by {entry['actor']}")

# Verify the entire chain is intact
verification = client.audit.verify()
print(f"Chain valid: {verification['valid']}")
print(f"Entries checked: {verification['entries_checked']}")
```

If anyone tampers with any entry in the chain, the verification fails. This is how you prove compliance.

## What You Have Now

Your application now has:

- **Cryptographic identities** for every service and user — no anonymous access
- **Field-level encryption at rest** — data is ciphertext in your database
- **Consent-gated cross-silo access** — no data movement without patient authorization
- **Tamper-evident audit chain** — every action logged, tampering detected
- **License enforcement** — tier limits checked at runtime

You didn't write any of that. You called the SDK. Bedrock handled it.

## Running Tests

```bash
# Core tests (encryption, identity, consent, audit, licensing)
cd core && pytest

# Python SDK tests
cd sdk-python && pytest

# TypeScript SDK tests
cd sdk-ts && npm test
```

## Next Steps

- **Production deployment**: See [PRODUCTION_DEPLOYMENT.md](docs/PRODUCTION_DEPLOYMENT.md) for hardening the API server, configuring TLS, and scaling considerations.
- **Architecture deep dive**: See [BEDROCK_ARCHITECTURE_SPEC.md](docs/BEDROCK_ARCHITECTURE_SPEC.md) for the full technical specification.
- **License tiers**: See the [pricing table](#pricing) in the README for node limits, certificate types, and feature differences.
- **Security reporting**: See [SECURITY.md](SECURITY.md) for responsible disclosure.

## Common Questions

**Do I need to manage encryption keys?**
No. Bedrock derives per-field keys using HKDF from the silo ID, record ID, and scope. You never see the keys.

**Can I use my own database?**
Yes. Bedrock encrypts the data; you store the ciphertext wherever you want. Postgres, DynamoDB, S3, flat files — it doesn't matter. The data is already encrypted before it leaves Bedrock.

**What happens if a node is compromised?**
Revoke its certificate. All data encrypted with its keys is re-encryptable from the silo master key. The compromised node can no longer authenticate or decrypt anything.

**How does consent revocation work?**
Consent can be denied at any time. Once denied, the consent token is invalid and any future access requests using that token are rejected. Previously decrypted data is a consumer responsibility — but the audit trail shows exactly what was accessed and when.

**Can I run this without the API server?**
Yes. You can use Bedrock Core directly as a Python library — import the modules and call them without the HTTP layer. The API server is for multi-service architectures where different apps need to talk to a shared Bedrock instance.