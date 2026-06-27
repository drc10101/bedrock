# Tutorial: Banking Application with Bedrock

Build a PCI-DSS-compliant financial data system using the Banking Template.

**What you'll learn:**
- Setting up a Bedrock client with the Banking Template
- Creating silos for PII/PAN/transaction separation
- Managing PCI-DSS consent flows
- PAN isolation with per-silo encryption
- Generating a PCI-DSS compliance report

---

## Prerequisites

```bash
pip install bedrock-sdk
```

---

## Step 1: Initialize with Banking Template

```python
from bedrock_sdk import BedrockClient
from templates.banking import BankingTemplate

# Create a banking-configured client
template = BankingTemplate(mode="developer")
config = template.get_config()

# Verify PCI-DSS-specific defaults
print(f"Audit retention: {config.audit.retention_years} years")  # 7
print(f"MFA required: {config.access_control.mfa_required}")      # True
print(f"Session TTL: {config.access_control.session_ttl_seconds}s")  # 1800 (30 min)
print(f"Lockout attempts: {config.access_control.lockout_max_attempts}")  # 3

client = BedrockClient(config=config)
```

---

## Step 2: Create Banking Silos

The Banking Template provides 3 pre-configured silos:

| Silo | Categories | Purpose |
|------|-----------|---------|
| `identity` | demographics, contact, ssn, kyc, beneficial_ownership | PII/KYC — identity verification |
| `transactions` | pan, transaction_history, balances, statements | Financial — PAN isolated per PCI-DSS 3.4 |
| `auth` | credentials, sessions, mfa, fraud_alerts | Authentication — fraud detection |

```python
silos = template.create_silos(client.data._silo_manager)

for name, silo in silos.items():
    print(f"  {name}: {silo.display_name}")
    print(f"    Categories: {', '.join(silo.categories)}")
```

---

## Step 3: Register Banking Staff and Customers

```python
# Register a teller
teller = client.identity.register_node(
    name="teller-001",
    role="teller",
    portal="provider",
)

# Register a customer
customer = client.identity.register_node(
    name="customer-67890",
    role="customer",
    portal="patient",
)

# Register an auditor
auditor = client.identity.register_node(
    name="auditor-compliance",
    role="auditor",
    portal="partner",
)
```

---

## Step 4: Encrypt Financial Data with PAN Isolation

PCI-DSS 3.4 requires that PAN (Primary Account Number) be isolated and encrypted separately from other data.

```python
# Encrypt PAN in the transactions silo (isolated per PCI-DSS 3.4)
pan_cipher = client.encryption.encrypt(
    data="4532-XXXX-XXXX-1234",
    silo_name="transactions",
    context={
        "customer_id": customer.id,
        "category": "pan",
        "action": "storage",
    },
)

# Encrypt customer PII in the identity silo (separate from PAN)
name_cipher = client.encryption.encrypt(
    data="John Smith",
    silo_name="identity",
    context={
        "customer_id": customer.id,
        "action": "demographics",
    },
)

# PAN ciphertext CANNOT be decrypted with identity context
# This enforces PCI-DSS 3.4 PAN isolation
try:
    client.encryption.decrypt(
        ciphertext=pan_cipher,
        silo_name="identity",  # Wrong silo!
        context={"customer_id": customer.id, "category": "pan"},
    )
except Exception as e:
    print(f"PAN isolation enforced: {e}")
```

---

## Step 5: PCI-DSS Consent Flows

```python
# Account opening — customer authorizes identity and financial data access
opening_consent = template.request_account_opening(
    customer_id=customer.id,
    reason="New checking account application",
)
client.data.approve_consent(consent_id=opening_consent.id)
print(f"Account opening consent: {opening_consent.status}")  # APPROVED

# Transaction authorization — customer authorizes a specific transaction
txn_consent = template.request_transaction_auth(
    customer_id=customer.id,
    reason="Wire transfer to external account",
)
client.data.approve_consent(consent_id=txn_consent.id)
print(f"Transaction consent: {txn_consent.status}")  # APPROVED

# Audit review — auditor requests access to transaction logs
audit_consent = template.request_audit_review(
    auditor_id=auditor.id,
    reason="Quarterly compliance review per PCI-DSS requirement 10",
)
client.data.approve_consent(consent_id=audit_consent.id)
print(f"Audit consent: {audit_consent.status}")  # APPROVED
```

---

## Step 6: PCI-DSS Compliance Report

```python
report = template.pci_dss_compliance_report()

print(f"Template: {report['template']}")
print(f"Version: {report['version']}")
print(f"Regulation: {report['regulation']}")
print(f"Silos: {', '.join(report['silos'])}")
print()

print("PCI-DSS Section Mappings:")
for section, mapping in report["mappings"]["pci_dss"].items():
    print(f"  {section}:")
    print(f"    Description: {mapping['description']}")
    print(f"    Enforcement: {mapping['enforcement']}")

print()
print("Enforcement Summary:")
for mechanism, description in report["enforcement_summary"].items():
    print(f"  {mechanism}: {description}")
```

---

## Key Differences from Healthcare

| Feature | Healthcare | Banking |
|---------|-----------|---------|
| Session timeout | 1 hour | 30 minutes |
| Lockout attempts | 5 | 3 |
| Consent default TTL | 1 hour | 30 minutes |
| PAN isolation | N/A | Required (PCI-DSS 3.4) |
| Audit retention | 7 years | 7 years |
| MFA | Required | Required |

---

## What's Next

- [Investment Template Tutorial](./investment-tutorial.md)
- [Defense Template Tutorial](./defense-tutorial.md)
- [API Reference](../api-reference.md)