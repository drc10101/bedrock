# Tutorial: Investment Platform with Bedrock

Build an SEC/FINRA-compliant investment platform using the Investment Template.

**What you'll learn:**
- Setting up a Bedrock client with the Investment Template
- Creating silos for identity/portfolio/auth separation
- Trade execution consent flows with 5-minute TTL
- SEC 17a-4 audit retention (6 years)
- Minimum necessary standard enforcement

---

## Prerequisites

```bash
pip install bedrock-sdk
```

---

## Step 1: Initialize with Investment Template

```python
from bedrock_sdk import BedrockClient
from templates.investment import InvestmentTemplate

template = InvestmentTemplate(mode="developer")
config = template.get_config()

# Verify SEC/FINRA-specific defaults
print(f"Audit retention: {config.audit.retention_years} years")  # 6 (SEC 17a-4)
print(f"Session TTL: {config.access_control.session_ttl_seconds}s")  # 1800 (30 min)
print(f"MFA required: {config.access_control.mfa_required}")  # True
```

---

## Step 2: Create Investment Silos

| Silo | Categories | Purpose |
|------|-----------|---------|
| `identity` | demographics, contact, ssn, kyc, accreditation, beneficial_ownership | PII/KYC/AML |
| `portfolio` | holdings, orders, margin, trade_history, performance | Trade data |
| `auth` | credentials, sessions, mfa, trade_surveillance, compliance_alerts | Surveillance |

```python
silos = template.create_silos(client.data._silo_manager)

for name, silo in silos.items():
    print(f"  {name}: {silo.display_name}")
    print(f"    Categories: {', '.join(silo.categories)}")
```

---

## Step 3: Register Investment Roles

```python
# Register an advisor
advisor = client.identity.register_node(
    name="advisor-smith",
    role="advisor",
    portal="provider",
)

# Register a client
client_node = client.identity.register_node(
    name="client-12345",
    role="client",
    portal="patient",
)

# Register a compliance officer
compliance = client.identity.register_node(
    name="compliance-jones",
    role="compliance",
    portal="admin",
)

# Register a regulator (read-only)
regulator = client.identity.register_node(
    name="regulator-sec",
    role="regulator",
    portal="partner",
)
```

---

## Step 4: Trade Execution Consent (5-Minute TTL)

Investment consent flows use the shortest TTL (5 minutes) for trade execution security.

```python
# Client authorizes an advisor to execute trades
trade_consent = template.request_trade_execution(
    client_id=client_node.id,
    reason="Client authorizes advisor to execute market orders on behalf",
)
client.data.approve_consent(consent_id=trade_consent.id)

print(f"Trade consent TTL: {trade_consent.ttl_seconds}s")  # 300 (5 minutes)
print(f"Trade consent status: {trade_consent.status}")      # APPROVED

# After 5 minutes, the consent expires automatically
# This enforces SEC minimum necessary standard
```

---

## Step 5: SEC/FINRA Compliance Report

```python
report = template.sec_finra_compliance_report()

print(f"Template: {report['template']}")
print(f"Regulation: {report['regulation']}")
print()

print("SEC/FINRA Mappings:")
for section, mapping in report["mappings"].items():
    print(f"  {section}:")
    for reg, details in mapping.items():
        print(f"    {reg}: {details['description']}")
        print(f"      Enforcement: {details['enforcement']}")
```

---

## Key Differences from Banking

| Feature | Banking | Investment |
|---------|---------|------------|
| Trade execution TTL | N/A | 5 minutes |
| Audit retention | 7 years | 6 years (SEC 17a-4) |
| Surveillance | Fraud alerts | Trade surveillance |
| Regulator role | N/A | Read-only (SEC/FINRA) |
| Accreditation data | N/A | In identity silo (KYC/AML) |

---

## What's Next

- [Defense Template Tutorial](./defense-tutorial.md)
- [API Reference](../api-reference.md)