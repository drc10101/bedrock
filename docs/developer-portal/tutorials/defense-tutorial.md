# Tutorial: Defense Application with Bedrock

Build a CMMC/DFARS-compliant defense application using the Defense Template.

**What you'll learn:**
- Setting up a Bedrock client with the Defense Template
- Clearance-gated consent flows (need-to-know basis)
- CUI (Controlled Unclassified Information) silo management
- ITAR/EAR export review flows
- CMMC Level 2 / NIST 800-171 compliance mapping

---

## Prerequisites

```bash
pip install bedrock-sdk
```

---

## Step 1: Initialize with Defense Template

```python
from bedrock_sdk import BedrockClient
from templates.defense import DefenseTemplate

template = DefenseTemplate(mode="developer")
config = template.get_config()

# Verify DFARS/CMMC-specific defaults
print(f"Audit retention: {config.audit.retention_years} years")  # 6 (DFARS)
print(f"MFA required: {config.access_control.mfa_required}")    # True (CMMC IA.1)
print(f"Session TTL: {config.access_control.session_ttl_seconds}s")  # 1800 (30 min)
print(f"Lockout attempts: {config.access_control.lockout_max_attempts}")  # 3
print(f"Consent requires reason: {config.data_separation.consent_require_reason}")  # True
```

---

## Step 2: Create Defense Silos

| Silo | Categories | Purpose |
|------|-----------|---------|
| `identity` | demographics, clearance_level, clearance_type, investigation_status, citizenship, adjudication | PII + clearance status |
| `cui` | technical_data, drawings, specifications, source_code, operational_plans, logistics | CUI per 32 CFR 2002 |
| `auth` | credentials, sessions, mfa, cui_access_logs, export_reviews, incident_reports | Access + audit |

```python
silos = template.create_silos(client.data._silo_manager)

for name, silo in silos.items():
    print(f"  {name}: {silo.display_name}")
    print(f"    Categories: {', '.join(silo.categories)}")
```

---

## Step 3: Clearance-Gated Access

Defense uses a 5-level clearance hierarchy: public(0) < cui(1) < secret(2) < top_secret(3) < top_secret_sci(4).

```python
# Register cleared staff
cleared_staff = client.identity.register_node(
    name="staff-001",
    role="cleared_staff",
    portal="provider",
)

# Register FSO (Facility Security Officer)
fso = client.identity.register_node(
    name="fso-johnson",
    role="fso",
    portal="admin",
)

# Register a subcontractor
sub = client.identity.register_node(
    name="sub-contractor",
    role="subcontractor",
    portal="partner",
)

# Check clearance levels
from templates.defense import DefenseTemplate

print(DefenseTemplate.check_clearance("cleared_staff", "cui"))       # True
print(DefenseTemplate.check_clearance("cleared_staff", "secret"))    # False
print(DefenseTemplate.check_clearance("fso", "top_secret"))          # True
print(DefenseTemplate.check_clearance("subcontractor", "cui"))       # True
print(DefenseTemplate.check_clearance("subcontractor", "secret"))    # False
```

---

## Step 4: Clearance Verification Consent

Before accessing CUI, personnel must verify their clearance level. This is a cross-silo consent flow from identity to CUI.

```python
# Cleared staff requests CUI access (requires CUI clearance minimum)
consent = template.request_clearance_verification(
    personnel_id=cleared_staff.id,
    reason="Need access to technical specifications for project X",
)
print(f"Clearance verification status: {consent.status}")  # PENDING

# FSO approves the clearance verification
client.data.approve_consent(consent_id=consent.id)
print(f"Clearance verification status: {consent.status}")  # APPROVED

# Now staff can request CUI access
cui_consent = template.request_cui_access(
    personnel_id=cleared_staff.id,
    reason="Review technical specifications for project X",
)
client.data.approve_consent(consent_id=cui_consent.id)
print(f"CUI access status: {cui_consent.status}")  # APPROVED
```

---

## Step 5: Export Review (ITAR/EAR)

Export review requires minimum Secret clearance and has a 24-hour TTL.

```python
from templates.defense import DEFENSE_CONSENT_FLOWS

export_flow = DEFENSE_CONSENT_FLOWS["export_review"]
print(f"Export review TTL: {export_flow.default_ttl_seconds}s")  # 86400 (24 hours)
print(f"Minimum clearance: {export_flow.min_clearance}")          # "secret"
print(f"CMMC sections: {export_flow.cmmc_sections}")
```

---

## Step 6: CMMC/DFARS Compliance Report

```python
report = template.cmmc_compliance_report()

print(f"Template: {report['template']}")
print(f"Regulation: {report['regulation']}")
print()

print("CMMC Level 2 Practices:")
for practice, mapping in report["mappings"]["cmmc_level_2"].items():
    print(f"  {practice}: {mapping['description']}")
    print(f"    Enforcement: {mapping['enforcement']}")

print()
print("DFARS 252.204-7012:")
for clause, mapping in report["mappings"]["dfars_252_204_7012"].items():
    print(f"  {clause}: {mapping['description']}")

print()
print("Enforcement Summary:")
for mechanism, description in report["enforcement_summary"].items():
    print(f"  {mechanism}: {description}")
```

---

## Key Differences from Other Templates

| Feature | Healthcare | Banking | Investment | Defense |
|---------|-----------|---------|------------|---------|
| Consent TTL | 1 hour | 30 min | 5 min (trades) | 1 hour (8 hour max) |
| Lockout attempts | 5 | 3 | 5 | 3 |
| Audit retention | 7 years | 7 years | 6 years | 6 years |
| Clearance gating | No | No | No | Yes (5 levels) |
| Need-to-know | Optional | Optional | Minimum necessary | Always required |
| Export review | N/A | N/A | N/A | ITAR/EAR (24h TTL) |

---

## What's Next

- [API Reference](../api-reference.md)
- [Quick Start Guide](../quick-start.md)