# Bedrock Compliance Kits

Regulation-to-enforcement mapping documents for compliance audits.

Each kit maps specific regulatory sections to the Bedrock features that enforce them, with module references and evidence collection guidance.

---

## Available Kits

| Kit | Regulation | Template | Sections Mapped |
|-----|-----------|----------|----------------|
| [HIPAA](./hipaa-compliance-kit.md) | 45 CFR 160/164 | Healthcare | Privacy Rule + Security Rule + Breach Notification |
| [PCI-DSS](./pci-dss-compliance-kit.md) | PCI-DSS v4.0 | Banking | Requirements 1-12 |
| [SOC 2](./soc2-compliance-kit.md) | AICPA TSC | All verticals | CC6-CC10 (Security, Availability, Processing Integrity, Confidentiality, Privacy) |
| [GLBA](./glba-compliance-kit.md) | 15 USC 6801-6809 | Banking, Investment | Privacy Rule + Safeguards Rule |
| [DFARS/CMMC](./dfars-cmmc-compliance-kit.md) | DFARS 252.204-7012, CMMC L2, NIST 800-171 | Defense | 7012(b)(c)(d) + CMMC Practices + NIST Controls |

---

## Quick Reference: Regulatory Coverage

| Bedrock Module | HIPAA | PCI-DSS | SOC 2 | GLBA | DFARS/CMMC |
|---------------|-------|---------|-------|------|-------------|
| EncryptionModule | §164.312(a)(2)(iv) | Req 3, 4 | CC6.3, CC9.2 | §314.4(b) | NIST 3.10, 3.13 |
| DataModule | §164.502, §164.508 | Req 3, 7 | CC9.1 | §313.5, §313.6 | NIST 3.1 |
| AuditModule | §164.312(b) | Req 10 | CC7.2 | §314.4(c) | NIST 3.3 |
| IdentityModule | §164.312(d) | Req 8 | CC6.2 | §314.4(a) | NIST 3.5 |
| AccessModule | §164.312(a)(1) | Req 7, 8 | CC6.1 | §314.4(a) | NIST 3.1 |
| TransportModule | §164.312(e)(1) | Req 1, 4 | CC7.1 | §314.4(b) | NIST 3.13 |

---

## Using These Kits

### For Compliance Audits

1. Identify the regulation you need to demonstrate compliance for
2. Open the corresponding kit document
3. For each regulatory section, find the Bedrock enforcement mechanism
4. Use `template.{regulation}_compliance_report()` to generate an automated mapping
5. Use `client.audit.export()` for evidence collection

### For Evidence Collection

```python
# Generate compliance report
from templates.healthcare import HealthcareTemplate
template = HealthcareTemplate(mode="production")
report = template.hipaa_compliance_report()

# Export audit trail for compliance review
audit_export = client.audit.export(format="jsonl")

# Verify audit chain integrity
is_valid = client.verify_integrity()
```

### For Regulation Switching

Bedrock's vertical templates pre-configure compliance-appropriate settings:

| Setting | HIPAA (Healthcare) | PCI-DSS (Banking) | SEC/FINRA (Investment) | DFARS (Defense) |
|---------|-------------------|-------------------|------------------------|-----------------|
| Audit retention | 7 years | 7 years | 6 years | 6 years |
| MFA required | Yes | Yes | Yes | Yes |
| Session TTL | 1 hour | 30 min | 30 min | 30 min |
| Lockout attempts | 5 | 3 | 5 | 3 |
| Consent TTL | 1 hour | 30 min | 5 min (trades) | 1 hour |
| Consent reason required | Yes | Yes | Yes | Yes (need-to-know) |
| Silo strict mode | Yes | Yes | Yes | Yes |