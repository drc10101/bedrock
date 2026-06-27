# SOC 2 Type II Compliance Kit

Mapping SOC 2 Type II (Trust Services Criteria) to Bedrock enforcement mechanisms.

**Regulation:** AICPA Trust Services Criteria (SOC 2 Type II)
**Version:** 1.0.0
**Templates:** All verticals
**Last Updated:** 2026-06-27

---

## Overview

SOC 2 Type II audits evaluate controls over time against the five Trust Services Criteria: Security, Availability, Processing Integrity, Confidentiality, and Privacy. This kit maps each criterion to Bedrock's enforcement mechanisms.

---

## CC6 — Security (Common Criteria)

### CC6.1 — Logical and Physical Access Controls

| SOC 2 Criterion | Bedrock Enforcement | Module |
|-----------------|---------------------|--------|
| CC6.1.1 — Logical access controls | RBAC with role-based permissions, certificate scoping | AccessModule + IdentityModule |
| CC6.1.2 — User registration and deprovisioning | `register_node()` + `revoke_certificate()` lifecycle | IdentityModule |
| CC6.1.3 — Least privilege | Minimum-necessary certificate scoping | IdentityModule |
| CC6.1.4 — Access restrictions | Silo strict mode blocks cross-silo access without consent | DataModule |

### CC6.2 — Authentication

| SOC 2 Criterion | Bedrock Enforcement | Module |
|-----------------|---------------------|--------|
| CC6.2.1 — Unique credentials | Node IDs are unique, no shared credentials | IdentityModule |
| CC6.2.2 — Multi-factor authentication | `mfa_required=True` enforced | AccessModule |
| CC6.2.3 — Password management | Lockout after max attempts, secure password handling | AccessModule |
| CC6.2.4 — Session management | Configurable TTL, max TTL, and automatic expiration | AccessModule |

### CC6.3 — Encryption

| SOC 2 Criterion | Bedrock Enforcement | Module |
|-----------------|---------------------|--------|
| CC6.3.1 — Encryption at rest | AES-256-GCM per-silo with HKDF-derived keys | EncryptionModule |
| CC6.3.2 — Encryption in transit | TLS 1.3 minimum with downgrade detection | TransportModule |
| CC6.3.3 — Key management | HKDF key derivation with rotation support | EncryptionModule |
| CC6.3.4 — Key separation | Per-silo keys (identity, medical, auth derive from different HKDF info) | EncryptionModule |

---

## CC7 — Availability

### CC7.1 — System Availability

| SOC 2 Criterion | Bedrock Enforcement | Module |
|-----------------|---------------------|--------|
| CC7.1.1 — System monitoring | Self-healing mesh monitors node health | TransportModule |
| CC7.1.2 — Incident detection | Anomaly detection (brute force, credential stuffing, port scans) | TransportModule |
| CC7.1.3 — Incident response | 5-state healing lifecycle (active → suspect → quarantined → healing → recovered) | TransportModule |
| CC7.1.4 — Recovery procedures | Mesh consensus for state transitions, automatic healing | TransportModule |

### CC7.2 — Backup and Recovery

| SOC 2 Criterion | Bedrock Enforcement | Module |
|-----------------|---------------------|--------|
| CC7.2.1 — Data backup | Audit chain export for compliance backup | AuditModule |
| CC7.2.2 — Recovery testing | Audit chain verification (`verify_integrity()`) | AuditModule |

### CC7.3 — Change Management

| SOC 2 Criterion | Bedrock Enforcement | Module |
|-----------------|---------------------|--------|
| CC7.3.1 — Change controls | Audit chain logs all configuration changes | AuditModule |
| CC7.3.2 — Change documentation | Attestation baselines document authorized state | IdentityModule |

---

## CC8 — Processing Integrity

### CC8.1 — Processing Accuracy and Completeness

| SOC 2 Criterion | Bedrock Enforcement | Module |
|-----------------|---------------------|--------|
| CC8.1.1 — Data validation | Silo categories validate data types | DataModule |
| CC8.1.2 — Processing integrity | AAD context binding ensures data integrity | EncryptionModule |
| CC8.1.3 — Error handling | Tamper-evident audit chain detects errors | AuditModule |
| CC8.1.4 — Reconciliation | `verify_integrity()` for audit chain reconciliation | AuditModule |

---

## CC9 — Confidentiality

### CC9.1 — Confidential Information Protection

| SOC 2 Criterion | Bedrock Enforcement | Module |
|-----------------|---------------------|--------|
| CC9.1.1 — Data classification | Silo categories classify data sensitivity levels | DataModule |
| CC9.1.2 — Access restrictions | Consent-gated cross-silo access | DataModule |
| CC9.1.3 — Encryption | AES-256-GCM at rest, TLS 1.3 in transit | EncryptionModule + TransportModule |
| CC9.1.4 — Data disposal | Anonymous ID deletion (`forget_id()`) for right to be forgotten | DataModule |
| CC9.1.5 — Confidentiality agreements | Partner role with scoped certificates | AccessModule |

### CC9.2 — Transmission and Storage

| SOC 2 Criterion | Bedrock Enforcement | Module |
|-----------------|---------------------|--------|
| CC9.2.1 — Encrypted transmission | TLS 1.3 + E2EE messaging | TransportModule + EncryptionModule |
| CC9.2.2 — Encrypted storage | Per-silo HKDF-derived encryption | EncryptionModule |
| CC9.2.3 — Key management | HKDF key derivation with rotation | EncryptionModule |

---

## CC10 — Privacy

### CC10.1 — Collection and Use

| SOC 2 Criterion | Bedrock Enforcement | Module |
|-----------------|---------------------|--------|
| CC10.1.1 — Notice | Consent flows require reason for all data access | DataModule |
| CC10.1.2 — Consent | Explicit consent required before cross-silo data use | DataModule |
| CC10.1.3 — Purpose limitation | Consent scope limits data use to specified purposes | DataModule |

### CC10.2 — Data Retention and Disposal

| SOC 2 Criterion | Bedrock Enforcement | Module |
|-----------------|---------------------|--------|
| CC10.2.1 — Retention | Configurable retention (7 years healthcare, 6 years SEC/DFARS) | AuditModule |
| CC10.2.2 — Disposal | `forget_id()` for complete data deletion | DataModule |
| CC10.2.3 — Consent expiration | TTL-based consent expiration | DataModule |

### CC10.3 — Access and Correction

| SOC 2 Criterion | Bedrock Enforcement | Module |
|-----------------|---------------------|--------|
| CC10.3.1 — Access requests | Patient/client portal access with `data.read` | AccessModule |
| CC10.3.2 — Amendment requests | Audit trail of all amendment requests | AuditModule |
| CC10.3.3 — Accounting of disclosures | Complete audit chain provides disclosure log | AuditModule |

---

## Enforcement Summary

| SOC 2 Criterion | Primary Module | Key Features |
|-----------------|---------------|-------------|
| CC6 (Security) | AccessModule + IdentityModule | RBAC, MFA, certificates, silo isolation |
| CC7 (Availability) | TransportModule | Self-healing mesh, anomaly detection |
| CC8 (Processing Integrity) | AuditModule + EncryptionModule | Hash chain, AAD context |
| CC9 (Confidentiality) | DataModule + EncryptionModule | Consent flows, per-silo encryption |
| CC10 (Privacy) | DataModule + AuditModule | Consent TTL, right to be forgotten, disclosure log |

---

## Evidence Collection for Audit

### Documents to Provide

| SOC 2 Request | Bedrock Evidence |
|---------------|-------------------|
| Access control policy | Role definitions (per vertical template) |
| User provisioning/deprovisioning | Node registration + certificate lifecycle |
| Encryption key management | HKDF key derivation documentation |
| Incident response | Self-healing mesh 5-state lifecycle |
| Audit trail | SHA-256 hash chain + export capability |
| Change management | Attestation baselines + audit log |
| Data classification | Silo category definitions (per vertical) |
| Privacy notice/consent | Consent flow configurations |
| Business continuity | Mesh healing + node failover |

### Automated Evidence

```python
# Generate compliance evidence for SOC 2 audit
from templates.healthcare import HealthcareTemplate

template = HealthcareTemplate(mode="production")
config = template.get_config()

# Access control evidence
evidence = {
    "mfa_required": config.access_control.mfa_required,
    "session_ttl": config.access_control.session_ttl_seconds,
    "lockout_attempts": config.access_control.lockout_max_attempts,
    "silo_strict_mode": config.data_separation.silo_strict_mode,
    "consent_require_reason": config.data_separation.consent_require_reason,
    "audit_retention_years": config.audit.retention_years,
    "encryption_algorithm": config.encryption.algorithm,
    "key_derivation": config.encryption.key_derivation,
}

# Audit trail evidence
audit_export = client.audit.export(format="jsonl")

# Role definitions
roles = template.ROLES  # Per-vertical role definitions
```