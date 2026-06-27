# DFARS 252.204-7012 / CMMC Level 2 Compliance Kit

Mapping DFARS 252.204-7012, CMMC Level 2, and NIST 800-171 requirements to Bedrock enforcement.

**Regulation:** DFARS 252.204-7012, CMMC Level 2, NIST SP 800-171
**Version:** 1.0.0
**Template:** Defense
**Last Updated:** 2026-06-27

---

## Overview

DFARS 252.204-7012 requires defense contractors handling CUI (Controlled Unclassified Information) to implement NIST 800-171 controls. CMMC Level 2 assesses these controls. This kit maps each requirement to Bedrock's enforcement mechanisms.

---

## DFARS 252.204-7012

### 7012(b) — Safeguarding Covered Defense Information

| DFARS Clause | Requirement | Bedrock Enforcement | Module |
|--------------|-------------|---------------------|--------|
| 7012(b) | Implement NIST 800-171 | DefenseTemplate provides CMMC Level 2 configuration | — |
| 7012(b) | Protect CUI at rest | Per-silo AES-256-GCM encryption, CUI isolated in `cui` silo | EncryptionModule |
| 7012(b) | Protect CUI in transit | TLS 1.3 minimum, E2EE messaging | TransportModule |
| 7012(b) | Access controls | RBAC with clearance-gated roles | AccessModule |
| 7012(b) | Audit controls | SHA-256 hash chain, 6-year retention | AuditModule |

### 7012(c) — Cyber Incident Reporting

| DFARS Clause | Requirement | Bedrock Enforcement | Module |
|--------------|-------------|---------------------|--------|
| 7012(c)(1) | Report incidents within 72 hours | Self-healing mesh detects anomalies, audit chain provides evidence | TransportModule + AuditModule |
| 7012(c)(2) | Preserve evidence | Audit chain is tamper-evident (SHA-256), preserves forensic evidence | AuditModule |
| 7012(c)(3) | Damage assessment | Attestation baselines detect compromise extent | IdentityModule |

### 7012(d) — Flow Down to Subcontractors

| DFARS Clause | Requirement | Bedrock Enforcement | Module |
|--------------|-------------|---------------------|--------|
| 7012(d) | Flow down CUI requirements | Subcontractor role enforces minimum-necessary access | AccessModule |
| 7012(d) | Subcontractor access controls | Certificate scoping limits subcontractor data access | IdentityModule |
| 7012(d) | Subcontractor reporting | Audit trail tracks all subcontractor access | AuditModule |

---

## CMMC Level 2 Practices

### AC — Access Control

| CMMC Practice | Requirement | Bedrock Enforcement | Module |
|--------------|-------------|---------------------|--------|
| AC.1.001 | Limit information system access | RBAC with role-based permissions | AccessModule |
| AC.1.002 | Authorized users | Node registration + certificates | IdentityModule |
| AC.2.005 | Least privilege | Minimum-necessary certificate scoping | IdentityModule |
| AC.2.006 | Need-to-know | `consent_require_reason=True` (Defense default) | DataModule |
| AC.2.007 | Control access | Clearance-gated consent flows | DataModule |
| AC.2.008 | Privilege limiting | 5 roles with scoped permissions | AccessModule |
| AC.2.010 | Logical access | Certificate-based node authentication | IdentityModule |
| AC.2.013 | Remote access | TLS 1.3 + E2EE for all remote access | TransportModule |
| AC.2.016 | Wireless access | Infrastructure control (out of scope) | — |

### AU — Audit and Accountability

| CMMC Practice | Requirement | Bedrock Enforcement | Module |
|--------------|-------------|---------------------|--------|
| AU.1.001 | Audit events | All actions logged to audit chain | AuditModule |
| AU.1.002 | Audit content | Action, actor, target, silo, timestamp, details | AuditModule |
| AU.2.031 | Audit monitoring | `audit.query()` for real-time monitoring | AuditModule |
| AU.2.032 | Audit review | `audit.export()` for compliance review | AuditModule |
| AU.2.033 | Audit protection | SHA-256 hash chain prevents tampering | AuditModule |
| AU.2.034 | Audit retention | 6-year retention per DFARS requirement | AuditModule |
| AU.2.035 | Audit reduction | Query by action, actor, silo, date | AuditModule |
| AU.2.036 | Audit generation | All system actions generate audit events | AuditModule |

### CM — Configuration Management

| CMMC Practice | Requirement | Bedrock Enforcement | Module |
|--------------|-------------|---------------------|--------|
| CM.1.001 | Configuration policy | DefenseTemplate provides standard configuration | — |
| CM.2.061 | Change control | Audit chain logs all configuration changes | AuditModule |
| CM.2.062 | Change approval | Attestation baselines for authorized state | IdentityModule |
| CM.2.065 | Software restrictions | Certificate scoping limits software capabilities | IdentityModule |

### IA — Identification and Authentication

| CMMC Practice | Requirement | Bedrock Enforcement | Module |
|--------------|-------------|---------------------|--------|
| IA.1.001 | Identify users | Unique node IDs via `register_node()` | IdentityModule |
| IA.1.002 | Authenticate users | Certificate-based authentication | IdentityModule |
| IA.2.001 | Network access | MFA required for all CUI access | AccessModule |
| IA.2.002 | Non-organizational users | Subcontractor role with scoped access | AccessModule |
| IA.2.003 | Centralized management | Node registry for identity management | IdentityModule |
| IA.2.004 | MFA for privileged access | MFA required for admin/FSO access | AccessModule |

### MP — Media Protection

| CMMC Practice | Requirement | Bedrock Enforcement | Module |
|--------------|-------------|---------------------|--------|
| MP.1.001 | Media protection policy | CUI silo encryption protects all media | EncryptionModule |
| MP.2.068 | CUI on media | Per-silo encryption ensures CUI protection on any media | EncryptionModule |
| MP.2.069 | Media sanitization | `forget_id()` for complete data removal | DataModule |

### PE — Physical Protection

| CMMC Practice | Requirement | Bedrock Enforcement | Module |
|--------------|-------------|---------------------|--------|
| PE.1.001 | Physical protection | Infrastructure control (out of scope) | — |
| PE.2.076 | Physical access controls | Infrastructure control (out of scope) | — |

### SC — System and Communications Protection

| CMMC Practice | Requirement | Bedrock Enforcement | Module |
|--------------|-------------|---------------------|--------|
| SC.1.001 | System boundary | Silo boundaries isolate CUI from other data | DataModule |
| SC.2.081 | Encryption in transit | TLS 1.3 minimum with downgrade detection | TransportModule |
| SC.2.082 | Encryption at rest | AES-256-GCM per-silo encryption | EncryptionModule |
| SC.2.083 | Network architecture | 3-silo architecture with clearance-gated access | DataModule |
| SC.2.084 | Denial of service | Rate limiting + self-healing mesh | TransportModule |

---

## NIST 800-171 Requirements

### §3.1 — Access Control

| NIST 800-171 | Requirement | Bedrock Enforcement | Module |
|--------------|-------------|---------------------|--------|
| 3.1.1 | Limit system access | RBAC + clearance-gated access | AccessModule |
| 3.1.2 | Limit system access to transactions | Consent-gated category-level access | DataModule |
| 3.1.3 | Control CUI flow | Silo strict mode + AAD context binding | DataModule + EncryptionModule |
| 3.1.5 | Least privilege | Minimum-necessary certificate scoping | IdentityModule |
| 3.1.6 | Least privilege for non-organizational users | Subcontractor role with scoped access | AccessModule |
| 3.1.7 | Prevent unauthorized access | Silo boundaries + consent flows | DataModule |
| 3.1.20 | Control CUI on external systems | E2EE messaging for external communication | EncryptionModule |

### §3.3 — Audit and Accountability

| NIST 800-171 | Requirement | Bedrock Enforcement | Module |
|--------------|-------------|---------------------|--------|
| 3.3.1 | Audit events | All actions logged to audit chain | AuditModule |
| 3.3.2 | Audit content | Action, actor, target, silo, timestamp, details | AuditModule |
| 3.3.3 | Audit review | `audit.query()` for compliance review | AuditModule |
| 3.3.4 | Alert on audit failures | Self-healing mesh detects anomalies | TransportModule |
| 3.3.5 | Correlate audit events | Audit chain hash linkage | AuditModule |
| 3.3.7 | Protect audit information | SHA-256 hash chain — tampering detected | AuditModule |
| 3.3.8 | Retain audit trail | 6-year retention per DFARS | AuditModule |

### §3.5 — Identification and Authentication

| NIST 800-171 | Requirement | Bedrock Enforcement | Module |
|--------------|-------------|---------------------|--------|
| 3.5.1 | Identify users | Unique node IDs | IdentityModule |
| 3.5.2 | Authenticate users | Certificate-based authentication | IdentityModule |
| 3.5.3 | MFA for CUI access | `mfa_required=True` (Defense default) | AccessModule |

### §3.10 — Media Protection

| NIST 800-171 | Requirement | Bedrock Enforcement | Module |
|--------------|-------------|---------------------|--------|
| 3.10.1 | Protect CUI on media | Per-silo encryption | EncryptionModule |
| 3.10.2 | Mark CUI | Silo categories identify CUI data | DataModule |
| 3.10.3 | Sanitize media | `forget_id()` for complete data removal | DataModule |

### §3.13 — System and Communications Protection

| NIST 800-171 | Requirement | Bedrock Enforcement | Module |
|--------------|-------------|---------------------|--------|
| 3.13.1 | Monitor, control, protect communications | TLS 1.3 + E2EE + rate limiting | TransportModule |
| 3.13.2 | Architectural provision | 3-silo architecture with clearance gates | DataModule |
| 3.13.8 | Implement cryptographic protection | AES-256-GCM at rest + TLS 1.3 in transit | EncryptionModule + TransportModule |
| 3.13.11 | FIPS-validated cryptography | AES-256-GCM (FIPS 197) + SHA-256 (FIPS 180-4) | EncryptionModule |

---

## Defense Template Clearance System

The Defense Template implements a 5-level clearance hierarchy that gates every consent flow:

| Level | Clearance | Numeric | Role Access |
|-------|-----------|---------|-------------|
| 0 | Public | 0 | All authenticated users |
| 1 | CUI | 1 | cleared_staff, subcontractor |
| 2 | Secret | 2 | program_manager, auditor |
| 3 | Top Secret | 3 | fso |
| 4 | Top Secret/SCI | 4 | fso (with SCI access) |

### Clearance-Gated Consent Flows

| Flow | Source → Target | Min Clearance | TTL |
|------|-----------------|---------------|-----|
| clearance_verification | identity → cui | CUI | 8 hours |
| cui_access | cui → identity | CUI | 1 hour |
| export_review | cui → identity | Secret | 24 hours |
| audit_review | auth → cui | Secret | 24 hours |

---

## Enforcement Summary

| Regulation | Primary Module | Key Feature |
|-----------|---------------|-------------|
| DFARS 7012(b) | EncryptionModule | Per-silo AES-256-GCM |
| DFARS 7012(c) | TransportModule + AuditModule | 72-hour breach notification |
| DFARS 7012(d) | AccessModule | Subcontractor flow-down |
| CMMC AC | AccessModule + DataModule | RBAC + clearance gates |
| CMMC AU | AuditModule | SHA-256 hash chain, 6-year retention |
| CMMC CM | AuditModule + IdentityModule | Change control + attestation |
| CMMC IA | IdentityModule + AccessModule | Certificates + MFA |
| CMMC MP | EncryptionModule | Per-silo encryption |
| CMMC SC | TransportModule + DataModule | TLS 1.3 + silo isolation |
| NIST 3.1 | DataModule | Consent-gated access |
| NIST 3.3 | AuditModule | Tamper-evident audit trail |
| NIST 3.5 | IdentityModule | Certificate-based auth |
| NIST 3.10 | EncryptionModule | Encryption at rest |
| NIST 3.13 | TransportModule | Encryption in transit |