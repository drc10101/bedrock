# HIPAA Compliance Kit

Mapping HIPAA Privacy Rule and Security Rule requirements to Bedrock enforcement mechanisms.

**Regulation:** 45 CFR Parts 160 and 164 (HIPAA Privacy Rule & Security Rule)
**Version:** 1.0.0
**Template:** Healthcare
**Last Updated:** 2026-06-27

---

## Overview

This compliance kit maps each HIPAA requirement to the specific Bedrock features that enforce it. Use this document during compliance audits to demonstrate how Bedrock satisfies each requirement.

---

## Privacy Rule (45 CFR 164.500-164.534)

### §164.502 — Uses and Disclosures of PHI: General Rules

| Requirement | Bedrock Enforcement | Module |
|-------------|---------------------|--------|
| Minimum necessary standard | Silo-based category scoping — each consent request specifies exact categories | DataModule |
| Uses limited to treatment, payment, operations | Consent flow types (PIR, ePRR, treatment, billing) with reason required | DataModule |
| Authorization required for non-TPO uses | `consent_require_reason=True` in DataSeparationConfig | DataModule |

### §164.508 — Uses and Disclosures: Authorization

| Requirement | Bedrock Enforcement | Module |
|-------------|---------------------|--------|
| Written authorization required | Consent flow creates auditable authorization record | DataModule |
| Authorization must specify expiration | Consent TTL enforcement (`consent_default_ttl_seconds`) | DataModule |
| Revocation of authorization | `revoke_consent()` immediately terminates access | DataModule |
| Authorizations must be specific | Categories and scope specified in every consent request | DataModule |

### §164.510 — Uses and Disclosures: Organizational Requirements

| Requirement | Bedrock Enforcement | Module |
|-------------|---------------------|--------|
| Minimum necessary for disclosures | Cross-silo consent only grants access to requested categories | DataModule |
| Business Associate agreements | Partner portal role with scoped certificates | AccessModule |

### §164.524 — Access of Individuals to PHI

| Requirement | Bedrock Enforcement | Module |
|-------------|---------------------|--------|
| Right to access PHI | Patient portal with `data.read` permission | AccessModule |
| Right to request amendments | Audit log of all amendment requests | AuditModule |
| Right to accounting of disclosures | Audit chain provides complete disclosure log | AuditModule |

### §164.526 — Amendment of PHI

| Requirement | Bedrock Enforcement | Module |
|-------------|---------------------|--------|
| Right to request amendment | Audit trail of amendment requests and responses | AuditModule |

### §164.528 — Accounting of Disclosures

| Requirement | Bedrock Enforcement | Module |
|-------------|---------------------|--------|
| Accounting of disclosures for 6 years | Audit retention = 7 years (HealthcareConfig) | AuditModule |
| Must include date, recipient, description | Audit chain entries include all required fields | AuditModule |

---

## Security Rule (45 CFR 164.302-164.318)

### §164.312(a)(1) — Access Control

| Requirement | Bedrock Enforcement | Module |
|-------------|---------------------|--------|
| Unique user identification | Node IDs are unique, issued via `register_node()` | IdentityModule |
| Emergency access procedure | FSO role with emergency override capability | AccessModule |
| Automatic logoff | `session_ttl_seconds=3600` (1 hour) | AccessModule |
| Encryption and decryption | AES-256-GCM per-silo encryption with HKDF-derived keys | EncryptionModule |

### §164.312(a)(2)(iv) — Encryption and Decryption

| Requirement | Bedrock Enforcement | Module |
|-------------|---------------------|--------|
| Encrypt PHI at rest | Silo-based encryption: each silo has unique HKDF-derived key | EncryptionModule |
| Decrypt only with correct AAD context | AAD context includes silo name, patient ID, action | EncryptionModule |
| Cross-silo decryption fails | AAD mismatch prevents cross-silo data leakage | EncryptionModule |

### §164.312(b) — Audit Controls

| Requirement | Bedrock Enforcement | Module |
|-------------|---------------------|--------|
| Record activity | Audit chain logs all actions with SHA-256 hash | AuditModule |
| Tamper-evident | SHA-256 hash chain — any modification breaks chain | AuditModule |
| 7-year retention | `retention_years=7` in AuditConfig | AuditModule |
| Query capability | `audit.query()` by action, actor, silo | AuditModule |
| Export for compliance | `audit.export()` in JSONL format | AuditModule |

### §164.312(c)(1) — Integrity Controls

| Requirement | Bedrock Enforcement | Module |
|-------------|---------------------|--------|
| Protect PHI from alteration | SHA-256 audit chain — any alteration detected | AuditModule |
| Attestation baselines | `baseline_attestation()` establishes node integrity baseline | IdentityModule |
| Periodic attestation checks | AttestationManager with STRICT policy (production) | IdentityModule |

### §164.312(d) — Authentication

| Requirement | Bedrock Enforcement | Module |
|-------------|---------------------|--------|
| Authentication of entity | Node certificates with `CertificateManager` | IdentityModule |
| Multi-factor authentication | `mfa_required=True` in AccessControlConfig | AccessModule |
| Password management | Lockout after 5 failed attempts (15-min duration) | AccessModule |

### §164.312(e)(1) — Transmission Security

| Requirement | Bedrock Enforcement | Module |
|-------------|---------------------|--------|
| Encrypt in transit | TLS 1.3 minimum with downgrade detection | TransportModule |
| E2EE message delivery | `send_e2ee()` / `receive_e2ee()` for node-to-node | EncryptionModule |
| Integrity controls | SHA-256 hash chain for all transmitted data | AuditModule |

### §164.314(a) — Organizational Requirements: Business Associate Contracts

| Requirement | Bedrock Enforcement | Module |
|-------------|---------------------|--------|
| BA must implement safeguards | Partner role with scoped certificates, minimum necessary | AccessModule |
| BA must report breaches | Audit chain provides breach evidence | AuditModule |
| BA must make records available | `audit.export()` provides complete record | AuditModule |

---

## Breach Notification Rule (45 CFR 164.400-164.414)

### §164.404 — Notification to Individuals

| Requirement | Bedrock Enforcement | Module |
|-------------|---------------------|--------|
| Detect breach | Self-healing mesh detects anomalies and flags nodes | TransportModule |
| Determine scope | Audit chain query identifies affected data | AuditModule |
| Document breach | Audit log creates breach event record | AuditModule |

---

## Enforcement Summary

| HIPAA Section | Primary Enforcement | Secondary |
|---------------|---------------------|-----------|
| §164.502 Minimum necessary | DataModule (silo categories) | ConsentScope |
| §164.508 Authorization | DataModule (consent flows) | AuditModule |
| §164.312(a)(1) Access control | AccessModule (RBAC + MFA) | IdentityModule |
| §164.312(a)(2)(iv) Encryption | EncryptionModule (AES-256-GCM) | SiloManager |
| §164.312(b) Audit | AuditModule (SHA-256 chain) | — |
| §164.312(c)(1) Integrity | AuditModule + AttestationManager | — |
| §164.312(d) Authentication | IdentityModule + AccessModule | MFA |
| §164.312(e)(1) Transmission | TransportModule (TLS 1.3) | E2EE |
| §164.314(a) BA contracts | AccessModule (partner role) | CertificateManager |
| §164.404 Breach notification | TransportModule + AuditModule | — |

---

## Audit Trail Requirements

The following audit events must be logged for HIPAA compliance:

| Event Type | Required Fields | HIPAA Section |
|-----------|----------------|---------------|
| `data.read` | actor_id, target_id, silo, categories, consent_id | §164.312(b) |
| `data.write` | actor_id, target_id, silo, categories | §164.312(b) |
| `consent.request` | actor_id, source_silo, target_silo, categories, reason | §164.508 |
| `consent.approve` | actor_id, consent_id, categories | §164.508 |
| `consent.revoke` | actor_id, consent_id | §164.508 |
| `consent.expire` | consent_id | §164.508 |
| `auth.login` | actor_id, mfa_verified | §164.312(d) |
| `auth.logout` | actor_id | §164.312(d) |
| `auth.lockout` | actor_id, attempts | §164.312(a)(1) |
| `cert.issue` | actor_id, node_id, scope | §164.312(d) |
| `cert.revoke` | actor_id, node_id | §164.312(d) |
| `key.rotate` | actor_id, key_id | §164.312(a)(2)(iv) |
| `healing.flag` | node_id, signal_type, reporter_id | §164.404 |
| `healing.quarantine` | node_id, consensus | §164.404 |