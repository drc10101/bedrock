# GLBA Compliance Kit

Mapping Gramm-Leach-Bliley Act requirements to Bedrock enforcement mechanisms.

**Regulation:** Gramm-Leach-Bliley Act (GLBA) — 15 USC §§ 6801-6809
**Version:** 1.0.0
**Templates:** Banking, Investment
**Last Updated:** 2026-06-27

---

## Overview

GLBA requires financial institutions to safeguard customer nonpublic personal information (NPI). This kit maps GLBA Privacy Rule and Safeguards Rule requirements to Bedrock enforcement.

---

## Privacy Rule (16 CFR 313)

### §313.4 — Initial Notice

| GLBA Requirement | Bedrock Enforcement | Module |
|-----------------|---------------------|--------|
| Notice of privacy policy | Consent flows require reason for all data access | DataModule |
| Notice of right to opt out | Consent flows include opt-out (revoke) capability | DataModule |
| Notice of information sharing | Audit trail logs all data sharing | AuditModule |

### §313.5 — Disclosure of NPI

| GLBA Requirement | Bedrock Enforcement | Module |
|-----------------|---------------------|--------|
| No disclosure of NPI without consent | `consent_require_reason=True` — all access requires explicit consent | DataModule |
| Right to opt out | `revoke_consent()` terminates access immediately | DataModule |
| Limited disclosure for processing | Minimum-necessary scoping via certificate categories | IdentityModule |

### §313.6 — Confidentiality of NPI

| GLBA Requirement | Bedrock Enforcement | Module |
|-----------------|---------------------|--------|
| Maintain confidentiality | Per-silo encryption (AES-256-GCM) | EncryptionModule |
| No disclosure to non-affiliates | Consent-gated access with silo boundaries | DataModule |
| Secure disposal | `forget_id()` for complete data deletion | DataModule |

---

## Safeguards Rule (16 CFR 314)

### §314.3 — Information Security Program

| GLBA Requirement | Bedrock Enforcement | Module |
|-----------------|---------------------|--------|
| Designate responsible employee | FSO/program_manager role in Defense template | AccessModule |
| Identify risks | Self-healing mesh anomaly detection | TransportModule |
| Assess safeguards effectiveness | `verify_integrity()` + attestation baselines | AuditModule + IdentityModule |

### §314.4 — Safeguard Requirements

#### (a) Employee Training and Management

| GLBA Requirement | Bedrock Enforcement | Module |
|-----------------|---------------------|--------|
| Access controls | RBAC roles with minimum-necessary scoping | AccessModule |
| MFA for sensitive access | `mfa_required=True` | AccessModule |
| Account management | Node registration + certificate lifecycle | IdentityModule |

#### (b) Information Systems

| GLBA Requirement | Bedrock Enforcement | Module |
|-----------------|---------------------|--------|
| Encryption at rest | AES-256-GCM per-silo | EncryptionModule |
| Encryption in transit | TLS 1.3 minimum | TransportModule |
| Access controls | Certificate-scoped access + consent flows | IdentityModule + DataModule |
| Audit logging | SHA-256 hash chain | AuditModule |
| Intrusion detection | Self-healing mesh + rate limiting | TransportModule |

#### (c) Testing and Monitoring

| GLBA Requirement | Bedrock Enforcement | Module |
|-----------------|---------------------|--------|
| Regular testing | Audit chain verification | AuditModule |
| Monitoring | Anomaly detection (brute force, credential stuffing) | TransportModule |
| Response procedures | 5-state healing lifecycle | TransportModule |

#### (d) Service Provider Oversight

| GLBA Requirement | Bedrock Enforcement | Module |
|-----------------|---------------------|--------|
| Contractual safeguards | Partner role with scoped certificates | AccessModule |
| Monitoring compliance | Audit trail of all partner access | AuditModule |

### §314.5 — Adjustments

| GLBA Requirement | Bedrock Enforcement | Module |
|-----------------|---------------------|--------|
| Material changes trigger reassessment | Attestation baselines detect changes | IdentityModule |
| Update safeguards | Key rotation + certificate renewal | EncryptionModule + IdentityModule |

---

## NPI Isolation (GLBA-Specific)

The Banking and Investment templates isolate NPI architecturally:

### Banking Template

```
┌─────────────────────────────────────────┐
│          Identity Silo                  │
│  demographics, contact, ssn, kyc        │  ← PII/NPI
│  beneficial_ownership                    │
└─────────────────────────────────────────┘
┌─────────────────────────────────────────┐
│       Transactions Silo                 │
│  pan, transaction_history, balances     │  ← Financial NPI
│  statements                              │
└─────────────────────────────────────────┘
┌─────────────────────────────────────────┐
│           Auth Silo                     │
│  credentials, sessions, mfa             │  ← Auth data (never NPI)
│  fraud_alerts                            │
└─────────────────────────────────────────┘
```

### Investment Template

```
┌─────────────────────────────────────────┐
│          Identity Silo                  │
│  demographics, contact, ssn, kyc        │  ← PII/NPI
│  accreditation, beneficial_ownership     │
└─────────────────────────────────────────┘
┌─────────────────────────────────────────┐
│        Portfolio Silo                    │
│  holdings, orders, margin                │  ← Investment NPI
│  trade_history, performance              │
└─────────────────────────────────────────┘
┌─────────────────────────────────────────┐
│           Auth Silo                     │
│  credentials, sessions, mfa             │  ← Auth data (never NPI)
│  trade_surveillance, compliance_alerts   │
└─────────────────────────────────────────┘
```

---

## Enforcement Summary

| GLBA Requirement | Primary Module | Key Feature |
|-----------------|---------------|-------------|
| §313.4 Notice | DataModule | Consent flow reason requirement |
| §313.5 Disclosure | DataModule | Consent-gated access with opt-out |
| §313.6 Confidentiality | EncryptionModule | Per-silo AES-256-GCM |
| §314.3 Security Program | TransportModule | Anomaly detection + healing |
| §314.4(a) Employee Training | AccessModule | RBAC + MFA |
| §314.4(b) Information Systems | EncryptionModule | Encryption at rest and in transit |
| §314.4(c) Testing | AuditModule | SHA-256 hash chain verification |
| §314.4(d) Service Providers | AccessModule | Partner role with scoped access |
| §314.5 Adjustments | IdentityModule | Attestation baselines |