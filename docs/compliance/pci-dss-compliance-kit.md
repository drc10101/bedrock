# PCI-DSS v4.0 Compliance Kit

Mapping PCI-DSS v4.0 requirements to Bedrock enforcement mechanisms.

**Regulation:** Payment Card Industry Data Security Standard v4.0
**Version:** 1.0.0
**Template:** Banking
**Last Updated:** 2026-06-27

---

## Requirement 1: Install and Maintain Network Security Controls

### Requirement 1.1 — Network Security Controls

| PCI-DSS Requirement | Bedrock Enforcement | Module |
|---------------------|---------------------|--------|
| 1.1.1 — Document and maintain network architecture | Silo architecture documented in BankingTemplate | — |
| 1.1.2 — Network diagrams | BankingTemplate defines 3-silo architecture | — |
| 1.2.1 — Network connections between trusted and untrusted | Self-healing mesh isolates untrusted nodes | TransportModule |
| 1.2.4 — Restrict inbound/outbound traffic | Rate limiting per node/endpoint | TransportModule |
| 1.2.6 — Segment cardholder data | Identity silo separates PII from transaction silo (PAN) | DataModule |
| 1.3.1 — Restrict inbound traffic to cardholder data | Silo boundaries enforced, no cross-access without consent | DataModule |

### Requirement 1.4 — Network Connection from Untrusted Networks

| PCI-DSS Requirement | Bedrock Enforcement | Module |
|---------------------|---------------------|--------|
| 1.4.1 — Network connection from untrusted networks | TLS 1.3 minimum, downgrade detection | TransportModule |
| 1.4.2 — Inspection of inbound traffic | Rate limiting + anomaly detection via mesh | TransportModule |

---

## Requirement 2: Apply Secure Configurations

### Requirement 2.1 — Processes and Mechanisms

| PCI-DSS Requirement | Bedrock Enforcement | Module |
|---------------------|---------------------|--------|
| 2.1.1 — Document and maintain system components | Node registry tracks all system nodes | IdentityModule |
| 2.2.1 — Configuration standards | BankingTemplate provides standard config | — |
| 2.2.2 — Only necessary services | Minimum-necessary scoping on all certificates | IdentityModule |
| 2.2.3 — Primary functions | Silos isolate PAN from other data | DataModule |
| 2.2.4 — Authorize and document services | Certificate scoping + audit log of all access | IdentityModule + AuditModule |

### Requirement 2.3 — Strong Cryptography

| PCI-DSS Requirement | Bedrock Enforcement | Module |
|---------------------|---------------------|--------|
| 2.3.1 — Encryption for admin access | TLS 1.3 required for all transport | TransportModule |
| 2.3.2 — Encryption for non-console admin | MFA required for all admin access | AccessModule |

---

## Requirement 3: Protect Stored Account Data

### Requirement 3.1 — Processes and Mechanisms

| PCI-DSS Requirement | Bedrock Enforcement | Module |
|---------------------|---------------------|--------|
| 3.1.1 — Minimize storage of cardholder data | Pan isolation: PAN stored only in transactions silo | DataModule |
| 3.2.1 — Do not store sensitive auth data | Auth data stored in separate auth silo | DataModule |
| 3.3.1 — Protect stored account data | AES-256-GCM encryption at rest per silo | EncryptionModule |
| 3.3.2 — Render PAN unreadable | Per-silo HKDF-derived keys make PAN unreadable outside transactions silo | EncryptionModule |
| 3.3.3 — Key management | Master key + per-silo HKDF derivation | EncryptionModule |
| 3.4.1 — Cryptographic key management | Key rotation via `rotate_keys()` | EncryptionModule |
| 3.4.2 — Split knowledge | HKDF derivation means no single key reveals PAN | EncryptionModule |
| 3.5.1 — Document and implement key management | Key management documented in EncryptionModule | EncryptionModule |
| 3.5.2 — Key rotation | `rotate_keys()` for periodic key rotation | EncryptionModule |
| 3.5.3 — Secure key storage | Keys never stored in plaintext, HKDF-derived per session | EncryptionModule |

### PAN Isolation (PCI-DSS 3.4)

The Banking Template enforces PAN isolation architecturally:

```
┌─────────────────────────────────────────┐
│          Identity Silo                  │
│  demographics, contact, ssn, kyc       │  ← PII, never contains PAN
│  beneficial_ownership                   │
└─────────────────────────────────────────┘
┌─────────────────────────────────────────┐
│       Transactions Silo                 │
│  pan, transaction_history, balances     │  ← PAN isolated here ONLY
│  statements                             │
└─────────────────────────────────────────┘
┌─────────────────────────────────────────┐
│           Auth Silo                     │
│  credentials, sessions, mfa             │  ← Never contains PAN or PII
│  fraud_alerts                            │
└─────────────────────────────────────────┘
```

Cross-silo access requires explicit consent. AAD context binding prevents PAN from being decrypted outside the transactions silo.

---

## Requirement 4: Protect Data in Transit

### Requirement 4.1 — Strong Cryptography and Security Protocols

| PCI-DSS Requirement | Bedrock Enforcement | Module |
|---------------------|---------------------|--------|
| 4.1.1 — Encryption in transit | TLS 1.3 minimum, enforced by TransportModule | TransportModule |
| 4.2.1 — Never send unprotected PAN | PAN encrypted in transactions silo, never transmitted decrypted | EncryptionModule |
| 4.2.2 — Encryption over open networks | E2EE messaging (`send_e2ee`/`receive_e2ee`) | EncryptionModule |

---

## Requirement 5: Protect Against Malicious Software

### Requirement 5.1 — Processes and Mechanisms

| PCI-DSS Requirement | Bedrock Enforcement | Module |
|---------------------|---------------------|--------|
| 5.1.1 — Malicious software detection | Self-healing mesh detects anomalous behavior | TransportModule |
| 5.2.1 — Anti-malware mechanisms | Node attestation baselines detect compromise | IdentityModule |
| 5.3.1 — Anti-malware mechanisms | AttestationManager with STRICT policy (production) | IdentityModule |

---

## Requirement 6: Develop and Maintain Secure Systems

### Requirement 6.1 — Processes and Mechanisms

| PCI-DSS Requirement | Bedrock Enforcement | Module |
|---------------------|---------------------|--------|
| 6.2.1 — Secure system development | Silo architecture enforces data isolation by design | DataModule |
| 6.3.1 — Security vulnerabilities | Attestation baselines detect unauthorized changes | IdentityModule |
| 6.4.1 — Change control | Audit chain logs all changes | AuditModule |
| 6.4.2 — Review changes | `audit.query()` provides change history | AuditModule |

---

## Requirement 7: Restrict Access by Business Need-to-Know

### Requirement 7.1 — Restrict Access to Need-to-Know

| PCI-DSS Requirement | Bedrock Enforcement | Module |
|---------------------|---------------------|--------|
| 7.1.1 — Access to system components | RBAC roles (teller, customer, compliance, auditor) | AccessModule |
| 7.2.1 — Least privileges | Minimum-necessary scoping on all certificates | IdentityModule |
| 7.2.2 — Default deny | `silo_strict_mode=True` — no access without explicit consent | DataModule |
| 7.2.3 — Need-to-know | `consent_require_reason=True` — every access must be justified | DataModule |

### Minimum Necessary Matrix (Banking)

| Role | Identity | Transactions | Auth | Permissions |
|------|----------|-------------|------|-------------|
| Customer | demographics, contact | balances, statements | sessions | read (own data) |
| Teller | demographics, contact | pan, transactions | sessions, mfa | read, write |
| Compliance | demographics | transaction_history | cui_access_logs | read |
| Auditor | — | — | audit_logs | read-only |

---

## Requirement 8: Identify Users and Authenticate Access

### Requirement 8.1 — Processes and Mechanisms

| PCI-DSS Requirement | Bedrock Enforcement | Module |
|---------------------|---------------------|--------|
| 8.1.1 — Identify all users | Unique node IDs via `register_node()` | IdentityModule |
| 8.2.1 — Authenticate all access | Certificate-based authentication | IdentityModule |
| 8.3.1 — Multi-factor authentication | `mfa_required=True` in AccessControlConfig | AccessModule |
| 8.3.2 — MFA for all CDE access | MFA required for all access (no exceptions in banking) | AccessModule |
| 8.4.1 — Strong authentication | Certificate + MFA for all access | IdentityModule + AccessModule |
| 8.6.1 — MFA for all console access | MFA verified before any access | AccessModule |

### Requirement 8.2 — Password Management

| PCI-DSS Requirement | Bedrock Enforcement | Module |
|---------------------|---------------------|--------|
| 8.2.4 — Password complexity | Enforced at account creation | AccessModule |
| 8.2.5 — No shared accounts | Unique node IDs prevent shared access | IdentityModule |
| 8.2.6 — Account lockout | `lockout_max_attempts=3` (banking default) | AccessModule |
| 8.2.7 — Session timeout | `session_ttl_seconds=1800` (30 min banking default) | AccessModule |

---

## Requirement 9: Restrict Physical Access

### Requirement 9.1 — Physical Access Restrictions

| PCI-DSS Requirement | Bedrock Enforcement | Module |
|---------------------|---------------------|--------|
| 9.1.1 — Physical access controls | Infrastructure control (out of Bedrock scope) | — |
| 9.3.1 — Physical access log | Audit chain logs all access events | AuditModule |

---

## Requirement 10: Log and Monitor All Access

### Requirement 10.1 — Logging Mechanisms

| PCI-DSS Requirement | Bedrock Enforcement | Module |
|---------------------|---------------------|--------|
| 10.1.1 — Audit logs present | Audit chain logs all actions | AuditModule |
| 10.2.1 — Individual user actions | Node IDs track individual actions | IdentityModule + AuditModule |
| 10.2.2 — Log entries | All audit entries include action, actor, target, silo, timestamp | AuditModule |
| 10.3.1 — Audit trail integrity | SHA-256 hash chain — tampering detectable | AuditModule |
| 10.3.2 — Review logs | `audit.query()` and `audit.export()` for review | AuditModule |
| 10.4.1 — Time synchronization | Timestamps on all audit entries | AuditModule |
| 10.5.1 — Retention | `retention_years=7` in AuditConfig | AuditModule |
| 10.7.1 — Detect anomalies | Self-healing mesh + rate limiting detect anomalies | TransportModule |

---

## Requirement 11: Test Security Regularly

### Requirement 11.1 — Security Testing

| PCI-DSS Requirement | Bedrock Enforcement | Module |
|---------------------|---------------------|--------|
| 11.1.1 — Penetration testing | Attestation baselines detect unauthorized changes | IdentityModule |
| 11.3.1 — Intrusion detection | Self-healing mesh detects and isolates compromised nodes | TransportModule |
| 11.3.2 — Detection and alerting | `flag_node()` + `check_downgrade()` for intrusion detection | TransportModule |

---

## Requirement 12: Organizational Policies

### Requirement 12.1 — Information Security Policy

| PCI-DSS Requirement | Bedrock Enforcement | Module |
|---------------------|---------------------|--------|
| 12.1.1 — Security policy | BankingTemplate provides standard configuration | — |
| 12.2.1 — Acceptable use | Role permissions enforce acceptable use | AccessModule |
| 12.3.1 — Data classification | Silo categories classify data (PII, PAN, auth) | DataModule |
| 12.5.1 — Incident response | Self-healing mesh + audit chain for incident evidence | TransportModule + AuditModule |
| 12.8.1 — Third-party agreements | Partner role with minimum-necessary scoping | AccessModule |
| 12.10.1 — Incident response plan | Mesh healing provides automated response | TransportModule |

---

## Enforcement Summary

| PCI-DSS Requirement | Primary Enforcement | Secondary |
|---------------------|---------------------|-----------|
| Req 1: Network Security | TransportModule (TLS, mesh) | DataModule (silo isolation) |
| Req 2: Secure Config | BankingTemplate (standard config) | IdentityModule (attestation) |
| Req 3: Protect Stored Data | EncryptionModule (AES-256-GCM) | DataModule (PAN isolation) |
| Req 4: Transit Security | TransportModule (TLS 1.3) | EncryptionModule (E2EE) |
| Req 5: Malware Protection | TransportModule (mesh detection) | IdentityModule (attestation) |
| Req 6: Secure Development | DataModule (silo architecture) | AuditModule (change control) |
| Req 7: Access Restriction | AccessModule (RBAC) | DataModule (consent flows) |
| Req 8: Authentication | IdentityModule (certificates) | AccessModule (MFA, lockout) |
| Req 9: Physical Access | AuditModule (access logs) | — |
| Req 10: Logging | AuditModule (SHA-256 chain) | TransportModule (anomaly detection) |
| Req 11: Security Testing | IdentityModule (attestation) | TransportModule (intrusion detection) |
| Req 12: Organizational | BankingTemplate (policy) | AccessModule (role enforcement) |