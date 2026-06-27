# Bedrock Security Audit Preparation

Pre-audit checklist and documentation for external security review.

**Status:** In Preparation
**Target:** SOC 2 Type II + HIPAA Security Rule compliance
**Version:** 1.0.0

---

## Audit Scope

### Core Modules Under Review

| Module | File | Purpose | Lines |
|--------|------|---------|-------|
| Encryption Engine | `core/bedrock/encryption/engine.py` | AES-256-GCM field-level encryption | ~580 |
| AAD | `core/bedrock/encryption/aad.py` | Authenticated Additional Data | ~50 |
| Ciphertext Format | `core/bedrock/encryption/version.py` | Versioned ciphertext format | ~30 |
| E2EE Deliverer | `core/bedrock/encryption/engine.py` | End-to-end encrypted delivery | ~200 |
| Key Management | `core/bedrock/key_management/keys.py` | HKDF-SHA256 key derivation | ~230 |
| Silo Manager | `core/bedrock/data_separation/silo.py` | Encrypted data silo lifecycle | ~280 |
| Consent Gate | `core/bedrock/data_separation/consent.py` | Consent-gated data access | ~260 |
| Anonymous ID | `core/bedrock/data_separation/anonymous_id.py` | Pseudonymous patient IDs | ~400 |
| Identity Fabric | `core/bedrock/identity/registration.py` | Node registration + lifecycle | ~260 |
| Certificates | `core/bedrock/identity/certificates.py` | X.509 certificate management | ~340 |
| Attestation | `core/bedrock/identity/attestation.py` | TPM-style attestation | ~170 |
| Capabilities | `core/bedrock/identity/capabilities.py` | RBAC capability tokens | ~100 |
| Audit Chain | `core/bedrock/audit/chain.py` | SHA-256 hash chain audit log | ~220 |
| Access Control | `core/bedrock/access_control/controller.py` | Portal-aware RBAC | ~310 |
| Transport Security | `core/bedrock/transport/security.py` | TLS enforcement + rate limiting | ~270 |
| Mesh State Machine | `core/bedrock/mesh/state_machine.py` | 5-state node lifecycle | ~200 |
| Attack Detector | `core/bedrock/mesh/detector.py` | Anomaly detection | ~150 |
| Self-Healing Mesh | `core/bedrock/mesh/healing.py` | Network restructuring | ~100 |
| Licensing | `core/bedrock/licensing/enforcement.py` | Two-tier CA-enforced | ~380 |

### Integration Layer Under Review

| Module | File | Purpose | Lines |
|--------|------|---------|-------|
| InFill Adapter | `integrations/infill/adapter.py` | InFill domain → Bedrock core | ~683 |

### Templates Under Review

| Template | File | Purpose | Tests |
|----------|------|---------|-------|
| Healthcare | `templates/healthcare/` | PIR, ePRR, E2EE, consent flows | 38 |
| Banking | `templates/banking/` | KYC, GLBA, PCI-DSS | 43 |
| Investment | `templates/investment/` | SEC, FINRA, portfolio | 45 |
| Defense | `templates/defense/` | CMMC, DFARS, CUI | 48 |

---

## Security Architecture Summary

### 1. Encryption
- **Algorithm:** AES-256-GCM (FIPS 197 compliant)
- **Key Derivation:** HKDF-SHA256 per-silo (NIST SP 800-56C)
- **Ciphertext Format:** Versioned, base64-encoded, with AAD per-field
- **Key Isolation:** Each silo gets a derived key from master; compromising one silo does not expose others
- **Key Rotation:** Version-based; retired keys retained for decryption

### 2. Identity
- **Node IDs:** UUID v7 (time-ordered, globally unique)
- **Key Pairs:** Ed25519 (signing) + X25519 (encryption)
- **Certificates:** X.509 v3 with CA-enforced node limits
- **Attestation:** 4-level baseline (none, basic, strong, hardware)

### 3. Data Separation
- **Silos:** Encrypted, HKDF-derived keys per silo per version
- **Consent:** Explicit consent required for cross-silo access
- **Anonymous IDs:** Pseudonymous patient identifiers with unlinkable cross-silo mapping
- **Categories:** Fine-grained data categories within silos (identity, medical, auth)

### 4. Audit
- **Hash Chain:** SHA-256 linked chain, each entry references previous hash
- **Tamper Evidence:** Any modification breaks the chain — verifiable in O(n)
- **Entry Fields:** action, actor_id, target_id, silo, timestamp, details
- **Query:** Filterable by action, actor, target, silo, time range

### 5. Access Control
- **Portals:** 4-portal architecture (patient, provider, admin, super_admin)
- **Roles:** Per-portal RBAC with permission-level gating
- **Cross-Portal Blocking:** Proxy-based portal isolation (proxy.ts)
- **Capability Tokens:** Scoped, revocable capability grants

### 6. Transport
- **TLS Enforcement:** Minimum TLS 1.2, downgrade detection
- **Rate Limiting:** Token bucket algorithm, configurable per-endpoint
- **CORS:** Strict origin validation

### 7. Self-Healing Mesh
- **States:** Active, Suspect, Quarantined, Healing, Revoked
- **Detection:** Anomaly-based signal detection (5 signal types)
- **Healing:** Automatic network restructuring around attacks
- **Consensus:** Multi-node agreement before quarantine

### 8. Licensing
- **Offline Validation:** HMAC-SHA256 signed license keys, no phone-home
- **CA Enforcement:** Certificate Authority refuses certificates beyond licensed node count
- **Tier Gating:** Developer (3 nodes, self-signed) vs. Runtime (per-node CA-enforced)
- **Upgrade Path:** Seamless Developer → Runtime with certificate re-issuance

---

## Test Coverage

| Category | Tests | Status |
|----------|-------|--------|
| Encryption | 68 | All passing |
| Key Management | 33 | All passing |
| Data Separation | 82 | All passing |
| Identity | 98 | All passing |
| Audit | 42 | All passing |
| Access Control | 87 | All passing |
| Transport | 38 | All passing |
| Mesh | 46 | All passing |
| Config | 24 | All passing |
| Integration (Python) | 16 | All passing |
| Integration (TypeScript) | 16 | All passing |
| Healthcare Template | 38 | All passing |
| Banking Template | 43 | All passing |
| Investment Template | 45 | All passing |
| Defense Template | 48 | All passing |
| Licensing System | 65 | All passing |
| InFill Adapter | 51 | All passing |
| **Total** | **866** | **All passing** |

---

## Compliance Mappings

| Regulation | Kit | Mapped Controls |
|------------|-----|-----------------|
| HIPAA | `docs/compliance/hipaa-compliance-kit.md` | 12 controls |
| PCI-DSS v4.0 | `docs/compliance/pci-dss-compliance-kit.md` | 14 controls |
| SOC 2 Type II | `docs/compliance/soc2-compliance-kit.md` | 10 controls |
| GLBA | `docs/compliance/glba-compliance-kit.md` | 8 controls |
| DFARS/CMMC | `docs/compliance/dfars-cmmc-compliance-kit.md` | 11 controls |

---

## Pre-Audit Checklist

- [x] All 866 tests passing
- [x] Encryption uses AES-256-GCM (FIPS 197)
- [x] Key derivation uses HKDF-SHA256 (NIST SP 800-56C)
- [x] No plaintext PII stored — all data encrypted per-field with silo-specific keys
- [x] Consent required for cross-silo data access
- [x] Audit chain uses SHA-256 linked hash chain
- [x] Audit chain integrity verifiable via `AuditChain.verify()`
- [x] Node identity uses Ed25519 + X25519 key pairs
- [x] Certificate issuance CA-enforced with node count limits
- [x] Rate limiting on all transport endpoints
- [x] TLS 1.2+ enforcement with downgrade detection
- [x] Self-healing mesh with 5-state lifecycle
- [x] Two-tier licensing with offline HMAC-SHA256 validation
- [x] Anonymous patient IDs with unlinkable cross-silo mapping
- [x] Cross-portal blocking (proxy.ts)
- [ ] Penetration testing (external)
- [ ] Static analysis (external)
- [ ] Dependency audit (external)
- [ ] Key rotation testing
- [ ] Performance testing under load

---

## Files for Auditor Review

### Core Implementation
- `core/bedrock/encryption/` — AES-256-GCM encryption, HKDF key derivation
- `core/bedrock/key_management/` — Master key and silo key management
- `core/bedrock/data_separation/` — Silo lifecycle, consent, anonymous IDs
- `core/bedrock/identity/` — Node registration, certificates, attestation
- `core/bedrock/audit/` — Hash chain audit log
- `core/bedrock/access_control/` — Portal-aware RBAC
- `core/bedrock/transport/` — TLS enforcement, rate limiting
- `core/bedrock/mesh/` — Self-healing mesh, attack detection
- `core/bedrock/licensing/` — Two-tier license enforcement

### Tests
- `tests/` — Core test suite (747 Python tests)
- `sdk/tests/` — SDK integration tests (16 Python + 16 TypeScript)
- `templates/*/test_*.py` — Vertical template tests
- `integrations/infill/test_adapter.py` — InFill adapter tests

### Compliance Kits
- `docs/compliance/hipaa-compliance-kit.md`
- `docs/compliance/pci-dss-compliance-kit.md`
- `docs/compliance/soc2-compliance-kit.md`
- `docs/compliance/glba-compliance-kit.md`
- `docs/compliance/dfars-cmmc-compliance-kit.md`

### Developer Portal
- `docs/developer-portal/quick-start.md`
- `docs/developer-portal/api-reference.md`
- `docs/developer-portal/configuration.md`
- `docs/developer-portal/tutorials/`