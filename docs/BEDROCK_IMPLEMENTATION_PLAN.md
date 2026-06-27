# Bedrock Implementation Plan

**Version:** 1.0.0  
**Status:** Draft  
**Created:** 2026-06-27

---

## Deliverable Breakdown

### Phase 1: Foundation (Core Extraction & Generalization)

Extract vertical-agnostic components from InFill, generalize them, and establish Bedrock Core.

| ID | Deliverable | Description | Est. Effort | Dependencies |
|----|-------------|-------------|-------------|--------------|
| B-101 | Core project structure | Package layout, build system, dependency management, dev environment setup | 1 day | None |
| B-102 | Encryption Engine | Generalize InFill's ECDH+HKDF+GCM stack into a standalone module. Support: field-level encryption, E2EE delivery, AAD construction, v2: prefix versioning, legacy Fernet backward compat | 3 days | B-101 |
| B-103 | Key Management | Master key hierarchy, HKDF derivation per silo, key rotation (info-string change), multi-key backward compat | 2 days | B-102 |
| B-104 | Data Separation Layer | Silo configuration, anonymous ID generation (word list customization), silo-scoped query engine, consent-gated cross-silo access | 3 days | B-102 |
| B-105 | Identity Fabric — Node Registration | Node ID generation (UUID v7 + ed25519), registration API, certificate signing request, CA integration | 3 days | B-103 |
| B-106 | Identity Fabric — Attestation | Boot-time attestation, known-good baseline verification, attestation API | 2 days | B-105 |
| B-107 | Identity Fabric — Certificate Lifecycle | Certificate issuance (24h default), auto-renewal, revocation, CRL/OCSP | 2 days | B-105 |
| B-108 | Audit Chain | SHA-256 hash chain logging, verification API, 6-year retention config, export for compliance | 2 days | B-101 |
| B-109 | Access Control | RBAC with role-portal mapping, scoped sessions, MFA (TOTP + recovery codes), account lockout | 3 days | B-105, B-108 |
| B-110 | Transport Security | TLS termination config, E2EE delivery generalization, downgrade detection, AAD format | 2 days | B-102, B-105 |
| B-111 | Core Integration Tests | End-to-end tests: register node → encrypt data → request across silo → consent → deliver → decrypt → verify audit chain | 3 days | B-102 through B-110 |

**Phase 1 Total: ~24 days**

### Phase 2: SDK Development

Build developer-facing SDKs wrapping Core's APIs.

| ID | Deliverable | Description | Est. Effort | Dependencies |
|----|-------------|-------------|-------------|--------------|
| B-201 | SDK project structure (Python) | Package layout, pyproject.toml, CI, documentation scaffold | 1 day | B-111 |
| B-202 | Identity SDK (Python) | Node registration, certificate management, capability scoping | 2 days | B-201, B-105 |
| B-203 | Encryption SDK (Python) | Field encrypt/decrypt, E2EE flow, AAD construction, key derivation | 2 days | B-201, B-102 |
| B-204 | Data SDK (Python) | Silo definition, compartmentalization config, cross-silo consent queries | 2 days | B-201, B-104 |
| B-205 | Audit SDK (Python) | Write to chain, verify integrity, export for compliance | 1 day | B-201, B-108 |
| B-206 | Access SDK (Python) | RBAC config, session management, MFA enrollment | 2 days | B-201, B-109 |
| B-207 | Transport SDK (Python) | E2EE message passing, downgrade detection | 1 day | B-201, B-110 |
| B-208 | SDK project structure (TypeScript) | Package layout, tsconfig, build, CI, documentation scaffold | 1 day | B-111 |
| B-209 | Identity SDK (TypeScript) | Browser + Node.js, Web Crypto API integration | 2 days | B-208, B-105 |
| B-210 | Encryption SDK (TypeScript) | Web Crypto E2EE (proven in InFill), AAD, key derivation | 2 days | B-208, B-102 |
| B-211 | Data SDK (TypeScript) | Silo configuration, consent flows | 1 day | B-208, B-104 |
| B-212 | Audit SDK (TypeScript) | Chain write, verify, export | 1 day | B-208, B-108 |
| B-213 | Access SDK (TypeScript) | RBAC, sessions, MFA | 2 days | B-208, B-109 |
| B-214 | Transport SDK (TypeScript) | E2EE, downgrade detection | 1 day | B-208, B-110 |
| B-215 | SDK Integration Tests (Python) | End-to-end SDK test suite | 2 days | B-202 through B-207 |
| B-216 | SDK Integration Tests (TypeScript) | End-to-end SDK test suite | 2 days | B-209 through B-214 |

**Phase 2 Total: ~22 days**

### Phase 3: Vertical Templates & Documentation

Build pre-configured verticals and comprehensive documentation.

| ID | Deliverable | Description | Est. Effort | Dependencies |
|----|-------------|-------------|-------------|--------------|
| B-301 | Healthcare Template | Extract from InFill: silo config, consent flows, E2EE, audit mapping (HIPAA) | 3 days | B-111, B-215, B-216 |
| B-302 | Banking Template | Silo config (Identity, Transaction, Auth), consent flows, PCI-DSS mapping | 3 days | B-111, B-215, B-216 |
| B-303 | Investment Template | Silo config (Identity, Portfolio, Auth), consent flows, SEC/FINRA mapping | 3 days | B-111, B-215, B-216 |
| B-304 | Defense Template | Silo config (Identity, Intelligence, Auth), clearance verification, CMMC mapping | 3 days | B-111, B-215, B-216 |
| B-305 | Developer Portal | Documentation site, API reference, tutorials, code examples | 5 days | B-215, B-216 |
| B-306 | Compliance Kits | HIPAA, SOC 2, PCI-DSS, GLBA, DFARS mapping documents per vertical | 3 days | B-301 through B-304 |
| B-307 | InFill Re-implementation | Re-implement InFill on Bedrock Core + Healthcare Template | 5 days | B-301, B-215, B-216 |
| B-308 | Subscription & Licensing System | License key validation, tier management, usage metering | 3 days | B-111 |
| B-309 | Security Audit (External) | Third-party penetration test and code audit | 5 days | B-111, B-215, B-216 |

**Phase 3 Total: ~33 days**

### Phase 4: Launch & Go-to-Market

| ID | Deliverable | Description | Est. Effort | Dependencies |
|----|-------------|-------------|-------------|--------------|
| B-401 | Landing Page | Bedrock.dev marketing site, value prop, pricing, docs link | 2 days | B-305 |
| B-402 | Demo Environment | Self-service sandbox with pre-configured vertical | 3 days | B-111, B-305 |
| B-403 | Sales Collateral | Technical whitepaper, ROI calculator, competitive analysis | 3 days | B-305, B-306 |
| B-404 | Legal Framework | SDK license agreement, subscription terms, NDA template | 2 days | None |
| B-405 | Beta Program | Invite-only beta with 3-5 design partners, feedback loop | 20 days | B-401, B-402 |
| B-406 | Public Launch | General availability announcement, press, developer conference | 1 day | B-405 |

**Phase 4 Total: ~31 days**

---

## Work Schedule Summary

| Phase | Duration | Key Milestone |
|-------|----------|--------------|
| Phase 1: Foundation | ~24 days | Core runtime passes all integration tests |
| Phase 2: SDK | ~22 days | Python + TypeScript SDKs pass all integration tests |
| Phase 3: Templates & Docs | ~33 days | 4 vertical templates + developer portal + InFill on Bedrock |
| Phase 4: Launch | ~31 days | Public launch with 3-5 beta design partners |
| **Total** | **~110 days** | |

---

## Priority Order (What to Build First)

1. **B-102 Encryption Engine** — The foundation everything depends on
2. **B-103 Key Management** — Must work before any data can be stored
3. **B-104 Data Separation Layer** — Core differentiator
4. **B-105 Identity Fabric: Node Registration** — Can't encrypt between nodes without identities
5. **B-108 Audit Chain** — Compliance requirement for every vertical
6. **B-109 Access Control** — RBAC is table stakes
7. **B-110 Transport Security** — E2EE delivery
8. **B-106/B-107 Attestation & Lifecycle** — Can be built in parallel with above
9. **B-111 Core Integration Tests** — Validates everything works together
10. **SDKs** — Start Python (B-201-B-207), then TypeScript (B-208-B-214)

---

## Risk Register

| Risk | Impact | Likelihood | Mitigation |
|------|--------|-----------|-----------|
| InFill extraction introduces regressions | High | Medium | Phase 1 tests must cover all InFill patterns before generalization |
| Key management UX is too complex | High | High | SDK provides sensible defaults; advanced config is opt-in |
| Performance overhead of per-field encryption | Medium | Medium | Benchmark early; offer column-level vs field-level granularity |
| Vertical templates are too healthcare-specific | Medium | Medium | Design abstraction layer early; banking template validates generality |
| Third-party audit finds vulnerabilities | High | Low | Budget for B-309; fix-before-launch policy |
| Subscription model doesn't resonate | Medium | Medium | Beta program (B-405) validates pricing before launch |

---

*This document is a trade secret of InFill Systems, LLC. Unauthorized distribution is prohibited.*