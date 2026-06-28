# Changelog

All notable changes to Bedrock are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [0.3.0] - 2026-06-27

### Added
- **CLI** (`bedrock`): init, serve, keygen, license issue/validate/revoke/info, health, status
- **Usage Metering**: per-tier rate limiting (developer 60/min through enterprise 2000/min), monthly caps
- **Usage API**: `GET /api/v1/usage` endpoint with `X-RateLimit-*` response headers
- **Developer Onboarding**: `bedrock init` scaffolds project, generates master key and signing key
- **Stripe Integration**: product and pricing constants for developer license tiers
- **Console Script**: `bedrock` entry point via pyproject.toml

### Changed
- Server restructured as package (`server/app.py`) for extensibility
- License validation in CLI catches `LicenseValidationError` gracefully
- Burst throttle now correctly counts throttled requests toward rate limits
- Version bumped to 0.3.0

## [0.2.0] - 2026-06-27

### Added
- **HTTPS/TLS Termination**: `TLSConfig`, self-signed cert generation, server wrapping
- **SQLite Opt-in Storage**: encrypted-at-rest storage backend
- **PBKDF2-HMAC-SHA256 Key Derivation**: for production key generation
- **Usage Metering Module**: `UsageMeter`, `TierRateLimits`, `RateLimitResult`

### Changed
- TLS is opt-in in tests via `TLSConfig(enabled=False)`
- Fixed concurrent write race condition in SQLite storage tests

## [0.1.0] - 2026-06-26

### Added
- **Encryption Engine**: field-level AES-256-GCM encryption, E2EE delivery, AAD, ciphertext versioning
- **Key Management**: HKDF key hierarchy, master key derivation, silo-scoped keys
- **Data Separation**: silos, anonymous IDs (adjective-animal-noun), consent-gated cross-silo access
- **Identity Fabric**: nodes, attestation, CA-enforced certificates, capabilities/scopes
- **Audit Chain**: SHA-256 hash chain, tamper-evident audit entries
- **Access Control**: RBAC, sessions, MFA enforcement
- **Transport Security**: TLS, E2EE transport, downgrade detection
- **Self-Healing Mesh**: 5-state lifecycle, attack detection, scope-aware routing
- **License Enforcement**: two-tier licensing, offline key validation
- **REST API Server**: FastAPI + uvicorn with all endpoints
- **Python SDK**: full client library
- **TypeScript SDK**: full client library
- **Docker Deployment**: Dockerfile + docker-compose.yml
- **CI Pipeline**: GitHub Actions (Python 3.12/3.13/3.14, Node 20, security scan)
- **Health Checker**: subsystem health verification