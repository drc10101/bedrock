# Configuration Guide

Complete reference for CoreConfig options and how they map to compliance requirements.

---

## CoreConfig

The `CoreConfig` class controls all Bedrock behavior. You can use it directly or get pre-configured instances from vertical templates.

```python
from bedrock.config import CoreConfig

# Default configuration
config = CoreConfig()

# From a vertical template
from templates.healthcare import HealthcareTemplate
template = HealthcareTemplate(mode="production")
config = template.get_config()
```

---

## Environment

```python
config.environment = "development"  # or "production"
```

| Mode | Description |
|------|-------------|
| `development` | Self-signed certificates, permissive attestation, relaxed enforcement |
| `production` | CA-signed certificates, strict attestation, full enforcement |

---

## EncryptionConfig

```python
from bedrock.config import EncryptionConfig

config.encryption = EncryptionConfig(
    algorithm="aes-256-gcm",           # AES-256-GCM (default)
    key_derivation="hkdf-sha256",      # HKDF-SHA256 (default)
)
```

| Option | Default | Values | Description |
|--------|---------|--------|-------------|
| `algorithm` | `aes-256-gcm` | `aes-256-gcm` | Encryption algorithm |
| `key_derivation` | `hkdf-sha256` | `hkdf-sha256` | Key derivation function |

**Compliance mapping:**
- AES-256-GCM satisfies HIPAA §164.312(a)(2)(iv), PCI-DSS 3.4, NIST 800-171 §3.13.11
- HKDF-SHA256 satisfies NIST SP 800-56C

---

## IdentityConfig

```python
from bedrock.config import IdentityConfig

config.identity = IdentityConfig(
    require_registration=True,      # Nodes must register before operating
    attestation_policy="strict",    # "strict" or "permissive"
    certificate_ttl_seconds=31536000,  # 1 year
)
```

| Option | Default | Description |
|--------|---------|-------------|
| `require_registration` | `True` | Require node registration before operations |
| `attestation_policy` | `"strict"` | Attestation enforcement level |
| `certificate_ttl_seconds` | `31536000` | Certificate validity period (1 year) |

**Compliance mapping:**
- Strict attestation satisfies CMMC IA.2, NIST 800-171 §3.5
- Certificate TTL supports DFARS audit requirements

---

## DataSeparationConfig

```python
from bedrock.config import DataSeparationConfig

config.data_separation = DataSeparationConfig(
    silo_strict_mode=True,                  # Enforce silo boundaries strictly
    consent_default_ttl_seconds=3600,       # 1 hour default consent
    consent_max_ttl_seconds=86400,          # 24 hours max consent
    consent_require_reason=True,             # Require reason for all consent
)
```

| Option | Default | Description |
|--------|---------|-------------|
| `silo_strict_mode` | `True` | Block cross-silo access without explicit consent |
| `consent_default_ttl_seconds` | `3600` | Default consent time-to-live |
| `consent_max_ttl_seconds` | `86400` | Maximum consent TTL |
| `consent_require_reason` | `True` | Require a reason for every consent request |

**Vertical template defaults:**

| Setting | Healthcare | Banking | Investment | Defense |
|---------|-----------|---------|------------|---------|
| Default TTL | 3600 | 1800 | 300 (trades) | 3600 |
| Max TTL | 86400 | 43200 | 86400 | 28800 |
| Require reason | True | True | True | True |

---

## AuditConfig

```python
from bedrock.config import AuditConfig

config.audit = AuditConfig(
    retention_years=7,              # Audit retention period
    chain_export_format="jsonl",    # Export format: "jsonl" or "csv"
)
```

| Option | Default | Description |
|--------|---------|-------------|
| `retention_years` | `7` | How long to retain audit records |
| `chain_export_format` | `"jsonl"` | Format for audit chain exports |

**Vertical template defaults:**

| Setting | Healthcare | Banking | Investment | Defense |
|---------|-----------|---------|------------|---------|
| Retention | 7 years | 7 years | 6 years | 6 years |

**Compliance mapping:**
- 7 years: HIPAA (6+1), PCI-DSS (1 year + 6 inactive)
- 6 years: SEC 17a-4 (5-6 years), DFARS (6 years)

---

## AccessControlConfig

```python
from bedrock.config import AccessControlConfig

config.access_control = AccessControlConfig(
    mfa_required=True,                       # Require MFA for all access
    session_ttl_seconds=3600,               # 1 hour session
    session_max_ttl_seconds=28800,           # 8 hours max session
    lockout_max_attempts=5,                  # Lock after 5 failed attempts
    lockout_duration_seconds=900,           # 15 minute lockout
    rate_limit_enabled=True,                 # Enable rate limiting
    rate_limit_requests_per_minute=60,       # Max requests per minute
)
```

| Option | Default | Description |
|--------|---------|-------------|
| `mfa_required` | `True` | Require MFA for all access |
| `session_ttl_seconds` | `3600` | Default session time-to-live |
| `session_max_ttl_seconds` | `28800` | Maximum session TTL |
| `lockout_max_attempts` | `5` | Failed login attempts before lockout |
| `lockout_duration_seconds` | `900` | Lockout duration |
| `rate_limit_enabled` | `True` | Enable rate limiting |
| `rate_limit_requests_per_minute` | `60` | Rate limit threshold |

**Vertical template defaults:**

| Setting | Healthcare | Banking | Investment | Defense |
|---------|-----------|---------|------------|---------|
| Session TTL | 3600 | 1800 | 1800 | 1800 |
| Max session | 28800 | 28800 | 28800 | 28800 |
| Lockout attempts | 5 | 3 | 5 | 3 |
| Lockout duration | 900 | 1800 | 900 | 1800 |

**Compliance mapping:**
- MFA required: CMMC IA.1, PCI-DSS 8.3, HIPAA §164.312(d)
- Lockout: PCI-DSS 8.1.6, NIST 800-171 §3.1.8
- Rate limiting: PCI-DSS 6.5, NIST 800-171 §3.13

---

## MeshConfig

```python
from bedrock.config import MeshConfig

config.mesh = MeshConfig(
    healing_threshold=3,                 # Flags before quarantine
    healing_period_seconds=3600,         # Observation period
    max_neighbors=10,                     # Max mesh neighbors
    consensus_required=True,              # Require consensus for healing
)
```

| Option | Default | Description |
|--------|---------|-------------|
| `healing_threshold` | `3` | Flags before transitioning to quarantine |
| `healing_period_seconds` | `3600` | Observation period before healing |
| `max_neighbors` | `10` | Maximum mesh neighbors per node |
| `consensus_required` | `True` | Require mesh consensus for state changes |

---

## LicensingConfig

```python
from bedrock.config import LicensingConfig

config.licensing = LicensingConfig(
    tier="production",     # "developer" or "production"
    dev_mode=False,        # Allow self-signed certificates
)
```

| Tier | Price | Nodes | Certificates | Use Case |
|------|-------|-------|-------------|----------|
| Developer | $99/yr (individual), $499/yr (team) | 3 max | Self-signed | Development and testing |
| Business Runtime | $5K/yr per node | Unlimited | CA-signed | Production deployment |
| Enterprise Runtime | $20K/yr per node | Unlimited | CA-signed + custom CA | Large-scale production |
| Custom | Negotiable | Unlimited | Custom | Special requirements |

**Developer tier limitations:**
- Maximum 3 local nodes
- Self-signed certificates only (no CA signing)
- No production deployment license
- Attestation policy: permissive

**Production tier features:**
- Unlimited nodes (per-node licensing)
- CA-signed certificates
- Full enforcement
- Attestation policy: strict
- Priority support

---

## Quick Reference: Template Defaults

| Config | Default | Healthcare | Banking | Investment | Defense |
|--------|---------|-----------|---------|------------|---------|
| `environment` | development | development/production | development/production | development/production | development/production |
| `silo_strict_mode` | True | True | True | True | True |
| `consent_default_ttl` | 3600 | 3600 | 1800 | 300 | 3600 |
| `consent_max_ttl` | 86400 | 86400 | 43200 | 86400 | 28800 |
| `consent_require_reason` | True | True | True | True | True |
| `audit_retention_years` | 7 | 7 | 7 | 6 | 6 |
| `mfa_required` | True | True | True | True | True |
| `session_ttl` | 3600 | 3600 | 1800 | 1800 | 1800 |
| `session_max_ttl` | 28800 | 28800 | 28800 | 28800 | 28800 |
| `lockout_max_attempts` | 5 | 5 | 3 | 5 | 3 |
| `lockout_duration` | 900 | 900 | 1800 | 900 | 1800 |