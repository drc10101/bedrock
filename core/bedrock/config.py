"""
Bedrock Core Configuration.

Central configuration for all Bedrock components.
Environment-driven with sensible defaults.
"""

import os
from dataclasses import dataclass, field


@dataclass
class EncryptionConfig:
    """Encryption Engine configuration."""

    # Master key source: env var name or file path
    master_key_source: str = "BEDROCK_MASTER_KEY"

    # Key derivation
    hkdf_hash: str = "SHA256"
    hkdf_info_prefix: str = "bedrock"

    # Field-level encryption
    field_cipher: str = "AES-256-GCM"
    field_key_length: int = 32  # 256 bits
    field_iv_length: int = 12  # 96 bits (GCM nonce)
    field_tag_length: int = 16  # 128 bits (GCM tag)

    # E2EE transport
    e2ee_curve: str = "secp256r1"  # P-256
    e2ee_cipher: str = "AES-256-GCM"

    # Database encryption
    db_cipher: str = "AES-256"  # SQLCipher
    db_kdf_iter: int = 64000  # SQLCipher PBKDF2 iterations

    # Version prefix for ciphertext format
    version_prefix: str = "v2:"
    legacy_prefix: str = "v1:"  # Fernet backward compat


@dataclass
class IdentityConfig:
    """Identity Fabric configuration."""

    # Node ID
    node_id_version: int = 7  # UUID v7

    # Attestation
    attestation_required: bool = True
    attestation_hash_algo: str = "SHA256"
    attestation_baseline_path: str = "/etc/bedrock/attestation-baselines"

    # Certificates
    cert_default_ttl_hours: int = 24
    cert_max_ttl_hours: int = 168  # 1 week
    cert_key_type: str = "ed25519"
    cert_ca_cert_path: str = "/etc/bedrock/ca-cert.pem"
    cert_ca_key_path: str = "/etc/bedrock/ca-key.pem"

    # CRL
    crl_path: str = "/etc/bedrock/crl.pem"
    crl_update_interval_seconds: int = 300  # 5 minutes


@dataclass
class DataSeparationConfig:
    """Data Separation Layer configuration."""

    # Anonymous IDs
    anon_id_format: str = "{adjective}-{animal}-{noun}"
    anon_id_word_lists: str = "default"  # or path to custom word list
    anon_id_max_combinations: int = 100_000_000  # 100M+ default (531x375x509)

    # Silo isolation
    silo_strict_mode: bool = True  # Enforce cross-silo consent at query level
    silo_default_encryption: bool = True  # All silos encrypted by default

    # Consent
    consent_default_ttl_seconds: int = 3600  # 1 hour
    consent_max_ttl_seconds: int = 86400  # 24 hours max
    consent_require_reason: bool = True


@dataclass
class AuditConfig:
    """Audit Chain configuration."""

    hash_algo: str = "SHA256"
    retention_years: int = 6
    chain_storage_path: str = "/var/lib/bedrock/audit"
    chain_rotation_size_mb: int = 100  # Rotate chain file at 100MB
    chain_export_format: str = "jsonl"  # jsonl or csv for compliance export


@dataclass
class AccessControlConfig:
    """Access Control configuration."""

    # RBAC
    rbac_enforce: bool = True
    rbac_default_role: str = "denied"  # Explicit deny by default

    # Sessions
    session_ttl_seconds: int = 3600  # 1 hour
    session_max_ttl_seconds: int = 28800  # 8 hours
    session_include_portal_scope: bool = True
    session_include_capability_scope: bool = True

    # MFA
    mfa_required: bool = True
    mfa_totp_digits: int = 6
    mfa_totp_period: int = 30  # seconds
    mfa_recovery_code_count: int = 8

    # Account lockout
    lockout_max_attempts: int = 5
    lockout_duration_seconds: int = 1800  # 30 minutes

    # Rate limiting
    rate_limit_enabled: bool = True
    rate_limit_requests_per_minute: int = 60


@dataclass
class MeshConfig:
    """Self-Healing Mesh configuration."""

    # Detection thresholds
    credential_stuffing_threshold: int = 50  # failed auth attempts
    credential_stuffing_window_seconds: int = 60
    unusual_volume_stddev: float = 3.0  # standard deviations from baseline
    heartbeat_timeout_seconds: int = 30

    # Consensus
    isolation_consensus_required: int = 2  # neighbors needed to isolate

    # Healing
    healing_duration_seconds: int = 3600  # 1 hour default
    healing_restricted_routing: bool = True  # relay only, no decrypt

    # Topology
    topology_type: str = "partial_mesh"  # full_mesh, partial_mesh, hub_spoke
    min_alternate_routes: int = 1  # every path has at least 1 alternate


@dataclass
class LicensingConfig:
    """Licensing configuration."""

    # License tiers
    tier: str = "developer"  # developer, starter, business, enterprise

    # Developer mode limits
    dev_mode: bool = True  # True = localhost only, self-signed certs
    dev_max_nodes: int = 3

    # Runtime mode (production)
    runtime_licensed_nodes: int = 0  # 0 = unlimited (enterprise), or per-tier limit
    runtime_ca_activated: bool = False  # True = production CA operational

    # License key (offline validation)
    license_key_path: str = "/etc/bedrock/license.key"

    # No phone-home
    phone_home_enabled: bool = False
    phone_home_url: str = ""  # Empty = no telemetry


@dataclass
class CoreConfig:
    """Top-level Bedrock Core configuration."""

    environment: str = "development"  # development, staging, production
    debug: bool = False
    log_level: str = "INFO"
    log_format: str = "json"  # json or text

    # Sub-configurations
    encryption: EncryptionConfig = field(default_factory=EncryptionConfig)
    identity: IdentityConfig = field(default_factory=IdentityConfig)
    data_separation: DataSeparationConfig = field(default_factory=DataSeparationConfig)
    audit: AuditConfig = field(default_factory=AuditConfig)
    access_control: AccessControlConfig = field(default_factory=AccessControlConfig)
    mesh: MeshConfig = field(default_factory=MeshConfig)
    licensing: LicensingConfig = field(default_factory=LicensingConfig)

    @classmethod
    def from_env(cls) -> "CoreConfig":
        """Load configuration from environment variables."""
        config = cls()
        config.environment = os.environ.get("BEDROCK_ENV", "development")
        config.debug = os.environ.get("BEDROCK_DEBUG", "false").lower() == "true"
        config.log_level = os.environ.get("BEDROCK_LOG_LEVEL", "INFO")

        # Licensing from env
        config.licensing.dev_mode = os.environ.get("BEDROCK_DEV_MODE", "true").lower() == "true"
        config.licensing.tier = os.environ.get("BEDROCK_TIER", "developer")

        return config
