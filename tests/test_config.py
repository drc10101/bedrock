"""Tests for Bedrock Configuration."""

import os
from bedrock.config import (
    CoreConfig,
    EncryptionConfig,
    IdentityConfig,
    MeshConfig,
    LicensingConfig,
)


class TestCoreConfig:
    """Test CoreConfig defaults and environment loading."""

    def test_default_config(self):
        config = CoreConfig()
        assert config.environment == "development"
        assert config.debug is False
        assert config.log_level == "INFO"

    def test_default_encryption_config(self):
        config = EncryptionConfig()
        assert config.field_cipher == "AES-256-GCM"
        assert config.e2ee_curve == "secp256r1"
        assert config.version_prefix == "v2:"

    def test_default_mesh_config(self):
        config = MeshConfig()
        assert config.credential_stuffing_threshold == 50
        assert config.isolation_consensus_required == 2
        assert config.healing_duration_seconds == 3600

    def test_default_licensing_config(self):
        config = LicensingConfig()
        assert config.tier == "developer"
        assert config.dev_mode is True
        assert config.dev_max_nodes == 3

    def test_from_env_defaults(self):
        config = CoreConfig.from_env()
        assert config.environment == "development"
        assert config.licensing.dev_mode is True

    def test_from_env_override(self):
        os.environ["BEDROCK_ENV"] = "production"
        os.environ["BEDROCK_TIER"] = "business"
        try:
            config = CoreConfig.from_env()
            assert config.environment == "production"
            assert config.licensing.tier == "business"
        finally:
            del os.environ["BEDROCK_ENV"]
            del os.environ["BEDROCK_TIER"]