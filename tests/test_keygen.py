"""
Tests for LicenseKeygen — key generation, signing, rotation, revocation, and validation.
"""

import json
import time
import unittest

import sys
sys.path.insert(0, "core")

from bedrock.licensing.keygen import LicenseKeygen, SigningKey
from bedrock.licensing.enforcement import (
    License,
    LicenseEnforcer,
    LicenseTier,
    LicenseValidationError,
    LicenseExpiredError,
    NODE_LIMITS,
    TIER_FEATURES,
)


class TestSigningKey(unittest.TestCase):
    """Test SigningKey creation, serialization, and revocation."""

    def test_create_signing_key(self):
        """SigningKey stores key material and metadata."""
        key = SigningKey(key_id="test-01", key_material=b"secret-key-bytes")
        assert key.key_id == "test-01"
        assert key.key_material == b"secret-key-bytes"
        assert key.algorithm == "HMAC-SHA256"
        assert key.revoked is False
        assert key.is_active is True

    def test_create_with_auto_timestamp(self):
        """SigningKey auto-sets created_at."""
        before = time.time()
        key = SigningKey(key_id="test", key_material=b"x")
        after = time.time()
        assert before <= key.created_at <= after

    def test_revoke_key(self):
        """Revoking a key marks it inactive."""
        key = SigningKey(key_id="test", key_material=b"x")
        assert key.is_active is True
        key.revoke(reason="Compromised")
        assert key.revoked is True
        assert key.is_active is False
        assert key.revocation_reason == "Compromised"

    def test_string_key_material(self):
        """SigningKey converts string key_material to bytes."""
        key = SigningKey(key_id="test", key_material="ascii-key-material")
        assert key.key_material == b"ascii-key-material"

    def test_serialization_roundtrip(self):
        """SigningKey serializes to dict and deserializes back."""
        original = SigningKey(key_id="key-01", key_material=b"test-bytes-1234")
        data = original.to_dict()
        assert data["key_id"] == "key-01"
        assert "key_material_b64" in data
        assert data["revoked"] is False

        restored = SigningKey.from_dict(data)
        assert restored.key_id == original.key_id
        assert restored.key_material == original.key_material
        assert restored.created_at == original.created_at
        assert restored.algorithm == original.algorithm

    def test_serialization_revoked_key(self):
        """Revoked key preserves revocation info through serialization."""
        key = SigningKey(key_id="rev-01", key_material=b"x")
        key.revoke("Security breach")
        data = key.to_dict()
        assert data["revoked"] is True
        assert data["revocation_reason"] == "Security breach"

        restored = SigningKey.from_dict(data)
        assert restored.revoked is True
        assert restored.revocation_reason == "Security breach"


class TestLicenseKeygenKeyManagement(unittest.TestCase):
    """Test key generation, listing, revocation, and rotation."""

    def setUp(self):
        self.keygen = LicenseKeygen()

    def test_generate_signing_key(self):
        """Generate a signing key with auto-generated key_id."""
        key = self.keygen.generate_signing_key()
        assert key.key_id.startswith("bedrock-")
        assert len(key.key_material) == 32  # 256-bit random
        assert key.is_active is True

    def test_generate_signing_key_with_id(self):
        """Generate a signing key with a specific key_id."""
        key = self.keygen.generate_signing_key(key_id="production-2026-01")
        assert key.key_id == "production-2026-01"

    def test_generate_signing_key_with_material(self):
        """Generate a signing key with specific key material."""
        material = b"deterministic-key-material-for-testing"
        key = self.keygen.generate_signing_key(key_id="test", key_material=material)
        assert key.key_material == material

    def test_get_key(self):
        """Retrieve a key by ID."""
        key = self.keygen.generate_signing_key(key_id="lookup-test")
        retrieved = self.keygen.get_key("lookup-test")
        assert retrieved is key

    def test_get_nonexistent_key(self):
        """Getting a nonexistent key returns None."""
        assert self.keygen.get_key("does-not-exist") is None

    def test_list_keys(self):
        """List all active keys."""
        self.keygen.generate_signing_key(key_id="k1")
        self.keygen.generate_signing_key(key_id="k2")
        keys = self.keygen.list_keys(active_only=True)
        assert len(keys) == 2

    def test_list_keys_excludes_revoked(self):
        """list_keys with active_only excludes revoked keys."""
        key = self.keygen.generate_signing_key(key_id="active")
        revoked = self.keygen.generate_signing_key(key_id="revoked")
        self.keygen.revoke_key("revoked", "test")
        active = self.keygen.list_keys(active_only=True)
        assert len(active) == 1
        assert active[0].key_id == "active"

    def test_list_keys_includes_revoked(self):
        """list_keys with active_only=False includes revoked keys."""
        self.keygen.generate_signing_key(key_id="active")
        self.keygen.generate_signing_key(key_id="revoked")
        self.keygen.revoke_key("revoked", "test")
        all_keys = self.keygen.list_keys(active_only=False)
        assert len(all_keys) == 2

    def test_revoke_key(self):
        """Revoke a signing key by ID."""
        self.keygen.generate_signing_key(key_id="to-revoke")
        result = self.keygen.revoke_key("to-revoke", "Compromised")
        assert result is True
        key = self.keygen.get_key("to-revoke")
        assert key.revoked is True

    def test_revoke_nonexistent_key(self):
        """Revoking a nonexistent key returns False."""
        result = self.keygen.revoke_key("ghost", "no such key")
        assert result is False

    def test_rotate_key(self):
        """Key rotation revokes old key and creates new one."""
        self.keygen.generate_signing_key(key_id="bedrock-2026-01")
        old_key, new_key = self.keygen.rotate_key("bedrock-2026-01")
        assert old_key.revoked is True
        assert old_key.key_id == "bedrock-2026-01"
        assert new_key.key_id == "bedrock-2026-02"
        assert new_key.is_active is True

    def test_rotate_key_auto_increments(self):
        """Rotation auto-increments the key version number."""
        self.keygen.generate_signing_key(key_id="prod-01")
        old, new = self.keygen.rotate_key("prod-01")
        assert new.key_id == "prod-02"

    def test_rotate_nonexistent_key(self):
        """Rotating a nonexistent key returns None."""
        result = self.keygen.rotate_key("ghost")
        assert result is None

    def test_rotate_with_custom_new_id(self):
        """Rotation accepts a custom new key ID."""
        self.keygen.generate_signing_key(key_id="old-key")
        old, new = self.keygen.rotate_key("old-key", new_key_id="brand-new-key")
        assert new.key_id == "brand-new-key"


class TestLicenseKeygenIssueLicense(unittest.TestCase):
    """Test license key issuance."""

    def setUp(self):
        self.keygen = LicenseKeygen()
        self.key = self.keygen.generate_signing_key(key_id="test-key-01")

    def test_issue_developer_license(self):
        """Issue a developer-tier license key."""
        license_key = self.keygen.issue_license(
            key=self.key,
            tier=LicenseTier.DEVELOPER,
            issued_to="Test Dev",
        )
        assert isinstance(license_key, str)
        parts = license_key.split(":")
        assert len(parts) == 3
        assert parts[0] == "1"  # version

    def test_issue_business_license(self):
        """Issue a business-tier license key."""
        license_key = self.keygen.issue_license(
            key=self.key,
            tier=LicenseTier.BUSINESS,
            issued_to="Acme Corp",
        )
        assert isinstance(license_key, str)

    def test_issue_enterprise_license(self):
        """Issue an enterprise-tier license key."""
        license_key = self.keygen.issue_license(
            key=self.key,
            tier=LicenseTier.ENTERPRISE,
            issued_to="Mega Corp",
        )
        assert isinstance(license_key, str)

    def test_issue_license_with_expiration(self):
        """Issue a license that expires in N days."""
        license_key = self.keygen.issue_license(
            key=self.key,
            tier=LicenseTier.STARTER,
            issued_to="Test Co",
            expires_days=365,
        )
        assert isinstance(license_key, str)

    def test_issue_license_with_revoked_key_raises(self):
        """Issuing a license with a revoked key raises ValueError."""
        self.key.revoke("test")
        with self.assertRaises(ValueError) as ctx:
            self.keygen.issue_license(key=self.key, tier=LicenseTier.DEVELOPER)
        assert "revoked" in str(ctx.exception).lower()

    def test_issue_license_string_tier(self):
        """Issue license with string tier instead of enum."""
        license_key = self.keygen.issue_license(
            key=self.key,
            tier="developer",
            issued_to="String Tier Dev",
        )
        assert isinstance(license_key, str)

    def test_license_key_contains_payload(self):
        """License key payload decodes to valid JSON."""
        import base64
        license_key = self.keygen.issue_license(
            key=self.key,
            tier=LicenseTier.STARTER,
            issued_to="Payload Test",
        )
        _, payload_b64, _ = license_key.split(":")
        payload_json = base64.urlsafe_b64decode(payload_b64).decode()
        payload = json.loads(payload_json)
        assert payload["tier"] == "starter"
        assert payload["issued_to"] == "Payload Test"
        assert payload["key_id"] == "test-key-01"
        assert payload["dev_mode"] is False

    def test_issue_developer_license_dev_mode_true(self):
        """Developer tier license has dev_mode=True in payload."""
        import base64
        license_key = self.keygen.issue_license(
            key=self.key,
            tier=LicenseTier.DEVELOPER,
            issued_to="Dev Mode Test",
        )
        _, payload_b64, _ = license_key.split(":")
        payload = json.loads(base64.urlsafe_b64decode(payload_b64).decode())
        assert payload["dev_mode"] is True


class TestLicenseKeygenValidation(unittest.TestCase):
    """Test license key validation with keygen."""

    def setUp(self):
        self.keygen = LicenseKeygen()
        self.key = self.keygen.generate_signing_key(key_id="validation-key")

    def test_validate_issued_license(self):
        """A license issued by keygen validates successfully."""
        license_key = self.keygen.issue_license(
            key=self.key,
            tier=LicenseTier.BUSINESS,
            issued_to="Validation Corp",
        )
        license_obj = self.keygen.validate_license(license_key)
        assert isinstance(license_obj, License)
        assert license_obj.tier == LicenseTier.BUSINESS
        assert license_obj.issued_to == "Validation Corp"
        assert license_obj.is_valid is True

    def test_validate_all_tiers(self):
        """Licenses for all tiers validate correctly."""
        for tier in LicenseTier:
            license_key = self.keygen.issue_license(
                key=self.key,
                tier=tier,
                issued_to=f"Test {tier.value}",
            )
            license_obj = self.keygen.validate_license(license_key)
            assert license_obj.tier == tier

    def test_validate_tampered_payload(self):
        """A license with tampered payload fails validation."""
        import base64
        license_key = self.keygen.issue_license(
            key=self.key,
            tier=LicenseTier.BUSINESS,
            issued_to="Honest Co",
        )
        # Tamper with the payload
        version, payload_b64, signature_b64 = license_key.split(":")
        payload_json = base64.urlsafe_b64decode(payload_b64).decode()
        payload = json.loads(payload_json)
        payload["tier"] = "enterprise"  # Upgrade attempt
        tampered_json = json.dumps(payload, separators=(",", ":"), sort_keys=True)
        tampered_b64 = base64.urlsafe_b64encode(tampered_json.encode()).decode()
        tampered_key = f"{version}:{tampered_b64}:{signature_b64}"

        with self.assertRaises(LicenseValidationError):
            self.keygen.validate_license(tampered_key)

    def test_validate_empty_key_raises(self):
        """Empty license key raises validation error."""
        with self.assertRaises(LicenseValidationError):
            self.keygen.validate_license("")

    def test_validate_malformed_key_raises(self):
        """Malformed license key raises validation error."""
        with self.assertRaises(LicenseValidationError):
            self.keygen.validate_license("not-a-valid-key")

    def test_validate_expired_license_raises(self):
        """An expired license raises LicenseExpiredError."""
        license_key = self.keygen.issue_license(
            key=self.key,
            tier=LicenseTier.DEVELOPER,
            issued_to="Expired Corp",
            expires_days=-1,  # Already expired
        )
        with self.assertRaises(LicenseExpiredError):
            self.keygen.validate_license(license_key)

    def test_validate_with_wrong_key_raises(self):
        """License signed with one key fails validation against a different keygen."""
        other_keygen = LicenseKeygen()
        # other_keygen has no keys, so validation should fail
        license_key = self.keygen.issue_license(
            key=self.key,
            tier=LicenseTier.STARTER,
            issued_to="Wrong Key Co",
        )
        with self.assertRaises(LicenseValidationError):
            other_keygen.validate_license(license_key)

    def test_validate_with_revoked_signing_key_raises(self):
        """License signed with a revoked key fails validation."""
        license_key = self.keygen.issue_license(
            key=self.key,
            tier=LicenseTier.STARTER,
            issued_to="Revoked Key Co",
        )
        self.keygen.revoke_key("validation-key", "compromised")
        # After revocation, the key is excluded from active keys
        # Need a second key to try validation against (none left = error)
        with self.assertRaises(LicenseValidationError):
            self.keygen.validate_license(license_key)

    def test_validate_license_features(self):
        """Validated license includes correct features for tier."""
        license_key = self.keygen.issue_license(
            key=self.key,
            tier=LicenseTier.BUSINESS,
            issued_to="Features Corp",
        )
        license_obj = self.keygen.validate_license(license_key)
        assert "ca_signed_certs" in license_obj.features
        assert "self_healing_mesh" in license_obj.features
        assert "compliance_reports" in license_obj.features


class TestLicenseKeygenRotation(unittest.TestCase):
    """Test key rotation and re-signing."""

    def setUp(self):
        self.keygen = LicenseKeygen()
        self.key = self.keygen.generate_signing_key(key_id="rotate-01")

    def test_re_sign_license(self):
        """Re-sign a license with a new key."""
        new_key = self.keygen.generate_signing_key(key_id="rotate-02")
        license_key = self.keygen.issue_license(
            key=self.key,
            tier=LicenseTier.STARTER,
            issued_to="Rotation Test",
        )
        re_signed = self.keygen.re_sign_license(license_key, new_key)
        # The re-signed license should validate
        license_obj = self.keygen.validate_license(re_signed)
        assert license_obj.issued_to == "Rotation Test"
        assert license_obj.tier == LicenseTier.STARTER

    def test_re_sign_updates_key_id(self):
        """Re-signing updates the key_id in the payload."""
        import base64
        new_key = self.keygen.generate_signing_key(key_id="new-key-02")
        license_key = self.keygen.issue_license(
            key=self.key,
            tier=LicenseTier.BUSINESS,
            issued_to="Key Update Test",
        )
        re_signed = self.keygen.re_sign_license(license_key, new_key)
        _, payload_b64, _ = re_signed.split(":")
        payload = json.loads(base64.urlsafe_b64decode(payload_b64).decode())
        assert payload["key_id"] == "new-key-02"

    def test_re_sign_with_revoked_key_raises(self):
        """Re-signing with a revoked key raises ValueError."""
        new_key = self.keygen.generate_signing_key(key_id="revoked-new")
        new_key.revoke("test")
        license_key = self.keygen.issue_license(
            key=self.key,
            tier=LicenseTier.STARTER,
            issued_to="Revoked Re-sign",
        )
        with self.assertRaises(ValueError):
            self.keygen.re_sign_license(license_key, new_key)

    def test_full_rotation_workflow(self):
        """Complete rotation workflow: issue -> rotate -> re-sign -> validate."""
        # Issue original license
        original_key = self.keygen.issue_license(
            key=self.key,
            tier=LicenseTier.BUSINESS,
            issued_to="Full Rotation Corp",
            expires_days=365,
        )
        # Rotate the signing key
        old_key, new_key = self.keygen.rotate_key("rotate-01")
        assert old_key.revoked is True
        assert new_key.key_id == "rotate-02"
        # Re-sign the license with new key
        re_signed = self.keygen.re_sign_license(original_key, new_key)
        # Validate the re-signed license
        license_obj = self.keygen.validate_license(re_signed)
        assert license_obj.tier == LicenseTier.BUSINESS
        assert license_obj.issued_to == "Full Rotation Corp"
        assert license_obj.is_valid is True


class TestLicenseKeygenExportImport(unittest.TestCase):
    """Test key export and import for backup/restore."""

    def setUp(self):
        self.keygen = LicenseKeygen()

    def test_export_keys(self):
        """Export signing keys as JSON."""
        self.keygen.generate_signing_key(key_id="export-01")
        self.keygen.generate_signing_key(key_id="export-02")
        exported = self.keygen.export_keys()
        data = json.loads(exported)
        assert "keys" in data
        assert "exported_at" in data
        assert len(data["keys"]) == 2

    def test_import_keys(self):
        """Import signing keys from JSON backup."""
        self.keygen.generate_signing_key(key_id="import-01")
        exported = self.keygen.export_keys()

        new_keygen = LicenseKeygen()
        count = new_keygen.import_keys(exported)
        assert count == 1
        key = new_keygen.get_key("import-01")
        assert key is not None

    def test_roundtrip_preserves_key_material(self):
        """Export + import preserves key material exactly."""
        original = self.keygen.generate_signing_key(
            key_id="roundtrip",
            key_material=b"exact-key-material-bytes",
        )
        exported = self.keygen.export_keys()

        new_keygen = LicenseKeygen()
        new_keygen.import_keys(exported)
        restored = new_keygen.get_key("roundtrip")
        assert restored.key_material == original.key_material

    def test_roundtrip_preserves_revocation(self):
        """Export + import preserves revoked key status."""
        key = self.keygen.generate_signing_key(key_id="rev-export")
        self.keygen.revoke_key("rev-export", "security incident")
        exported = self.keygen.export_keys()

        new_keygen = LicenseKeygen()
        new_keygen.import_keys(exported)
        restored = new_keygen.get_key("rev-export")
        assert restored.revoked is True
        assert restored.revocation_reason == "security incident"


class TestLicenseKeygenBatchIssue(unittest.TestCase):
    """Test batch license issuance."""

    def setUp(self):
        self.keygen = LicenseKeygen()
        self.key = self.keygen.generate_signing_key(key_id="batch-key")

    def test_batch_issue(self):
        """Issue multiple licenses at once."""
        keys = self.keygen.batch_issue(
            key=self.key,
            tier=LicenseTier.DEVELOPER,
            count=5,
            issued_to="Batch Dev",
            expires_days=365,
        )
        assert len(keys) == 5
        # All should be valid and unique
        for license_key in keys:
            license_obj = self.keygen.validate_license(license_key)
            assert license_obj.tier == LicenseTier.DEVELOPER
        # Should be unique
        assert len(set(keys)) == 5

    def test_batch_issue_single(self):
        """Batch issue with count=1 works."""
        keys = self.keygen.batch_issue(
            key=self.key,
            tier=LicenseTier.STARTER,
            count=1,
            issued_to="Single Batch",
        )
        assert len(keys) == 1

    def test_batch_issue_with_prefix(self):
        """Batch issue with prefix for issued_to."""
        keys = self.keygen.batch_issue(
            key=self.key,
            tier=LicenseTier.DEVELOPER,
            count=3,
            issued_to="Team",
            prefix="Acme Corp - ",
        )
        for license_key in keys:
            license_obj = self.keygen.validate_license(license_key)
            assert license_obj.issued_to.startswith("Acme Corp - ")


class TestLicenseKeygenNodeLimits(unittest.TestCase):
    """Test that license node limits match tier expectations."""

    def setUp(self):
        self.keygen = LicenseKeygen()
        self.key = self.keygen.generate_signing_key(key_id="limits-key")

    def test_developer_node_limit(self):
        """Developer license has 3-node limit."""
        license_key = self.keygen.issue_license(
            key=self.key, tier=LicenseTier.DEVELOPER, issued_to="Dev"
        )
        license_obj = self.keygen.validate_license(license_key)
        assert license_obj.max_nodes == 3

    def test_starter_node_limit(self):
        """Starter license has 5-node limit."""
        license_key = self.keygen.issue_license(
            key=self.key, tier=LicenseTier.STARTER, issued_to="Starter"
        )
        license_obj = self.keygen.validate_license(license_key)
        assert license_obj.max_nodes == 5

    def test_business_node_limit(self):
        """Business license has 25-node limit."""
        license_key = self.keygen.issue_license(
            key=self.key, tier=LicenseTier.BUSINESS, issued_to="Biz"
        )
        license_obj = self.keygen.validate_license(license_key)
        assert license_obj.max_nodes == 25

    def test_enterprise_unlimited_nodes(self):
        """Enterprise license has unlimited nodes (inf)."""
        license_key = self.keygen.issue_license(
            key=self.key, tier=LicenseTier.ENTERPRISE, issued_to="Ent"
        )
        license_obj = self.keygen.validate_license(license_key)
        assert license_obj.max_nodes == float("inf")

    def test_custom_node_limit(self):
        """Custom node limit overrides tier default."""
        license_key = self.keygen.issue_license(
            key=self.key, tier=LicenseTier.STARTER, issued_to="Custom",
            max_nodes=10,
        )
        license_obj = self.keygen.validate_license(license_key)
        assert license_obj.max_nodes == 10


if __name__ == "__main__":
    unittest.main()