"""
Tests for the Bedrock Licensing & Enforcement System.

Validates license key generation, validation, enforcement, tier features,
upgrade paths, and error handling.
"""

import json
import base64
import hmac
import hashlib
import time
import tempfile
import os

import pytest

from bedrock.licensing.enforcement import (
    LicenseEnforcer,
    License,
    LicenseTier,
    LicenseValidationError,
    LicenseExpiredError,
    LicenseLimitError,
    NODE_LIMITS,
    TIER_PRICING,
    TIER_FEATURES,
)


# ── Fixtures ──

@pytest.fixture
def enforcer():
    """Create a LicenseEnforcer with the default signing key."""
    return LicenseEnforcer()


@pytest.fixture
def dev_key(enforcer):
    """Generate a valid developer license key."""
    return enforcer.generate_license_key(
        tier=LicenseTier.DEVELOPER,
        issued_to="Test Developer",
        max_devs=1,
    )


@pytest.fixture
def starter_key(enforcer):
    """Generate a valid starter license key."""
    return enforcer.generate_license_key(
        tier=LicenseTier.STARTER,
        issued_to="Test Startup",
    )


@pytest.fixture
def business_key(enforcer):
    """Generate a valid business license key."""
    return enforcer.generate_license_key(
        tier=LicenseTier.BUSINESS,
        issued_to="Test Corp",
    )


@pytest.fixture
def enterprise_key(enforcer):
    """Generate a valid enterprise license key."""
    return enforcer.generate_license_key(
        tier=LicenseTier.ENTERPRISE,
        issued_to="Test Enterprise",
    )


# ── License Key Generation ──

class TestLicenseKeyGeneration:
    """Test license key generation."""

    def test_generate_developer_key(self, enforcer):
        key = enforcer.generate_license_key(
            tier=LicenseTier.DEVELOPER,
            issued_to="Dev User",
        )
        assert key is not None
        assert isinstance(key, str)
        # Format: version:payload:signature
        parts = key.split(":")
        assert len(parts) == 3
        assert parts[0] == "1"

    def test_generate_starter_key(self, enforcer):
        key = enforcer.generate_license_key(
            tier=LicenseTier.STARTER,
            issued_to="Startup Inc",
        )
        parts = key.split(":")
        assert len(parts) == 3

    def test_generate_business_key(self, enforcer):
        key = enforcer.generate_license_key(
            tier=LicenseTier.BUSINESS,
            issued_to="Business Corp",
        )
        parts = key.split(":")
        assert len(parts) == 3

    def test_generate_enterprise_key(self, enforcer):
        key = enforcer.generate_license_key(
            tier=LicenseTier.ENTERPRISE,
            issued_to="Enterprise Ltd",
        )
        parts = key.split(":")
        assert len(parts) == 3

    def test_generate_key_with_expiry(self, enforcer):
        expires = time.time() + 365 * 86400  # 1 year from now
        key = enforcer.generate_license_key(
            tier=LicenseTier.BUSINESS,
            issued_to="Expiring Corp",
            expires_at=expires,
        )
        assert key is not None

    def test_generate_key_custom_max_nodes(self, enforcer):
        key = enforcer.generate_license_key(
            tier=LicenseTier.BUSINESS,
            issued_to="Custom Nodes Corp",
            max_nodes=50,
        )
        license = enforcer.validate_license(key)
        assert license.max_nodes == 50

    def test_generate_key_custom_features(self, enforcer):
        custom_features = ["ca_signed_certs", "custom_feature"]
        key = enforcer.generate_license_key(
            tier=LicenseTier.ENTERPRISE,
            issued_to="Custom Features Corp",
            features=custom_features,
        )
        license = enforcer.validate_license(key)
        assert "custom_feature" in license.features

    def test_generated_key_payload_contains_tier(self, enforcer):
        key = enforcer.generate_license_key(
            tier=LicenseTier.BUSINESS,
            issued_to="Payload Test",
        )
        parts = key.split(":")
        payload_json = base64.urlsafe_b64decode(parts[1]).decode()
        payload = json.loads(payload_json)
        assert payload["tier"] == "business"

    def test_generated_key_payload_contains_issued_to(self, enforcer):
        key = enforcer.generate_license_key(
            tier=LicenseTier.STARTER,
            issued_to="Named Corp",
        )
        parts = key.split(":")
        payload_json = base64.urlsafe_b64decode(parts[1]).decode()
        payload = json.loads(payload_json)
        assert payload["issued_to"] == "Named Corp"


# ── License Validation ──

class TestLicenseValidation:
    """Test license key validation."""

    def test_validate_developer_key(self, enforcer, dev_key):
        license = enforcer.validate_license(dev_key)
        assert license.tier == LicenseTier.DEVELOPER
        assert license.is_developer is True
        assert license.is_runtime is False
        assert license.dev_mode is True

    def test_validate_starter_key(self, enforcer, starter_key):
        license = enforcer.validate_license(starter_key)
        assert license.tier == LicenseTier.STARTER
        assert license.is_developer is False
        assert license.is_runtime is True
        assert license.dev_mode is False

    def test_validate_business_key(self, enforcer, business_key):
        license = enforcer.validate_license(business_key)
        assert license.tier == LicenseTier.BUSINESS
        assert license.is_developer is False
        assert license.is_runtime is True

    def test_validate_enterprise_key(self, enforcer, enterprise_key):
        license = enforcer.validate_license(enterprise_key)
        assert license.tier == LicenseTier.ENTERPRISE
        assert license.is_developer is False
        assert license.is_runtime is True

    def test_validate_extracts_issued_to(self, enforcer):
        key = enforcer.generate_license_key(
            tier=LicenseTier.BUSINESS,
            issued_to="Acme Corp",
        )
        license = enforcer.validate_license(key)
        assert license.issued_to == "Acme Corp"

    def test_validate_extracts_max_nodes(self, enforcer):
        key = enforcer.generate_license_key(
            tier=LicenseTier.STARTER,
            issued_to="Test",
        )
        license = enforcer.validate_license(key)
        assert license.max_nodes == 5

    def test_validate_enterprise_max_nodes_unlimited(self, enforcer, enterprise_key):
        license = enforcer.validate_license(enterprise_key)
        assert license.max_nodes == float("inf")

    def test_validate_round_trip(self, enforcer):
        """Generate and validate should produce consistent results."""
        key = enforcer.generate_license_key(
            tier=LicenseTier.BUSINESS,
            issued_to="Round Trip Corp",
        )
        license = enforcer.validate_license(key)
        assert license.tier == LicenseTier.BUSINESS
        assert license.issued_to == "Round Trip Corp"
        assert license.is_runtime is True


# ── Invalid License Handling ──

class TestInvalidLicenseHandling:
    """Test handling of invalid or tampered license keys."""

    def test_empty_key_raises_error(self, enforcer):
        with pytest.raises(LicenseValidationError, match="Empty license key"):
            enforcer.validate_license("")

    def test_invalid_format_raises_error(self, enforcer):
        with pytest.raises(LicenseValidationError, match="Invalid license key format"):
            enforcer.validate_license("invalid-key")

    def test_wrong_version_raises_error(self, enforcer):
        key = enforcer.generate_license_key(tier=LicenseTier.DEVELOPER)
        # Tamper with version
        parts = key.split(":")
        tampered = "2:" + parts[1] + ":" + parts[2]
        with pytest.raises(LicenseValidationError, match="Unsupported license key version"):
            enforcer.validate_license(tampered)

    def test_tampered_payload_raises_error(self, enforcer):
        key = enforcer.generate_license_key(tier=LicenseTier.BUSINESS)
        parts = key.split(":")
        # Decode payload, modify tier, re-encode
        payload_json = base64.urlsafe_b64decode(parts[1]).decode()
        payload = json.loads(payload_json)
        payload["tier"] = "enterprise"  # Upgrade without authorization
        tampered_payload = base64.urlsafe_b64encode(
            json.dumps(payload, separators=(",", ":"), sort_keys=True).encode()
        ).decode()
        tampered_key = f"1:{tampered_payload}:{parts[2]}"
        with pytest.raises(LicenseValidationError, match="Invalid license key signature"):
            enforcer.validate_license(tampered_key)

    def test_tampered_signature_raises_error(self, enforcer):
        key = enforcer.generate_license_key(tier=LicenseTier.BUSINESS)
        parts = key.split(":")
        tampered_sig = base64.urlsafe_b64encode(b"0" * 64).decode()
        tampered_key = f"1:{parts[1]}:{tampered_sig}"
        with pytest.raises(LicenseValidationError, match="Invalid license key signature"):
            enforcer.validate_license(tampered_key)

    def test_corrupt_payload_raises_error(self, enforcer):
        corrupt_payload = base64.urlsafe_b64encode(b"not-json").decode()
        corrupt_sig = base64.urlsafe_b64encode(b"not-a-sig").decode()
        corrupt_key = f"1:{corrupt_payload}:{corrupt_sig}"
        with pytest.raises(LicenseValidationError):
            enforcer.validate_license(corrupt_key)

    def test_invalid_tier_raises_error(self, enforcer):
        """A key with an unknown tier string should fail validation."""
        # We need to craft this manually since generate_license_key only accepts valid tiers
        payload = {
            "key_id": "bedrock-2026-01",
            "tier": "invalid_tier",
            "max_nodes": 10,
            "max_devs": 0,
            "dev_mode": False,
            "issued_to": "Hacker",
            "issued_at": time.time(),
            "expires_at": None,
            "features": [],
        }
        payload_json = json.dumps(payload, separators=(",", ":"), sort_keys=True)
        payload_b64 = base64.urlsafe_b64encode(payload_json.encode()).decode()
        sig = hmac.new(
            enforcer._signing_key,
            payload_json.encode(),
            hashlib.sha256,
        ).hexdigest()
        sig_b64 = base64.urlsafe_b64encode(sig.encode()).decode()
        key = f"1:{payload_b64}:{sig_b64}"
        with pytest.raises(LicenseValidationError, match="Invalid tier"):
            enforcer.validate_license(key)


# ── License Expiration ──

class TestLicenseExpiration:
    """Test license expiration handling."""

    def test_non_expired_license_is_valid(self, enforcer):
        key = enforcer.generate_license_key(
            tier=LicenseTier.BUSINESS,
            issued_to="Active Corp",
            expires_at=time.time() + 365 * 86400,
        )
        license = enforcer.validate_license(key)
        assert license.is_valid is True
        assert license.is_expired is False

    def test_expired_license_raises_error(self, enforcer):
        expired_time = time.time() - 86400  # 1 day ago
        key = enforcer.generate_license_key(
            tier=LicenseTier.BUSINESS,
            issued_to="Expired Corp",
            expires_at=expired_time,
        )
        with pytest.raises(LicenseExpiredError, match="License expired"):
            enforcer.validate_license(key)

    def test_perpetual_license_never_expires(self, enforcer):
        key = enforcer.generate_license_key(
            tier=LicenseTier.ENTERPRISE,
            issued_to="Perpetual Corp",
            expires_at=None,  # No expiration
        )
        license = enforcer.validate_license(key)
        assert license.is_expired is False
        assert license.is_valid is True

    def test_days_until_expiry(self, enforcer):
        expires = time.time() + 30 * 86400  # 30 days
        key = enforcer.generate_license_key(
            tier=LicenseTier.BUSINESS,
            issued_to="Expiring Corp",
            expires_at=expires,
        )
        license = enforcer.validate_license(key)
        days = license.days_until_expiry
        assert days is not None
        assert 29 < days < 31

    def test_no_expiry_returns_none_days(self, enforcer):
        key = enforcer.generate_license_key(
            tier=LicenseTier.ENTERPRISE,
            issued_to="No Expiry Corp",
            expires_at=None,
        )
        license = enforcer.validate_license(key)
        assert license.days_until_expiry is None


# ── License Enforcement ──

class TestLicenseEnforcement:
    """Test license enforcement rules."""

    def test_developer_mode_restrictions(self, enforcer):
        key = enforcer.generate_license_key(
            tier=LicenseTier.DEVELOPER,
            issued_to="Dev User",
        )
        license = enforcer.validate_license(key)
        restrictions = enforcer.enforce_developer_mode(license)
        assert restrictions["dev_mode"] is True
        assert restrictions["localhost_only"] is True
        assert restrictions["self_signed_certs"] is True
        assert restrictions["no_production"] is True
        assert restrictions["max_nodes"] <= 3

    def test_runtime_mode_no_restrictions(self, enforcer):
        key = enforcer.generate_license_key(
            tier=LicenseTier.BUSINESS,
            issued_to="Business Corp",
        )
        license = enforcer.validate_license(key)
        restrictions = enforcer.enforce_developer_mode(license)
        assert restrictions["dev_mode"] is False

    def test_can_issue_certificate_under_limit(self, enforcer, business_key):
        license = enforcer.validate_license(business_key)
        assert enforcer.can_issue_certificate(license, 0) is True
        assert enforcer.can_issue_certificate(license, 10) is True
        assert enforcer.can_issue_certificate(license, 24) is True

    def test_can_issue_certificate_at_limit(self, enforcer, business_key):
        license = enforcer.validate_license(business_key)
        assert enforcer.can_issue_certificate(license, 25) is False

    def test_can_issue_certificate_over_limit(self, enforcer, business_key):
        license = enforcer.validate_license(business_key)
        assert enforcer.can_issue_certificate(license, 30) is False

    def test_enterprise_always_can_issue(self, enforcer, enterprise_key):
        license = enforcer.validate_license(enterprise_key)
        assert enforcer.can_issue_certificate(license, 0) is True
        assert enforcer.can_issue_certificate(license, 100) is True
        assert enforcer.can_issue_certificate(license, 10000) is True

    def test_developer_max_3_nodes(self, enforcer, dev_key):
        license = enforcer.validate_license(dev_key)
        assert enforcer.can_issue_certificate(license, 0) is True
        assert enforcer.can_issue_certificate(license, 2) is True
        assert enforcer.can_issue_certificate(license, 3) is False

    def test_starter_max_5_nodes(self, enforcer, starter_key):
        license = enforcer.validate_license(starter_key)
        assert enforcer.can_issue_certificate(license, 4) is True
        assert enforcer.can_issue_certificate(license, 5) is False


# ── Feature Access ──

class TestFeatureAccess:
    """Test feature access enforcement."""

    def test_developer_features(self, enforcer, dev_key):
        license = enforcer.validate_license(dev_key)
        assert license.has_feature("self_signed_certs") is True
        assert license.has_feature("localhost_only") is True
        assert license.has_feature("max_3_nodes") is True
        assert license.has_feature("basic_mesh") is True
        # Developer should NOT have production features
        assert license.has_feature("ca_signed_certs") is False
        assert license.has_feature("production_deployment") is False
        assert license.has_feature("self_healing_mesh") is False

    def test_starter_features(self, enforcer, starter_key):
        license = enforcer.validate_license(starter_key)
        assert license.has_feature("ca_signed_certs") is True
        assert license.has_feature("production_deployment") is True
        assert license.has_feature("self_healing_mesh") is True
        assert license.has_feature("compliance_reports") is True
        # Starter should NOT have business features
        assert license.has_feature("custom_certificates") is False
        assert license.has_feature("priority_support") is False

    def test_business_features(self, enforcer, business_key):
        license = enforcer.validate_license(business_key)
        assert license.has_feature("ca_signed_certs") is True
        assert license.has_feature("custom_certificates") is True
        assert license.has_feature("priority_support") is True

    def test_enterprise_features(self, enforcer, enterprise_key):
        license = enforcer.validate_license(enterprise_key)
        assert license.has_feature("ca_signed_certs") is True
        assert license.has_feature("custom_ca") is True
        assert license.has_feature("air_gap_support") is True
        assert license.has_feature("dedicated_support") is True

    def test_validate_feature_access(self, enforcer, dev_key):
        license = enforcer.validate_license(dev_key)
        assert enforcer.validate_feature_access(license, "basic_mesh") is True
        assert enforcer.validate_feature_access(license, "ca_signed_certs") is False

    def test_nonexistent_feature(self, enforcer, business_key):
        license = enforcer.validate_license(business_key)
        assert license.has_feature("nonexistent_feature") is False


# ── Tier Information ──

class TestTierInfo:
    """Test tier information and pricing."""

    def test_developer_tier_info(self, enforcer):
        info = enforcer.get_tier_info(LicenseTier.DEVELOPER)
        assert info["tier"] == "developer"
        assert info["max_nodes"] == 3
        assert info["pricing"]["individual"] == 99
        assert info["pricing"]["team"] == 499

    def test_starter_tier_info(self, enforcer):
        info = enforcer.get_tier_info(LicenseTier.STARTER)
        assert info["tier"] == "starter"
        assert info["max_nodes"] == 5
        assert info["pricing"] == 5000

    def test_business_tier_info(self, enforcer):
        info = enforcer.get_tier_info(LicenseTier.BUSINESS)
        assert info["tier"] == "business"
        assert info["max_nodes"] == 25
        assert info["pricing"] == 20000

    def test_enterprise_tier_info(self, enforcer):
        info = enforcer.get_tier_info(LicenseTier.ENTERPRISE)
        assert info["tier"] == "enterprise"
        assert info["max_nodes"] == float("inf")
        assert info["pricing"] == "custom"

    def test_node_limits_constant(self):
        assert NODE_LIMITS[LicenseTier.DEVELOPER] == 3
        assert NODE_LIMITS[LicenseTier.STARTER] == 5
        assert NODE_LIMITS[LicenseTier.BUSINESS] == 25
        assert NODE_LIMITS[LicenseTier.ENTERPRISE] == float("inf")

    def test_tier_pricing_constant(self):
        assert TIER_PRICING[LicenseTier.DEVELOPER]["individual"] == 99
        assert TIER_PRICING[LicenseTier.DEVELOPER]["team"] == 499
        assert TIER_PRICING[LicenseTier.STARTER] == 5000
        assert TIER_PRICING[LicenseTier.BUSINESS] == 20000
        assert TIER_PRICING[LicenseTier.ENTERPRISE] == "custom"


# ── Upgrade Paths ──

class TestUpgradePaths:
    """Test license upgrade path calculation."""

    def test_developer_upgrade_path(self, enforcer):
        upgrades = enforcer.get_upgrade_path(LicenseTier.DEVELOPER)
        assert "starter" in upgrades
        assert "business" in upgrades
        assert "enterprise" in upgrades

    def test_starter_upgrade_path(self, enforcer):
        upgrades = enforcer.get_upgrade_path(LicenseTier.STARTER)
        assert "starter" not in upgrades
        assert "business" in upgrades
        assert "enterprise" in upgrades

    def test_business_upgrade_path(self, enforcer):
        upgrades = enforcer.get_upgrade_path(LicenseTier.BUSINESS)
        assert "starter" not in upgrades
        assert "business" not in upgrades
        assert "enterprise" in upgrades

    def test_enterprise_no_upgrade_path(self, enforcer):
        upgrades = enforcer.get_upgrade_path(LicenseTier.ENTERPRISE)
        assert len(upgrades) == 0

    def test_upgrade_path_includes_pricing(self, enforcer):
        upgrades = enforcer.get_upgrade_path(LicenseTier.DEVELOPER)
        assert upgrades["starter"]["pricing"] == 5000
        assert upgrades["business"]["pricing"] == 20000


# ── License File Validation ──

class TestLicenseFileValidation:
    """Test license validation from file."""

    def test_validate_from_file(self, enforcer):
        key = enforcer.generate_license_key(
            tier=LicenseTier.BUSINESS,
            issued_to="File Corp",
        )
        tmpdir = tempfile.mkdtemp()
        path = os.path.join(tmpdir, "license.key")
        try:
            with open(path, "w") as f:
                f.write(key)
            license = enforcer.validate_license_from_file(path)
            assert license.tier == LicenseTier.BUSINESS
            assert license.issued_to == "File Corp"
        finally:
            os.unlink(path)
            os.rmdir(tmpdir)

    def test_validate_from_missing_file_raises_error(self, enforcer):
        with pytest.raises(FileNotFoundError, match="License file not found"):
            enforcer.validate_license_from_file("/tmp/nonexistent_license.key")


# ── License Properties ──

class TestLicenseProperties:
    """Test License dataclass properties."""

    def test_is_developer_property(self, enforcer, dev_key, business_key):
        dev_license = enforcer.validate_license(dev_key)
        biz_license = enforcer.validate_license(business_key)
        assert dev_license.is_developer is True
        assert biz_license.is_developer is False

    def test_is_runtime_property(self, enforcer, dev_key, starter_key, enterprise_key):
        dev_license = enforcer.validate_license(dev_key)
        starter_license = enforcer.validate_license(starter_key)
        ent_license = enforcer.validate_license(enterprise_key)
        assert dev_license.is_runtime is False
        assert starter_license.is_runtime is True
        assert ent_license.is_runtime is True

    def test_is_valid_property(self, enforcer):
        key = enforcer.generate_license_key(
            tier=LicenseTier.BUSINESS,
            issued_to="Valid Corp",
            expires_at=time.time() + 86400,
        )
        license = enforcer.validate_license(key)
        assert license.is_valid is True

    def test_license_key_preserved(self, enforcer):
        key = enforcer.generate_license_key(
            tier=LicenseTier.STARTER,
            issued_to="Key Test",
        )
        license = enforcer.validate_license(key)
        assert license.license_key == key


# ── Cross-Module Integration ──

class TestLicensingCertificateIntegration:
    """Test integration between licensing and certificate system."""

    def test_developer_certificates_limited(self):
        """Developer tier should be limited to 3 certificates."""
        from bedrock.identity.certificates import (
            CertificateManager, LicenseTier as CertTier
        )
        cert_mgr = CertificateManager(license_tier=CertTier.DEVELOPER)
        # Should be able to issue 3 certificates
        for i in range(3):
            cert = cert_mgr.issue_certificate(
                node_uuid=f"node-{i}",
                node_name=f"Node {i}",
                public_key_hash=f"hash-{i}",
            )
            assert cert.is_valid()

        # 4th certificate should fail
        from bedrock.identity.certificates import LicenseExceededError
        with pytest.raises(LicenseExceededError):
            cert_mgr.issue_certificate(
                node_uuid="node-4",
                node_name="Node 4",
                public_key_hash="hash-4",
            )

    def test_business_certificates_limited(self):
        """Business tier should be limited to 25 certificates."""
        from bedrock.identity.certificates import (
            CertificateManager, LicenseTier as CertTier
        )
        cert_mgr = CertificateManager(license_tier=CertTier.BUSINESS)
        # Issue 25 certificates
        for i in range(25):
            cert_mgr.issue_certificate(
                node_uuid=f"node-{i}",
                node_name=f"Node {i}",
                public_key_hash=f"hash-{i}",
            )
        # 26th should fail
        from bedrock.identity.certificates import LicenseExceededError
        with pytest.raises(LicenseExceededError):
            cert_mgr.issue_certificate(
                node_uuid="node-26",
                node_name="Node 26",
                public_key_hash="hash-26",
            )

    def test_enterprise_certificates_unlimited(self):
        """Enterprise tier should have no certificate limit."""
        from bedrock.identity.certificates import (
            CertificateManager, LicenseTier as CertTier
        )
        cert_mgr = CertificateManager(license_tier=CertTier.ENTERPRISE)
        # Issue 50 certificates — should all succeed
        for i in range(50):
            cert = cert_mgr.issue_certificate(
                node_uuid=f"node-{i}",
                node_name=f"Node {i}",
                public_key_hash=f"hash-{i}",
            )
            assert cert.is_valid()

    def test_developer_uses_self_signed_issuer(self):
        """Developer tier certificates should use self-signed issuer."""
        from bedrock.identity.certificates import CertificateManager, LicenseTier as CertTier
        cert_mgr = CertificateManager(license_tier=CertTier.DEVELOPER)
        cert = cert_mgr.issue_certificate(
            node_uuid="dev-node-1",
            node_name="Dev Node",
            public_key_hash="dev-hash",
        )
        assert cert.issuer == "bedrock-self-signed"

    def test_business_uses_ca_issuer(self):
        """Business tier certificates should use CA issuer."""
        from bedrock.identity.certificates import CertificateManager, LicenseTier as CertTier
        cert_mgr = CertificateManager(license_tier=CertTier.BUSINESS, ca_name="acme-ca")
        cert = cert_mgr.issue_certificate(
            node_uuid="biz-node-1",
            node_name="Biz Node",
            public_key_hash="biz-hash",
        )


class TestTrialLicense:
    """Tests for the free 30-day trial license tier."""

    def test_trial_tier_exists(self):
        """Trial tier should be a valid LicenseTier."""
        assert LicenseTier.TRIAL.value == "trial"

    def test_trial_key_generation(self):
        """issue_trial_license should generate a valid trial key."""
        enforcer = LicenseEnforcer()
        key = enforcer.issue_trial_license(issued_to="test-user@example.com")
        assert key  # Non-empty
        assert key.startswith("1:")

    def test_trial_license_validation(self):
        """Trial key should validate as TRIAL tier."""
        enforcer = LicenseEnforcer()
        key = enforcer.issue_trial_license(issued_to="trial-tester")
        license_obj = enforcer.validate_license(key)
        assert license_obj.tier == LicenseTier.TRIAL
        assert license_obj.is_trial is True
        assert license_obj.is_developer is True  # Trial inherits developer privileges
        assert license_obj.issued_to == "trial-tester"

    def test_trial_license_expires_in_30_days(self):
        """Trial license should expire 30 days from issuance."""
        import time
        enforcer = LicenseEnforcer()
        before = time.time()
        key = enforcer.issue_trial_license()
        after = time.time()
        license_obj = enforcer.validate_license(key)
        # Should have ~30 days remaining
        days_left = license_obj.days_until_expiry
        assert days_left is not None
        assert 29 <= days_left <= 30  # Allow for test execution time

    def test_trial_node_limit_is_3(self):
        """Trial tier allows max 3 nodes (same as developer)."""
        assert NODE_LIMITS[LicenseTier.TRIAL] == 3

    def test_trial_pricing_is_free(self):
        """Trial tier should be free ($0)."""
        assert TIER_PRICING[LicenseTier.TRIAL] == 0

    def test_trial_features(self):
        """Trial tier should include trial_mode feature flag."""
        features = TIER_FEATURES[LicenseTier.TRIAL]
        assert "trial_mode" in features
        assert "self_signed_certs" in features
        assert "localhost_only" in features

    def test_trial_enforcement_mode(self):
        """Trial license should enforce developer mode restrictions plus trial watermark."""
        enforcer = LicenseEnforcer()
        key = enforcer.issue_trial_license()
        license_obj = enforcer.validate_license(key)
        restrictions = enforcer.enforce_developer_mode(license_obj)
        assert restrictions["dev_mode"] is True
        assert restrictions["trial_mode"] is True
        assert "trial_days_remaining" in restrictions
        assert restrictions["localhost_only"] is True
        assert restrictions["self_signed_certs"] is True

    def test_trial_upgrade_path(self):
        """Trial should be able to upgrade to developer and above."""
        enforcer = LicenseEnforcer()
        upgrades = enforcer.get_upgrade_path(LicenseTier.TRIAL)
        assert "developer" in upgrades
        assert "starter" in upgrades
        assert "business" in upgrades
        assert "enterprise" in upgrades

    def test_trial_is_not_runtime(self):
        """Trial license should not be considered a runtime/production license."""
        enforcer = LicenseEnforcer()
        key = enforcer.issue_trial_license()
        license_obj = enforcer.validate_license(key)
        assert license_obj.is_runtime is False