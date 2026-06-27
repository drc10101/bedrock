"""Tests for License Enforcement."""

from bedrock.licensing.enforcement import LicenseEnforcer, License, LicenseTier


class TestLicenseEnforcer:
    """Test license enforcement logic."""

    def _make_license(self, tier=LicenseTier.DEVELOPER, max_nodes=3):
        return License(
            license_key="test-key",
            tier=tier,
            max_nodes=max_nodes,
            max_devs=1 if tier == LicenseTier.DEVELOPER else 0,
            dev_mode=(tier == LicenseTier.DEVELOPER),
        )

    def test_developer_license_properties(self):
        lic = self._make_license(LicenseTier.DEVELOPER, max_nodes=3)
        assert lic.is_developer is True
        assert lic.is_runtime is False

    def test_starter_license_properties(self):
        lic = self._make_license(LicenseTier.STARTER, max_nodes=5)
        assert lic.is_developer is False
        assert lic.is_runtime is True

    def test_enterprise_unlimited_nodes(self):
        enforcer = LicenseEnforcer()
        lic = self._make_license(LicenseTier.ENTERPRISE, max_nodes=0)
        assert enforcer.can_issue_certificate(lic, 1000) is True

    def test_developer_max_3_nodes(self):
        enforcer = LicenseEnforcer()
        lic = self._make_license(LicenseTier.DEVELOPER, max_nodes=3)
        assert enforcer.can_issue_certificate(lic, 0) is True
        assert enforcer.can_issue_certificate(lic, 2) is True
        assert enforcer.can_issue_certificate(lic, 3) is False

    def test_starter_max_5_nodes(self):
        enforcer = LicenseEnforcer()
        lic = self._make_license(LicenseTier.STARTER, max_nodes=5)
        assert enforcer.can_issue_certificate(lic, 4) is True
        assert enforcer.can_issue_certificate(lic, 5) is False

    def test_business_max_25_nodes(self):
        enforcer = LicenseEnforcer()
        lic = self._make_license(LicenseTier.BUSINESS, max_nodes=25)
        assert enforcer.can_issue_certificate(lic, 24) is True
        assert enforcer.can_issue_certificate(lic, 25) is False

    def test_developer_mode_restrictions(self):
        enforcer = LicenseEnforcer()
        lic = self._make_license(LicenseTier.DEVELOPER, max_nodes=3)
        restrictions = enforcer.enforce_developer_mode(lic)
        assert restrictions["dev_mode"] is True
        assert restrictions["localhost_only"] is True
        assert restrictions["self_signed_certs"] is True
        assert restrictions["no_production"] is True

    def test_runtime_mode_no_dev_restrictions(self):
        enforcer = LicenseEnforcer()
        lic = self._make_license(LicenseTier.STARTER, max_nodes=5)
        restrictions = enforcer.enforce_developer_mode(lic)
        assert restrictions["dev_mode"] is False