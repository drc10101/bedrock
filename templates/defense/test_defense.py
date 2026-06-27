"""
Tests for the Defense Vertical Template.

Verifies silo creation, consent flows, CMMC/DFARS compliance mapping,
clearance checking, and configuration defaults.
"""

import pytest
from bedrock.config import CoreConfig
from bedrock.data_separation.silo import SiloManager
from bedrock.data_separation.consent import ConsentStatus

from templates.defense import (
    DefenseTemplate,
    DEFENSE_SILOS,
    DEFENSE_CONSENT_FLOWS,
    DEFENSE_ROLES,
    CMMC_DFARS_MAPPINGS,
    CLEARANCE_LEVELS,
    DefenseConsentFlowType,
)


class TestDefenseSilos:
    """Test defense silo definitions and creation."""

    def setup_method(self):
        self.template = DefenseTemplate(mode="developer")
        self.silo_manager = SiloManager()

    def test_create_all_defense_silos(self):
        silos = self.template.create_silos(self.silo_manager)

        assert len(silos) == 3
        assert "identity" in silos
        assert "cui" in silos
        assert "auth" in silos

    def test_identity_silo_categories(self):
        silos = self.template.create_silos(self.silo_manager)
        identity = silos["identity"]

        assert "clearance_level" in identity.categories
        assert "clearance_type" in identity.categories
        assert "investigation_status" in identity.categories
        assert "citizenship" in identity.categories

    def test_cui_silo_categories(self):
        silos = self.template.create_silos(self.silo_manager)
        cui = silos["cui"]

        assert "technical_data" in cui.categories
        assert "drawings" in cui.categories
        assert "specifications" in cui.categories
        assert "operational_plans" in cui.categories
        assert "source_code" in cui.categories

    def test_auth_silo_categories(self):
        silos = self.template.create_silos(self.silo_manager)
        auth = silos["auth"]

        assert "cui_access_logs" in auth.categories
        assert "export_reviews" in auth.categories
        assert "incident_reports" in auth.categories

    def test_silos_are_encrypted(self):
        silos = self.template.create_silos(self.silo_manager)
        for name, silo in silos.items():
            assert silo.encrypted is True, f"{name} silo should be encrypted"

    def test_silo_hkdf_info_format(self):
        silos = self.template.create_silos(self.silo_manager)
        for name, silo in silos.items():
            assert silo.hkdf_info.startswith("bedrock:silo:defense:"), \
                f"{name} silo has wrong hkdf prefix"

    def test_silo_isolation_cui_not_in_identity(self):
        """CUI content must never appear in identity silo."""
        silos = self.template.create_silos(self.silo_manager)
        identity = silos["identity"]
        cui_categories = {"technical_data", "drawings", "specifications", "operational_plans"}
        overlap = set(identity.categories) & cui_categories
        assert len(overlap) == 0, \
            f"Identity silo contains CUI categories: {overlap}"

    def test_clearance_data_in_identity_only(self):
        """Clearance data must be in identity silo only."""
        silos = self.template.create_silos(self.silo_manager)
        assert "clearance_level" in silos["identity"].categories
        assert "clearance_level" not in silos["cui"].categories
        assert "clearance_level" not in silos["auth"].categories


class TestDefenseConsentFlows:
    """Test defense consent flow patterns."""

    def setup_method(self):
        self.template = DefenseTemplate(mode="developer")

    def test_clearance_verification_flow(self):
        consent = self.template.request_clearance_verification("staff-001")

        assert consent.status == ConsentStatus.PENDING
        assert consent.source_silo == "identity"
        assert consent.target_silo == "cui"
        assert "clearance_level" in consent.categories
        assert "investigation_status" in consent.categories

    def test_cui_access_flow(self):
        consent = self.template.request_cui_access("staff-001")

        assert consent.status == ConsentStatus.PENDING
        assert consent.source_silo == "cui"
        assert "technical_data" in consent.categories

    def test_consent_flows_have_cmmc_sections(self):
        for name, flow in DEFENSE_CONSENT_FLOWS.items():
            assert len(flow.cmmc_sections) > 0, \
                f"{name} flow has no CMMC sections mapped"

    def test_clearance_verification_has_access_control(self):
        flow = DEFENSE_CONSENT_FLOWS["clearance_verification"]
        assert "ac_3_access_enforcement" in flow.cmmc_sections

    def test_cui_access_has_media_protection(self):
        flow = DEFENSE_CONSENT_FLOWS["cui_access"]
        assert "mp_1_media_protection" in flow.cmmc_sections

    def test_all_flows_require_reason(self):
        """Defense consent always requires a reason (need-to-know)."""
        for name, flow in DEFENSE_CONSENT_FLOWS.items():
            assert flow.require_reason is True, \
                f"{name} flow should require reason"

    def test_all_flows_have_min_clearance(self):
        """All defense consent flows have minimum clearance levels."""
        for name, flow in DEFENSE_CONSENT_FLOWS.items():
            assert flow.min_clearance in CLEARANCE_LEVELS, \
                f"{name} flow has invalid clearance level: {flow.min_clearance}"

    def test_export_review_requires_secret(self):
        """Export review requires Secret clearance minimum."""
        flow = DEFENSE_CONSENT_FLOWS["export_review"]
        assert CLEARANCE_LEVELS[flow.min_clearance] >= CLEARANCE_LEVELS["secret"]

    def test_all_flows_distinct_ids(self):
        types = [f.flow_type for f in DEFENSE_CONSENT_FLOWS.values()]
        assert len(types) == len(set(types))


class TestDefenseConfiguration:
    """Test defense-specific CoreConfig settings."""

    def test_developer_mode_config(self):
        template = DefenseTemplate(mode="developer")
        config = template.get_config()

        assert config.environment == "development"
        assert config.licensing.dev_mode is True

    def test_production_mode_config(self):
        template = DefenseTemplate(mode="production")
        config = template.get_config()

        assert config.environment == "production"
        assert config.licensing.dev_mode is False

    def test_dfars_audit_retention(self):
        """DFARS requires 6-year retention."""
        template = DefenseTemplate(mode="production")
        config = template.get_config()

        assert config.audit.retention_years == 6

    def test_cmmc_consent_requires_reason(self):
        """CMMC requires need-to-know (reason required)."""
        template = DefenseTemplate(mode="production")
        config = template.get_config()

        assert config.data_separation.consent_require_reason is True

    def test_cmmc_strict_silo_mode(self):
        template = DefenseTemplate(mode="production")
        config = template.get_config()

        assert config.data_separation.silo_strict_mode is True

    def test_cmmc_mfa_required(self):
        """CMMC IA.1 requires MFA."""
        template = DefenseTemplate(mode="production")
        config = template.get_config()

        assert config.access_control.mfa_required is True

    def test_defense_session_timeout(self):
        """Defense sessions: 30 min default, 8 hour max."""
        template = DefenseTemplate(mode="production")
        config = template.get_config()

        assert config.access_control.session_ttl_seconds == 1800
        assert config.access_control.session_max_ttl_seconds == 28800

    def test_defense_lockout_3_attempts(self):
        """Defense requires lockout after 3 attempts."""
        template = DefenseTemplate(mode="production")
        config = template.get_config()

        assert config.access_control.lockout_max_attempts == 3


class TestDefenseClearanceLevels:
    """Test clearance level hierarchy."""

    def test_clearance_hierarchy(self):
        assert CLEARANCE_LEVELS["public"] < CLEARANCE_LEVELS["cui"]
        assert CLEARANCE_LEVELS["cui"] < CLEARANCE_LEVELS["secret"]
        assert CLEARANCE_LEVELS["secret"] < CLEARANCE_LEVELS["top_secret"]
        assert CLEARANCE_LEVELS["top_secret"] < CLEARANCE_LEVELS["top_secret_sci"]

    def test_check_clearance_meets_requirement(self):
        """Cleared staff (CUI) meets CUI requirement."""
        assert DefenseTemplate.check_clearance("cleared_staff", "cui") is True

    def test_check_clearance_insufficient(self):
        """Cleared staff (CUI) does NOT meet Secret requirement."""
        assert DefenseTemplate.check_clearance("cleared_staff", "secret") is False

    def test_check_clearance_fso_meets_top_secret(self):
        """FSO (Top Secret) meets Top Secret requirement."""
        assert DefenseTemplate.check_clearance("fso", "top_secret") is True

    def test_check_clearance_fso_meets_cui(self):
        """FSO (Top Secret) also meets CUI requirement."""
        assert DefenseTemplate.check_clearance("fso", "cui") is True

    def test_check_clearance_unknown_role(self):
        assert DefenseTemplate.check_clearance("unknown_role", "cui") is False


class TestDefenseRoles:
    """Test defense role-portal mappings."""

    def test_cleared_staff_role(self):
        assert "provider" in DEFENSE_ROLES["cleared_staff"]["portals"]
        assert DEFENSE_ROLES["cleared_staff"]["min_clearance"] == "cui"

    def test_program_manager_role(self):
        assert "admin" in DEFENSE_ROLES["program_manager"]["portals"]
        assert DEFENSE_ROLES["program_manager"]["min_clearance"] == "secret"

    def test_fso_role(self):
        assert "admin" in DEFENSE_ROLES["fso"]["portals"]
        assert DEFENSE_ROLES["fso"]["min_clearance"] == "top_secret"

    def test_subcontractor_role(self):
        assert "partner" in DEFENSE_ROLES["subcontractor"]["portals"]
        assert DEFENSE_ROLES["subcontractor"]["min_clearance"] == "cui"

    def test_auditor_role(self):
        assert "partner" in DEFENSE_ROLES["auditor"]["portals"]
        assert DEFENSE_ROLES["auditor"]["min_clearance"] == "secret"

    def test_fso_can_revoke_certs(self):
        """FSO can issue and revoke certificates."""
        perms = DEFENSE_ROLES["fso"]["permissions"]
        assert "cert.issue" in perms
        assert "cert.revoke" in perms

    def test_subcontractor_cannot_write(self):
        """Subcontractor has read-only access."""
        perms = DEFENSE_ROLES["subcontractor"]["permissions"]
        assert "data.read" in perms
        assert "data.write" not in perms

    def test_auditor_cannot_write(self):
        """Auditor has read-only access."""
        perms = DEFENSE_ROLES["auditor"]["permissions"]
        assert "data.read" in perms
        assert "data.write" not in perms

    def test_minimum_necessary_all_roles(self):
        """All defense roles have minimum necessary standard."""
        for role, config in DEFENSE_ROLES.items():
            assert config["dfars_minimum_necessary"] is True


class TestCMMCComplianceReport:
    """Test CMMC/DFARS compliance mapping completeness."""

    def setup_method(self):
        self.template = DefenseTemplate(mode="developer")

    def test_compliance_report_has_cmmc_level_2(self):
        report = self.template.cmmc_compliance_report()
        assert "cmmc_level_2" in report["mappings"]

    def test_compliance_report_has_dfars(self):
        report = self.template.cmmc_compliance_report()
        assert "dfars_252_204_7012" in report["mappings"]

    def test_compliance_report_has_nist_800_171(self):
        report = self.template.cmmc_compliance_report()
        assert "nist_800_171" in report["mappings"]

    def test_compliance_report_lists_all_silos(self):
        report = self.template.cmmc_compliance_report()
        assert set(report["silos"]) == {"identity", "cui", "auth"}

    def test_compliance_report_has_clearance_levels(self):
        report = self.template.cmmc_compliance_report()
        assert "clearance_levels" in report
        assert report["clearance_levels"]["secret"] > report["clearance_levels"]["cui"]

    def test_breach_reporting_mapping(self):
        report = self.template.cmmc_compliance_report()
        assert "breach_reporting" in report["enforcement_summary"]

    def test_flow_down_mapping(self):
        report = self.template.cmmc_compliance_report()
        assert "flow_down" in report["enforcement_summary"]

    def test_encryption_mapping(self):
        report = self.template.cmmc_compliance_report()
        assert "encryption_at_rest" in report["enforcement_summary"]