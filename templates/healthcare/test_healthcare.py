"""
Tests for the Healthcare Vertical Template.

Verifies silo creation, consent flows, HIPAA compliance mapping,
and configuration defaults.
"""

import pytest
from bedrock.config import CoreConfig
from bedrock.data_separation.silo import SiloManager
from bedrock.data_separation.consent import ConsentStatus

from templates.healthcare import (
    HealthcareTemplate,
    HEALTHCARE_SILOS,
    HEALTHCARE_CONSENT_FLOWS,
    HEALTHCARE_ROLES,
    HIPAA_MAPPINGS,
    ConsentFlowType,
)


class TestHealthcareSilos:
    """Test healthcare silo definitions and creation."""

    def setup_method(self):
        self.template = HealthcareTemplate(mode="developer")
        self.silo_manager = SiloManager()

    def test_create_all_healthcare_silos(self):
        silos = self.template.create_silos(self.silo_manager)

        assert len(silos) == 3
        assert "identity" in silos
        assert "medical" in silos
        assert "auth" in silos

    def test_identity_silo_categories(self):
        silos = self.template.create_silos(self.silo_manager)
        identity = silos["identity"]

        assert "demographics" in identity.categories
        assert "contact" in identity.categories
        assert "insurance" in identity.categories
        assert "ssn" in identity.categories

    def test_medical_silo_categories(self):
        silos = self.template.create_silos(self.silo_manager)
        medical = silos["medical"]

        assert "diagnosis" in medical.categories
        assert "medications" in medical.categories
        assert "vitals" in medical.categories
        assert "lab_results" in medical.categories
        assert "imaging" in medical.categories
        assert "procedures" in medical.categories

    def test_auth_silo_categories(self):
        silos = self.template.create_silos(self.silo_manager)
        auth = silos["auth"]

        assert "credentials" in auth.categories
        assert "sessions" in auth.categories
        assert "mfa" in auth.categories

    def test_silos_are_encrypted(self):
        silos = self.template.create_silos(self.silo_manager)
        for name, silo in silos.items():
            assert silo.encrypted is True, f"{name} silo should be encrypted"

    def test_silo_hkdf_info_format(self):
        silos = self.template.create_silos(self.silo_manager)
        for name, silo in silos.items():
            assert silo.hkdf_info.startswith("bedrock:silo:healthcare:"), \
                f"{name} silo has wrong hkdf prefix"

    def test_silo_isolation_medical_not_in_identity(self):
        silos = self.template.create_silos(self.silo_manager)
        identity = silos["identity"]
        # Medical categories must not appear in identity silo
        medical_categories = {"diagnosis", "medications", "vitals", "lab_results"}
        overlap = set(identity.categories) & medical_categories
        assert len(overlap) == 0, f"Identity silo contains medical categories: {overlap}"


class TestHealthcareConsentFlows:
    """Test PIR/ePRR consent flow patterns."""

    def setup_method(self):
        self.template = HealthcareTemplate(mode="developer")

    def test_pir_flow_creates_pending_consent(self):
        consent = self.template.request_pir(
            requesting_node_id="provider-001",
            patient_id="patient-42",
            reason="Treatment coordination",
        )

        assert consent.status == ConsentStatus.PENDING
        assert consent.source_silo == "identity"
        assert consent.target_silo == "medical"
        assert "demographics" in consent.categories
        assert consent.scope == "read"
        assert consent.reason == "Treatment coordination"

    def test_eprr_flow_creates_pending_consent(self):
        consent = self.template.request_eprr(
            requesting_node_id="provider-001",
            patient_id="patient-42",
            reason="Lab results review",
        )

        assert consent.status == ConsentStatus.PENDING
        assert consent.source_silo == "medical"
        assert consent.target_silo == "medical"
        assert "diagnosis" in consent.categories
        assert "lab_results" in consent.categories

    def test_pir_and_eprr_are_separate(self):
        """PIR and ePRR are separate consent events (InFill pattern)."""
        pir = self.template.request_pir("provider-001", "patient-42")
        eprr = self.template.request_eprr("provider-001", "patient-42")

        assert pir.consent_id != eprr.consent_id
        assert pir.source_silo != eprr.source_silo
        # PIR: identity→medical (demographics only)
        # ePRR: medical→medical (diagnoses, labs, etc.)
        assert "demographics" in pir.categories
        assert "demographics" not in eprr.categories

    def test_consent_flows_have_hipaa_sections(self):
        for name, flow in HEALTHCARE_CONSENT_FLOWS.items():
            assert len(flow.hipaa_sections) > 0, \
                f"{name} flow has no HIPAA sections mapped"

    def test_pir_flow_hipaa_mapping(self):
        pir_flow = HEALTHCARE_CONSENT_FLOWS["pir"]
        assert "164.508_uses_disclosures_authorization" in pir_flow.hipaa_sections

    def test_eprr_flow_hipaa_mapping(self):
        eprr_flow = HEALTHCARE_CONSENT_FLOWS["eprr"]
        assert "164.502_uses_disclosures" in eprr_flow.hipaa_sections

    def test_treatment_flow_is_write_scope(self):
        treatment = HEALTHCARE_CONSENT_FLOWS["treatment"]
        assert treatment.scope == "write"

    def test_research_flow_has_longer_ttl(self):
        research = HEALTHCARE_CONSENT_FLOWS["research"]
        pir = HEALTHCARE_CONSENT_FLOWS["pir"]
        assert research.default_ttl_seconds > pir.default_ttl_seconds

    def test_pir_default_reason(self):
        """PIR without explicit reason uses template description."""
        consent = self.template.request_pir("provider-001", "patient-42")
        assert consent.reason  # Should have a default description


class TestHealthcareConfiguration:
    """Test healthcare-specific CoreConfig settings."""

    def test_developer_mode_config(self):
        template = HealthcareTemplate(mode="developer")
        config = template.get_config()

        assert config.environment == "development"
        assert config.licensing.dev_mode is True

    def test_production_mode_config(self):
        template = HealthcareTemplate(mode="production")
        config = template.get_config()

        assert config.environment == "production"
        assert config.licensing.dev_mode is False

    def test_hipaa_audit_retention(self):
        template = HealthcareTemplate(mode="production")
        config = template.get_config()

        assert config.audit.retention_years == 6

    def test_hipaa_consent_requires_reason(self):
        template = HealthcareTemplate(mode="production")
        config = template.get_config()

        assert config.data_separation.consent_require_reason is True

    def test_hipaa_strict_silo_mode(self):
        template = HealthcareTemplate(mode="production")
        config = template.get_config()

        assert config.data_separation.silo_strict_mode is True

    def test_hipaa_mfa_required(self):
        template = HealthcareTemplate(mode="production")
        config = template.get_config()

        assert config.access_control.mfa_required is True

    def test_session_timeout_within_hipaa_limits(self):
        template = HealthcareTemplate(mode="production")
        config = template.get_config()

        assert config.access_control.session_ttl_seconds <= 28800  # 8 hours max
        assert config.access_control.session_max_ttl_seconds == 28800


class TestHealthcareRoles:
    """Test healthcare role-portal mappings."""

    def test_provider_has_provider_portal(self):
        assert "provider" in HEALTHCARE_ROLES["provider"]["portals"]

    def test_patient_has_patient_portal(self):
        assert "patient" in HEALTHCARE_ROLES["patient"]["portals"]

    def test_admin_has_admin_portal(self):
        assert "admin" in HEALTHCARE_ROLES["admin"]["portals"]

    def test_researcher_has_partner_portal(self):
        assert "partner" in HEALTHCARE_ROLES["researcher"]["portals"]

    def test_provider_cannot_revoke_certs(self):
        """Provider can issue but not revoke certificates."""
        perms = HEALTHCARE_ROLES["provider"]["permissions"]
        assert "cert.issue" in perms
        assert "cert.revoke" not in perms

    def test_admin_can_revoke_certs(self):
        """Admin can both issue and revoke certificates."""
        perms = HEALTHCARE_ROLES["admin"]["permissions"]
        assert "cert.issue" in perms
        assert "cert.revoke" in perms

    def test_patient_cannot_write(self):
        """Patient role is read-only for their own data."""
        perms = HEALTHCARE_ROLES["patient"]["permissions"]
        assert "data.read" in perms
        assert "data.write" not in perms

    def test_minimum_necessary_enforcement(self):
        """All roles except patient have minimum necessary standard."""
        for role, config in HEALTHCARE_ROLES.items():
            if role == "patient":
                assert config["hipaa_minimum_necessary"] is False
            else:
                assert config["hipaa_minimum_necessary"] is True


class TestHIPAAComplianceReport:
    """Test HIPAA compliance mapping completeness."""

    def setup_method(self):
        self.template = HealthcareTemplate(mode="developer")

    def test_compliance_report_has_privacy_rule(self):
        report = self.template.hipaa_compliance_report()
        assert "privacy_rule" in report["mappings"]

    def test_compliance_report_has_security_rule(self):
        report = self.template.hipaa_compliance_report()
        assert "security_rule" in report["mappings"]

    def test_compliance_report_has_breach_notification(self):
        report = self.template.hipaa_compliance_report()
        assert "breach_notification" in report["mappings"]

    def test_compliance_report_lists_all_silos(self):
        report = self.template.hipaa_compliance_report()
        assert set(report["silos"]) == {"identity", "medical", "auth"}

    def test_compliance_report_lists_all_flows(self):
        report = self.template.hipaa_compliance_report()
        assert set(report["consent_flows"]) == {"pir", "eprr", "treatment", "research", "insurance"}

    def test_encryption_mapping(self):
        report = self.template.hipaa_compliance_report()
        assert "encryption_at_rest" in report["enforcement_summary"]

    def test_audit_trail_mapping(self):
        report = self.template.hipaa_compliance_report()
        assert "audit_trail" in report["enforcement_summary"]