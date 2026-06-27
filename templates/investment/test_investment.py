"""
Tests for the Investment Vertical Template.

Verifies silo creation, consent flows, SEC/FINRA compliance mapping,
and configuration defaults.
"""

import pytest
from bedrock.config import CoreConfig
from bedrock.data_separation.silo import SiloManager
from bedrock.data_separation.consent import ConsentStatus

from templates.investment import (
    InvestmentTemplate,
    INVESTMENT_SILOS,
    INVESTMENT_CONSENT_FLOWS,
    INVESTMENT_ROLES,
    SEC_FINRA_MAPPINGS,
    InvestmentConsentFlowType,
)


class TestInvestmentSilos:
    """Test investment silo definitions and creation."""

    def setup_method(self):
        self.template = InvestmentTemplate(mode="developer")
        self.silo_manager = SiloManager()

    def test_create_all_investment_silos(self):
        silos = self.template.create_silos(self.silo_manager)

        assert len(silos) == 3
        assert "identity" in silos
        assert "portfolio" in silos
        assert "auth" in silos

    def test_identity_silo_categories(self):
        silos = self.template.create_silos(self.silo_manager)
        identity = silos["identity"]

        assert "ssn" in identity.categories
        assert "kyc_documents" in identity.categories
        assert "accreditation" in identity.categories
        assert "beneficial_ownership" in identity.categories

    def test_portfolio_silo_categories(self):
        silos = self.template.create_silos(self.silo_manager)
        portfolio = silos["portfolio"]

        assert "holdings" in portfolio.categories
        assert "transactions" in portfolio.categories
        assert "orders" in portfolio.categories
        assert "margin" in portfolio.categories
        assert "risk_metrics" in portfolio.categories

    def test_auth_silo_categories(self):
        silos = self.template.create_silos(self.silo_manager)
        auth = silos["auth"]

        assert "compliance_alerts" in auth.categories
        assert "trade_surveillance" in auth.categories

    def test_silos_are_encrypted(self):
        silos = self.template.create_silos(self.silo_manager)
        for name, silo in silos.items():
            assert silo.encrypted is True, f"{name} silo should be encrypted"

    def test_silo_hkdf_info_format(self):
        silos = self.template.create_silos(self.silo_manager)
        for name, silo in silos.items():
            assert silo.hkdf_info.startswith("bedrock:silo:investment:"), \
                f"{name} silo has wrong hkdf prefix"

    def test_silo_isolation_portfolio_not_in_identity(self):
        silos = self.template.create_silos(self.silo_manager)
        identity = silos["identity"]
        portfolio_categories = {"holdings", "transactions", "orders", "margin"}
        overlap = set(identity.categories) & portfolio_categories
        assert len(overlap) == 0, \
            f"Identity silo contains portfolio categories: {overlap}"

    def test_accreditation_in_identity_only(self):
        """Accreditation status must be in identity silo (KYC)."""
        silos = self.template.create_silos(self.silo_manager)
        assert "accreditation" in silos["identity"].categories
        assert "accreditation" not in silos["portfolio"].categories

    def test_trade_surveillance_in_auth_only(self):
        """Trade surveillance must be in auth silo (FINRA 3110)."""
        silos = self.template.create_silos(self.silo_manager)
        assert "trade_surveillance" in silos["auth"].categories
        assert "trade_surveillance" not in silos["portfolio"].categories


class TestInvestmentConsentFlows:
    """Test investment consent flow patterns."""

    def setup_method(self):
        self.template = InvestmentTemplate(mode="developer")

    def test_account_opening_flow(self):
        consent = self.template.request_account_opening("client-42")

        assert consent.status == ConsentStatus.PENDING
        assert consent.source_silo == "identity"
        assert consent.target_silo == "portfolio"
        assert "kyc_documents" in consent.categories
        assert "accreditation" in consent.categories

    def test_trade_execution_flow(self):
        consent = self.template.request_trade_execution(
            client_id="client-42",
            reason="Buy 100 shares AAPL",
        )

        assert consent.status == ConsentStatus.PENDING
        assert consent.source_silo == "portfolio"
        assert consent.scope == "write"
        assert "orders" in consent.categories
        assert "margin" in consent.categories

    def test_advisory_flow(self):
        consent = self.template.request_advisory(
            advisor_id="advisor-001",
            client_id="client-42",
        )

        assert consent.status == ConsentStatus.PENDING
        assert "holdings" in consent.categories
        assert "risk_metrics" in consent.categories

    def test_trade_execution_has_shortest_ttl(self):
        """Trade execution TTL is shortest (5 min) for security."""
        trade_flow = INVESTMENT_CONSENT_FLOWS["trade_execution"]
        for name, flow in INVESTMENT_CONSENT_FLOWS.items():
            if name != "trade_execution":
                assert trade_flow.default_ttl_seconds <= flow.default_ttl_seconds, \
                    f"Trade TTL should be shortest, but {name} is shorter"

    def test_consent_flows_have_sec_finra_sections(self):
        for name, flow in INVESTMENT_CONSENT_FLOWS.items():
            assert len(flow.sec_finra_sections) > 0, \
                f"{name} flow has no SEC/FINRA sections mapped"

    def test_account_opening_has_kyc_mapping(self):
        flow = INVESTMENT_CONSENT_FLOWS["account_opening"]
        assert "aml_kyc" in flow.sec_finra_sections

    def test_trade_execution_has_suitability_mapping(self):
        flow = INVESTMENT_CONSENT_FLOWS["trade_execution"]
        assert "finra_2111_suitability" in flow.sec_finra_sections

    def test_advisory_has_best_interest_mapping(self):
        flow = INVESTMENT_CONSENT_FLOWS["advisory"]
        assert "rbi_15l_duty" in flow.sec_finra_sections

    def test_all_flows_distinct_ids(self):
        types = [f.flow_type for f in INVESTMENT_CONSENT_FLOWS.values()]
        assert len(types) == len(set(types))


class TestInvestmentConfiguration:
    """Test investment-specific CoreConfig settings."""

    def test_developer_mode_config(self):
        template = InvestmentTemplate(mode="developer")
        config = template.get_config()

        assert config.environment == "development"
        assert config.licensing.dev_mode is True

    def test_production_mode_config(self):
        template = InvestmentTemplate(mode="production")
        config = template.get_config()

        assert config.environment == "production"
        assert config.licensing.dev_mode is False

    def test_sec_17a4_audit_retention(self):
        """SEC 17a-4 requires 5-6 year retention."""
        template = InvestmentTemplate(mode="production")
        config = template.get_config()

        assert config.audit.retention_years >= 5

    def test_sec_consent_requires_reason(self):
        template = InvestmentTemplate(mode="production")
        config = template.get_config()

        assert config.data_separation.consent_require_reason is True

    def test_sec_strict_silo_mode(self):
        template = InvestmentTemplate(mode="production")
        config = template.get_config()

        assert config.data_separation.silo_strict_mode is True

    def test_mfa_required(self):
        template = InvestmentTemplate(mode="production")
        config = template.get_config()

        assert config.access_control.mfa_required is True

    def test_session_timeout_investment(self):
        """Investment sessions: 30 min default, 8 hour max."""
        template = InvestmentTemplate(mode="production")
        config = template.get_config()

        assert config.access_control.session_ttl_seconds == 1800
        assert config.access_control.session_max_ttl_seconds == 28800


class TestInvestmentRoles:
    """Test investment role-portal mappings."""

    def test_client_role(self):
        assert "patient" in INVESTMENT_ROLES["client"]["portals"]

    def test_advisor_role(self):
        assert "provider" in INVESTMENT_ROLES["advisor"]["portals"]

    def test_trader_role(self):
        assert "provider" in INVESTMENT_ROLES["trader"]["portals"]

    def test_compliance_role(self):
        assert "admin" in INVESTMENT_ROLES["compliance"]["portals"]

    def test_regulator_role(self):
        assert "partner" in INVESTMENT_ROLES["regulator"]["portals"]

    def test_client_cannot_write(self):
        """Client role is read-only for their own data."""
        perms = INVESTMENT_ROLES["client"]["permissions"]
        assert "data.read" in perms
        assert "data.write" not in perms

    def test_advisor_can_write(self):
        """Advisor can write (recommendations, orders)."""
        perms = INVESTMENT_ROLES["advisor"]["permissions"]
        assert "data.write" in perms

    def test_trader_can_write(self):
        """Trader can write (execute trades)."""
        perms = INVESTMENT_ROLES["trader"]["permissions"]
        assert "data.write" in perms

    def test_regulator_cannot_write(self):
        """Regulator has read-only access (SEC/FINRA examiner)."""
        perms = INVESTMENT_ROLES["regulator"]["permissions"]
        assert "data.read" in perms
        assert "data.write" not in perms

    def test_compliance_can_quarantine(self):
        """Compliance can quarantine nodes (FINRA 3110 supervision)."""
        perms = INVESTMENT_ROLES["compliance"]["permissions"]
        assert "node.quarantine" in perms

    def test_minimum_necessary_enforcement(self):
        """All roles except client have minimum necessary standard."""
        for role, config in INVESTMENT_ROLES.items():
            if role == "client":
                assert config["sec_minimum_necessary"] is False
            else:
                assert config["sec_minimum_necessary"] is True


class TestSECFINRAComplianceReport:
    """Test SEC/FINRA compliance mapping completeness."""

    def setup_method(self):
        self.template = InvestmentTemplate(mode="developer")

    def test_compliance_report_has_reg_s_p(self):
        report = self.template.sec_finra_compliance_report()
        assert "reg_s_p_privacy" in report["mappings"]

    def test_compliance_report_has_reg_best_interest(self):
        report = self.template.sec_finra_compliance_report()
        assert "reg_best_interest" in report["mappings"]

    def test_compliance_report_has_finra_rules(self):
        report = self.template.sec_finra_compliance_report()
        assert "finra_rules" in report["mappings"]

    def test_compliance_report_has_sec_17a_4(self):
        report = self.template.sec_finra_compliance_report()
        assert "sec_17a_4_records" in report["mappings"]

    def test_compliance_report_has_aml_bsa(self):
        report = self.template.sec_finra_compliance_report()
        assert "aml_bsa" in report["mappings"]

    def test_compliance_report_lists_all_silos(self):
        report = self.template.sec_finra_compliance_report()
        assert set(report["silos"]) == {"identity", "portfolio", "auth"}

    def test_compliance_report_lists_all_flows(self):
        report = self.template.sec_finra_compliance_report()
        assert set(report["consent_flows"]) == {
            "account_opening", "trade_execution", "advisory",
            "audit_review", "third_party_sharing",
        }

    def test_encryption_mapping(self):
        report = self.template.sec_finra_compliance_report()
        assert "encryption_at_rest" in report["enforcement_summary"]

    def test_supervision_mapping(self):
        report = self.template.sec_finra_compliance_report()
        assert "supervision" in report["enforcement_summary"]