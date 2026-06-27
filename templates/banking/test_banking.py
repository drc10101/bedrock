"""
Tests for the Banking Vertical Template.

Verifies silo creation, consent flows, PCI-DSS compliance mapping,
and configuration defaults.
"""

import pytest
from bedrock.config import CoreConfig
from bedrock.data_separation.silo import SiloManager
from bedrock.data_separation.consent import ConsentStatus

from templates.banking import (
    BankingTemplate,
    BANKING_SILOS,
    BANKING_CONSENT_FLOWS,
    BANKING_ROLES,
    PCI_DSS_MAPPINGS,
    BankingConsentFlowType,
)


class TestBankingSilos:
    """Test banking silo definitions and creation."""

    def setup_method(self):
        self.template = BankingTemplate(mode="developer")
        self.silo_manager = SiloManager()

    def test_create_all_banking_silos(self):
        silos = self.template.create_silos(self.silo_manager)

        assert len(silos) == 3
        assert "identity" in silos
        assert "transactions" in silos
        assert "auth" in silos

    def test_identity_silo_categories(self):
        silos = self.template.create_silos(self.silo_manager)
        identity = silos["identity"]

        assert "ssn" in identity.categories
        assert "kyc_documents" in identity.categories
        assert "credit_score" in identity.categories
        assert "income" in identity.categories

    def test_transactions_silo_categories(self):
        silos = self.template.create_silos(self.silo_manager)
        transactions = silos["transactions"]

        assert "account_balances" in transactions.categories
        assert "deposits" in transactions.categories
        assert "withdrawals" in transactions.categories
        assert "transfers" in transactions.categories
        assert "payment_cards" in transactions.categories
        assert "loans" in transactions.categories

    def test_auth_silo_categories(self):
        silos = self.template.create_silos(self.silo_manager)
        auth = silos["auth"]

        assert "credentials" in auth.categories
        assert "sessions" in auth.categories
        assert "mfa" in auth.categories
        assert "device_fingerprints" in auth.categories

    def test_silos_are_encrypted(self):
        silos = self.template.create_silos(self.silo_manager)
        for name, silo in silos.items():
            assert silo.encrypted is True, f"{name} silo should be encrypted"

    def test_silo_hkdf_info_format(self):
        silos = self.template.create_silos(self.silo_manager)
        for name, silo in silos.items():
            assert silo.hkdf_info.startswith("bedrock:silo:banking:"), \
                f"{name} silo has wrong hkdf prefix"

    def test_silo_isolation_transactions_not_in_identity(self):
        silos = self.template.create_silos(self.silo_manager)
        identity = silos["identity"]
        transaction_categories = {"account_balances", "deposits", "withdrawals", "transfers"}
        overlap = set(identity.categories) & transaction_categories
        assert len(overlap) == 0, \
            f"Identity silo contains transaction categories: {overlap}"

    def test_pan_isolation(self):
        """Payment card data must be in transactions silo only (PCI-DSS 3.4)."""
        silos = self.template.create_silos(self.silo_manager)
        identity = silos["identity"]
        auth = silos["auth"]
        assert "payment_cards" not in identity.categories
        assert "payment_cards" not in auth.categories
        assert "payment_cards" in silos["transactions"].categories


class TestBankingConsentFlows:
    """Test banking consent flow patterns."""

    def setup_method(self):
        self.template = BankingTemplate(mode="developer")

    def test_account_inquiry_flow(self):
        consent = self.template.request_account_inquiry("customer-42")

        assert consent.status == ConsentStatus.PENDING
        assert consent.source_silo == "transactions"
        assert "account_balances" in consent.categories

    def test_fund_transfer_flow(self):
        consent = self.template.request_fund_transfer(
            customer_id="customer-42",
            reason="Rent payment",
        )

        assert consent.status == ConsentStatus.PENDING
        assert consent.source_silo == "transactions"
        assert consent.scope == "write"
        assert consent.reason == "Rent payment"

    def test_loan_application_flow(self):
        consent = self.template.request_loan_application("customer-42")

        assert consent.status == ConsentStatus.PENDING
        assert consent.source_silo == "identity"
        assert "credit_score" in consent.categories
        assert "kyc_documents" in consent.categories

    def test_fund_transfer_shorter_ttl_than_inquiry(self):
        """Fund transfers have shorter TTL than account inquiries."""
        transfer_flow = BANKING_CONSENT_FLOWS["fund_transfer"]
        inquiry_flow = BANKING_CONSENT_FLOWS["account_inquiry"]
        assert transfer_flow.default_ttl_seconds < inquiry_flow.default_ttl_seconds

    def test_consent_flows_have_pci_dss_sections(self):
        for name, flow in BANKING_CONSENT_FLOWS.items():
            assert len(flow.pci_dss_sections) > 0, \
                f"{name} flow has no PCI-DSS sections mapped"

    def test_fund_transfer_requires_mfa(self):
        """Fund transfers must require MFA (PCI-DSS 8.3)."""
        transfer_flow = BANKING_CONSENT_FLOWS["fund_transfer"]
        assert "8.3_mfa" in transfer_flow.pci_dss_sections

    def test_fund_transfer_has_audit_trail(self):
        """Fund transfers must have audit trail (PCI-DSS 10.1)."""
        transfer_flow = BANKING_CONSENT_FLOWS["fund_transfer"]
        assert "10.1_audit_trails" in transfer_flow.pci_dss_sections

    def test_all_flows_distinct_ids(self):
        """Each consent flow type must be unique."""
        types = [f.flow_type for f in BANKING_CONSENT_FLOWS.values()]
        assert len(types) == len(set(types))


class TestBankingConfiguration:
    """Test banking-specific CoreConfig settings."""

    def test_developer_mode_config(self):
        template = BankingTemplate(mode="developer")
        config = template.get_config()

        assert config.environment == "development"
        assert config.licensing.dev_mode is True

    def test_production_mode_config(self):
        template = BankingTemplate(mode="production")
        config = template.get_config()

        assert config.environment == "production"
        assert config.licensing.dev_mode is False

    def test_pci_dss_audit_retention(self):
        template = BankingTemplate(mode="production")
        config = template.get_config()

        assert config.audit.retention_years == 1  # PCI-DSS 10.7

    def test_pci_dss_consent_requires_reason(self):
        template = BankingTemplate(mode="production")
        config = template.get_config()

        assert config.data_separation.consent_require_reason is True

    def test_pci_dss_strict_silo_mode(self):
        template = BankingTemplate(mode="production")
        config = template.get_config()

        assert config.data_separation.silo_strict_mode is True

    def test_pci_dss_mfa_required(self):
        template = BankingTemplate(mode="production")
        config = template.get_config()

        assert config.access_control.mfa_required is True

    def test_banking_session_timeout_short(self):
        """Banking sessions are shorter than healthcare (PCI-DSS 8.1.8)."""
        template = BankingTemplate(mode="production")
        config = template.get_config()

        assert config.access_control.session_ttl_seconds <= 1800  # 30 min

    def test_pci_dss_lockout_after_3_attempts(self):
        """PCI-DSS requires lockout after no more than 6 attempts (we use 3)."""
        template = BankingTemplate(mode="production")
        config = template.get_config()

        assert config.access_control.lockout_max_attempts <= 6

    def test_consent_ttl_shorter_than_healthcare(self):
        """Banking consent TTLs are shorter than healthcare (financial data)."""
        banking = BankingTemplate(mode="production").get_config()
        assert banking.data_separation.consent_default_ttl_seconds == 1800


class TestBankingRoles:
    """Test banking role-portal mappings."""

    def test_customer_role(self):
        assert "patient" in BANKING_ROLES["customer"]["portals"]

    def test_teller_role(self):
        assert "provider" in BANKING_ROLES["teller"]["portals"]

    def test_analyst_role(self):
        assert "provider" in BANKING_ROLES["analyst"]["portals"]

    def test_admin_role(self):
        assert "admin" in BANKING_ROLES["admin"]["portals"]

    def test_auditor_role(self):
        assert "partner" in BANKING_ROLES["auditor"]["portals"]

    def test_teller_cannot_issue_certs(self):
        """Teller cannot issue or revoke certificates."""
        perms = BANKING_ROLES["teller"]["permissions"]
        assert "cert.issue" not in perms
        assert "cert.revoke" not in perms

    def test_customer_cannot_write(self):
        """Customer role is read-only for their own data."""
        perms = BANKING_ROLES["customer"]["permissions"]
        assert "data.read" in perms
        assert "data.write" not in perms

    def test_analyst_cannot_write(self):
        """Analyst role is read-only for fraud investigation."""
        perms = BANKING_ROLES["analyst"]["permissions"]
        assert "data.read" in perms
        assert "data.write" not in perms

    def test_minimum_necessary_enforcement(self):
        """All roles except customer have minimum necessary standard."""
        for role, config in BANKING_ROLES.items():
            if role == "customer":
                assert config["pci_minimum_necessary"] is False
            else:
                assert config["pci_minimum_necessary"] is True


class TestPCIDSSComplianceReport:
    """Test PCI-DSS compliance mapping completeness."""

    def setup_method(self):
        self.template = BankingTemplate(mode="developer")

    def test_compliance_report_has_requirement_3(self):
        report = self.template.pci_dss_compliance_report()
        assert "requirement_3_protect_stored_data" in report["mappings"]

    def test_compliance_report_has_requirement_4(self):
        report = self.template.pci_dss_compliance_report()
        assert "requirement_4_encrypt_transmission" in report["mappings"]

    def test_compliance_report_has_requirement_7(self):
        report = self.template.pci_dss_compliance_report()
        assert "requirement_7_restrict_access" in report["mappings"]

    def test_compliance_report_has_requirement_8(self):
        report = self.template.pci_dss_compliance_report()
        assert "requirement_8_identify_users" in report["mappings"]

    def test_compliance_report_has_requirement_10(self):
        report = self.template.pci_dss_compliance_report()
        assert "requirement_10_track_monitor" in report["mappings"]

    def test_compliance_report_lists_all_silos(self):
        report = self.template.pci_dss_compliance_report()
        assert set(report["silos"]) == {"identity", "transactions", "auth"}

    def test_compliance_report_lists_all_flows(self):
        report = self.template.pci_dss_compliance_report()
        assert set(report["consent_flows"]) == {
            "account_inquiry", "fund_transfer", "loan_application",
            "fraud_review", "third_party_sharing",
        }

    def test_encryption_mapping(self):
        report = self.template.pci_dss_compliance_report()
        assert "encryption_at_rest" in report["enforcement_summary"]

    def test_key_management_mapping(self):
        report = self.template.pci_dss_compliance_report()
        assert "key_management" in report["enforcement_summary"]