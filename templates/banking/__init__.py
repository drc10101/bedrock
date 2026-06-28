"""
Banking Vertical Template — PCI-DSS-compliant data architecture.

Pre-configured silo definitions, consent flows, and compliance mappings
for banking and financial services.

This template provides:
1. Silo definitions (identity, transactions, auth) with PCI-DSS category mapping
2. Consent flow patterns (account inquiry, fund transfer, loan application, fraud review)
3. Role-portal mappings for banking
4. PCI-DSS compliance mapping report
5. Configuration presets tuned for PCI-DSS requirements

SPDX-License-Identifier: BSL-1.1 — See LICENSE for details.
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional

from bedrock.config import (
    CoreConfig, EncryptionConfig, IdentityConfig,
    DataSeparationConfig, AuditConfig, AccessControlConfig,
    MeshConfig, LicensingConfig,
)
from bedrock.data_separation.silo import Silo, SiloManager
from bedrock.data_separation.consent import ConsentGate, ConsentEvent, ConsentStatus


# ---------------------------------------------------------------------------
# Banking Silo Definitions
# ---------------------------------------------------------------------------

BANKING_SILOS = {
    "identity": {
        "display_name": "Customer Identity",
        "categories": [
            "demographics", "contact", "ssn", "employment", "income",
            "kyc_documents", "credit_score",
        ],
        "description": "PII silo — customer identity, KYC documents, SSN, income "
                       "verification. Breach reveals personal identity but never "
                       "transaction details or account balances.",
        "hkdf_info": "bedrock:silo:banking:identity:v1",
    },
    "transactions": {
        "display_name": "Account Transactions",
        "categories": [
            "account_balances", "deposits", "withdrawals", "transfers",
            "payment_cards", "loans", "fees", "interest",
        ],
        "description": "Financial silo — account balances, transactions, payment "
                       "cards, loans. Breach reveals financial activity but cannot "
                       "link to personal identity without consent.",
        "hkdf_info": "bedrock:silo:banking:transactions:v1",
    },
    "auth": {
        "display_name": "Authentication & Security",
        "categories": [
            "credentials", "sessions", "mfa", "security_questions",
            "device_fingerprints", "audit_tokens",
        ],
        "description": "Auth silo — login credentials, session tokens, MFA secrets, "
                       "device fingerprints. Isolated from both identity and transactions.",
        "hkdf_info": "bedrock:silo:banking:auth:v1",
    },
}

# PCI-DSS mapping: which requirement sections apply to which silos/categories
PCI_DSS_MAPPINGS = {
    "requirement_3_protect_stored_data": {
        "3.2_keep_cryptographic_keys_secure": {
            "description": "Protect cryptographic keys used for cardholder data encryption",
            "silos": ["transactions"],
            "categories": ["payment_cards"],
            "enforcement": "encryption_at_rest",
        },
        "3.4_render_pantry_unreadable": {
            "description": "Render PAN unreadable anywhere it is stored",
            "silos": ["transactions"],
            "categories": ["payment_cards"],
            "enforcement": "encryption_at_rest",
        },
        "3.5_document_and_implement_key_management": {
            "description": "Document and implement key management procedures",
            "silos": ["auth", "transactions"],
            "categories": ["*"],
            "enforcement": "key_rotation_policy",
        },
    },
    "requirement_4_encrypt_transmission": {
        "4.1_strong_cryptography_transmission": {
            "description": "Use strong cryptography for transmitting cardholder data",
            "silos": ["transactions"],
            "categories": ["payment_cards", "transfers"],
            "enforcement": "tls_enforcement",
        },
    },
    "requirement_5_malware": {
        "5.1_5.4_anti_malware": {
            "description": "Protect against malicious software",
            "silos": ["auth"],
            "categories": ["device_fingerprints"],
            "enforcement": "mesh_self_healing",
        },
    },
    "requirement_6_secure_systems": {
        "6.1_vulnerability_management": {
            "description": "Establish vulnerability management processes",
            "silos": ["auth"],
            "categories": ["credentials", "sessions"],
            "enforcement": "access_control",
        },
        "6.3_secure_software_development": {
            "description": "Develop and maintain secure systems and applications",
            "silos": ["auth"],
            "categories": ["*"],
            "enforcement": "rbac_enforced",
        },
    },
    "requirement_7_restrict_access": {
        "7.1_need_to_know": {
            "description": "Restrict access to cardholder data to need-to-know basis",
            "silos": ["identity", "transactions"],
            "categories": ["ssn", "payment_cards", "account_balances"],
            "enforcement": "consent_required",
        },
        "7.2_role_based_access": {
            "description": "Establish role-based access control",
            "silos": ["identity", "transactions", "auth"],
            "categories": ["*"],
            "enforcement": "rbac_enforced",
        },
    },
    "requirement_8_identify_users": {
        "8.1_unique_ids": {
            "description": "Assign unique ID to each person with computer access",
            "silos": ["auth"],
            "categories": ["credentials"],
            "enforcement": "unique_node_id",
        },
        "8.3_mfa": {
            "description": "Incorporate two-factor authentication for remote access",
            "silos": ["auth"],
            "categories": ["mfa", "sessions"],
            "enforcement": "mfa_required",
        },
        "8.6_accounts_for_apps": {
            "description": "Accounts for application and system management",
            "silos": ["auth"],
            "categories": ["credentials"],
            "enforcement": "rbac_enforced",
        },
    },
    "requirement_9_physical_access": {
        "9.1_physical_access_controls": {
            "description": "Use appropriate facility entry controls",
            "silos": [],
            "categories": [],
            "enforcement": "infrastructure_control",
        },
    },
    "requirement_10_track_monitor": {
        "10.1_audit_trails": {
            "description": "Track and monitor all access to network resources and cardholder data",
            "silos": ["identity", "transactions", "auth"],
            "categories": ["*"],
            "enforcement": "audit_logging",
        },
        "10.2_automatic_audit": {
            "description": "Implement automated audit trails for system events",
            "silos": ["auth"],
            "categories": ["audit_tokens"],
            "enforcement": "audit_chain",
        },
        "10.7_retention": {
            "description": "Retain audit trail history for at least one year",
            "silos": ["identity", "transactions", "auth"],
            "categories": ["*"],
            "enforcement": "audit_retention",
        },
    },
    "requirement_11_security_testing": {
        "11.3_penetration_testing": {
            "description": "Perform penetration testing at least annually",
            "silos": [],
            "categories": [],
            "enforcement": "security_testing",
        },
    },
    "requirement_12_information_security_policy": {
        "12.1_security_policy": {
            "description": "Establish and maintain security policies",
            "silos": ["auth"],
            "categories": ["*"],
            "enforcement": "policy_enforcement",
        },
    },
}


# ---------------------------------------------------------------------------
# Banking Consent Flows
# ---------------------------------------------------------------------------

class BankingConsentFlowType:
    """Standard banking consent flow types."""
    ACCOUNT_INQUIRY = "account_inquiry"       # Customer views their own accounts
    FUND_TRANSFER = "fund_transfer"            # Customer initiates a transfer
    LOAN_APPLICATION = "loan_application"      # Customer applies for a loan
    FRAUD_REVIEW = "fraud_review"              # Fraud analyst reviews flagged transactions
    THIRD_PARTY_SHARING = "third_party_sharing"  # Customer authorizes data sharing


@dataclass
class BankingConsentFlowConfig:
    """Configuration for a banking consent flow pattern."""
    flow_type: str
    source_silo: str
    target_silo: str
    categories: List[str]
    scope: str
    default_ttl_seconds: int
    require_reason: bool
    pci_dss_sections: List[str] = field(default_factory=list)
    description: str = ""


BANKING_CONSENT_FLOWS = {
    # Account inquiry: Customer views their own account data
    # PCI-DSS 7.1: need-to-know access; 8.3: MFA for remote access
    "account_inquiry": BankingConsentFlowConfig(
        flow_type=BankingConsentFlowType.ACCOUNT_INQUIRY,
        source_silo="transactions",
        target_silo="identity",
        categories=["account_balances", "deposits", "withdrawals", "fees", "interest"],
        scope="read",
        default_ttl_seconds=1800,  # 30 minutes — shorter for financial data
        require_reason=False,      # Customer viewing own data
        pci_dss_sections=["7.1_need_to_know", "8.3_mfa"],
        description="Account inquiry — customer views their own account balances "
                    "and transaction history. MFA required for remote access per "
                    "PCI-DSS 8.3.",
    ),
    # Fund transfer: Customer initiates money movement
    # PCI-DSS 7.1: need-to-know; 8.3: MFA; 10.1: audit trail
    "fund_transfer": BankingConsentFlowConfig(
        flow_type=BankingConsentFlowType.FUND_TRANSFER,
        source_silo="transactions",
        target_silo="identity",
        categories=["account_balances", "transfers", "payment_cards"],
        scope="write",
        default_ttl_seconds=600,   # 10 minutes — short for write operations
        require_reason=True,       # Money movement requires reason
        pci_dss_sections=["7.1_need_to_know", "8.3_mfa", "10.1_audit_trails"],
        description="Fund transfer — customer authorizes money movement. Short TTL, "
                    "MFA required, full audit trail per PCI-DSS 10.1.",
    ),
    # Loan application: Customer authorizes credit check and income verification
    # PCI-DSS 7.1: need-to-know; 3.4: PAN unreadable when stored
    "loan_application": BankingConsentFlowConfig(
        flow_type=BankingConsentFlowType.LOAN_APPLICATION,
        source_silo="identity",
        target_silo="transactions",
        categories=["demographics", "income", "kyc_documents", "credit_score", "loans"],
        scope="read",
        default_ttl_seconds=86400,  # 24 hours — applications take time
        require_reason=True,
        pci_dss_sections=["7.1_need_to_know", "3.4_render_pantry_unreadable"],
        description="Loan application — customer authorizes credit check and income "
                    "verification. Cross-silo consent links identity to transaction "
                    "history for underwriting.",
    ),
    # Fraud review: Analyst reviews flagged transactions
    # PCI-DSS 10.1: audit trail; 7.2: role-based access
    "fraud_review": BankingConsentFlowConfig(
        flow_type=BankingConsentFlowType.FRAUD_REVIEW,
        source_silo="transactions",
        target_silo="identity",
        categories=["transfers", "withdrawals", "payment_cards"],
        scope="read",
        default_ttl_seconds=3600,  # 1 hour
        require_reason=True,       # Must document fraud review reason
        pci_dss_sections=["10.1_audit_trails", "7.2_role_based_access"],
        description="Fraud review — analyst accesses flagged transactions for "
                    "investigation. Minimum necessary standard: only flagged "
                    "transaction categories, not full account history.",
    ),
    # Third-party sharing: Customer authorizes data sharing with partner
    # PCI-DSS 7.1: need-to-know; 3.4: PAN protection
    "third_party_sharing": BankingConsentFlowConfig(
        flow_type=BankingConsentFlowType.THIRD_PARTY_SHARING,
        source_silo="identity",
        target_silo="transactions",
        categories=["demographics", "contact", "account_balances"],
        scope="read",
        default_ttl_seconds=3600,
        require_reason=True,
        pci_dss_sections=["7.1_need_to_know", "3.4_render_pantry_unreadable"],
        description="Third-party sharing — customer authorizes sharing identity and "
                    "limited financial data with a partner. PAN is never shared; "
                    "only minimum necessary data flows.",
    ),
}


# ---------------------------------------------------------------------------
# Banking Role-Portal Mapping
# ---------------------------------------------------------------------------

BANKING_ROLES = {
    "customer": {
        "portals": ["patient"],   # Reusing patient portal for self-service
        "permissions": [
            "data.read", "consent.request", "consent.approve",
        ],
        "description": "Banking customer accessing their own accounts.",
        "pci_minimum_necessary": False,  # Customers see all their own data
    },
    "teller": {
        "portals": ["provider"],  # Reusing provider portal for internal staff
        "permissions": [
            "data.read", "data.write", "consent.request", "audit.read",
        ],
        "description": "Bank teller — limited read/write for in-branch transactions.",
        "pci_minimum_necessary": True,
    },
    "analyst": {
        "portals": ["provider"],
        "permissions": [
            "data.read", "consent.request", "audit.read",
        ],
        "description": "Fraud/compliance analyst — read-only, minimum necessary.",
        "pci_minimum_necessary": True,
    },
    "admin": {
        "portals": ["admin"],
        "permissions": [
            "data.read", "data.write", "consent.request", "consent.approve",
            "cert.issue", "cert.revoke", "node.register", "node.quarantine",
            "audit.read",
        ],
        "description": "System administrator with full access.",
        "pci_minimum_necessary": True,
    },
    "auditor": {
        "portals": ["partner"],
        "permissions": [
            "data.read", "audit.read",
        ],
        "description": "External auditor — read-only access to audit logs.",
        "pci_minimum_necessary": True,
    },
}


# ---------------------------------------------------------------------------
# Banking Template Class
# ---------------------------------------------------------------------------

class BankingTemplate:
    """Pre-configured Bedrock instance for banking applications.

    Sets up silos, consent flows, roles, and configuration tuned for PCI-DSS
    compliance.

    Usage:
        template = BankingTemplate()
        client = template.create_client()

        # Create banking silos
        silos = template.create_silos(silo_manager)

        # Start an account inquiry consent flow
        consent = template.request_account_inquiry("customer-42")
    """

    def __init__(self, mode: str = "developer"):
        self.mode = mode
        self._silo_manager: Optional[SiloManager] = None
        self._consent_gate: Optional[ConsentGate] = None

    def create_silos(self, silo_manager: SiloManager) -> Dict[str, Silo]:
        """Create the standard banking silo configuration."""
        silos = {}
        for name, config in BANKING_SILOS.items():
            silo = silo_manager.create_silo(
                name=name,
                display_name=config["display_name"],
                categories=config["categories"],
                description=config["description"],
                hkdf_info=config["hkdf_info"],
            )
            silos[name] = silo
        return silos

    def request_account_inquiry(self, customer_id: str,
                                reason: str = "") -> ConsentEvent:
        """Start an account inquiry flow (customer viewing own data)."""
        if not self._consent_gate:
            self._consent_gate = ConsentGate()
        flow = BANKING_CONSENT_FLOWS["account_inquiry"]
        return self._consent_gate.request_consent(
            requesting_node_id=customer_id,
            source_silo=flow.source_silo,
            target_silo=flow.target_silo,
            categories=flow.categories,
            scope=flow.scope,
            reason=reason or flow.description,
        )

    def request_fund_transfer(self, customer_id: str,
                              reason: str = "") -> ConsentEvent:
        """Start a fund transfer flow (money movement authorization)."""
        if not self._consent_gate:
            self._consent_gate = ConsentGate()
        flow = BANKING_CONSENT_FLOWS["fund_transfer"]
        return self._consent_gate.request_consent(
            requesting_node_id=customer_id,
            source_silo=flow.source_silo,
            target_silo=flow.target_silo,
            categories=flow.categories,
            scope=flow.scope,
            reason=reason or flow.description,
        )

    def request_loan_application(self, customer_id: str,
                                 reason: str = "") -> ConsentEvent:
        """Start a loan application flow (credit check authorization)."""
        if not self._consent_gate:
            self._consent_gate = ConsentGate()
        flow = BANKING_CONSENT_FLOWS["loan_application"]
        return self._consent_gate.request_consent(
            requesting_node_id=customer_id,
            source_silo=flow.source_silo,
            target_silo=flow.target_silo,
            categories=flow.categories,
            scope=flow.scope,
            reason=reason or flow.description,
        )

    def get_config(self) -> CoreConfig:
        """Get a CoreConfig pre-configured for PCI-DSS compliance.

        Applies banking-specific settings:
        - 1-year audit retention (PCI-DSS minimum)
        - Short session timeouts (30 min default, 2 hour max)
        - MFA required for all remote access
        - Strict consent mode with short TTLs
        """
        return CoreConfig(
            environment="production" if self.mode != "developer" else "development",
            data_separation=DataSeparationConfig(
                silo_strict_mode=True,
                consent_default_ttl_seconds=1800,  # 30 min — shorter for banking
                consent_max_ttl_seconds=86400,       # 24 hours max
                consent_require_reason=True,
            ),
            audit=AuditConfig(
                retention_years=1,  # PCI-DSS 10.7 minimum
                chain_export_format="jsonl",
            ),
            access_control=AccessControlConfig(
                mfa_required=True,  # PCI-DSS 8.3
                session_ttl_seconds=1800,   # 30 minutes
                session_max_ttl_seconds=7200,  # 2 hours max
                lockout_max_attempts=3,      # PCI-DSS: lock after 3 failed attempts
                lockout_duration_seconds=1800,
                rate_limit_enabled=True,
                rate_limit_requests_per_minute=30,
            ),
            licensing=LicensingConfig(
                tier=self.mode,
                dev_mode=(self.mode == "developer"),
            ),
        )

    @staticmethod
    def pci_dss_compliance_report() -> Dict:
        """Generate a PCI-DSS compliance mapping report.

        Maps each PCI-DSS requirement to the Bedrock features that enforce it.
        """
        return {
            "template": "banking",
            "version": "1.0.0",
            "regulation": "PCI-DSS v4.0",
            "silos": list(BANKING_SILOS.keys()),
            "consent_flows": list(BANKING_CONSENT_FLOWS.keys()),
            "mappings": PCI_DSS_MAPPINGS,
            "enforcement_summary": {
                "encryption_at_rest": "All silos encrypted with AES-256-GCM, "
                                      "per-silo HKDF-derived keys",
                "consent_required": "Cross-silo data access gated by explicit consent",
                "minimum_necessary": "Silo categories limit disclosure to minimum "
                                      "necessary data per PCI-DSS 7.1",
                "audit_trail": "SHA-256 hash chain, 1-year retention (PCI-DSS 10.7), "
                               "tamper-evident",
                "access_control": "RBAC with MFA, short session timeouts, "
                                  "3-attempt lockout per PCI-DSS 8.3-8.5",
                "breach_isolation": "Self-healing mesh isolates compromised nodes",
                "key_management": "Per-silo HKDF key derivation with versioned rotation",
            },
        }