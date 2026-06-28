"""
Investment Vertical Template — SEC/FINRA-compliant data architecture.

Pre-configured silo definitions, consent flows, and compliance mappings
for investment advisors, broker-dealers, and wealth management.

This template provides:
1. Silo definitions (identity, portfolio, auth) with SEC/FINRA category mapping
2. Consent flow patterns (account_opening, trade_execution, advisory, audit_review)
3. Role-portal mappings for investment firms
4. SEC/FINRA compliance mapping report
5. Configuration presets tuned for SEC Regulation S-P and FINRA rules

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
# Investment Silo Definitions
# ---------------------------------------------------------------------------

INVESTMENT_SILOS = {
    "identity": {
        "display_name": "Client Identity",
        "categories": [
            "demographics", "contact", "ssn", "employment", "income",
            "accreditation", "kyc_documents", "beneficial_ownership",
        ],
        "description": "PII silo — client identity, KYC/AML documents, SSN, "
                       "accreditation status, beneficial ownership. Breach reveals "
                       "personal identity but never portfolio positions.",
        "hkdf_info": "bedrock:silo:investment:identity:v1",
    },
    "portfolio": {
        "display_name": "Portfolio & Positions",
        "categories": [
            "account_balances", "holdings", "transactions", "orders",
            "performance", "fees", "margin", "risk_metrics",
        ],
        "description": "Financial silo — portfolio holdings, transaction history, "
                       "order book, performance data, margin positions. Breach "
                       "reveals financial positions but cannot link to identity.",
        "hkdf_info": "bedrock:silo:investment:portfolio:v1",
    },
    "auth": {
        "display_name": "Authentication & Compliance",
        "categories": [
            "credentials", "sessions", "mfa", "compliance_alerts",
            "trade_surveillance", "audit_tokens",
        ],
        "description": "Auth & compliance silo — login credentials, session tokens, "
                       "MFA secrets, compliance alerts, trade surveillance flags. "
                       "Isolated from both identity and portfolio data.",
        "hkdf_info": "bedrock:silo:investment:auth:v1",
    },
}

# SEC/FINRA mapping: which regulation sections apply to which silos/categories
SEC_FINRA_MAPPINGS = {
    "reg_s_p_privacy": {
        "sp_248_3_privacy_notice": {
            "description": "Privacy notice — provide clear privacy notice to customers",
            "silos": ["identity"],
            "categories": ["demographics", "contact"],
            "enforcement": "consent_required",
        },
        "sp_248_7_opt_out": {
            "description": "Opt-out — customers must be able to opt out of information sharing",
            "silos": ["identity"],
            "categories": ["demographics", "contact", "ssn"],
            "enforcement": "consent_required",
        },
        "sp_248_13_safeguards": {
            "description": "Safeguards — protect customer information",
            "silos": ["identity", "portfolio", "auth"],
            "categories": ["*"],
            "enforcement": "encryption_at_rest",
        },
    },
    "reg_best_interest": {
        "rbi_15l_duty": {
            "description": "Best interest — act in customer's best interest when recommending",
            "silos": ["portfolio"],
            "categories": ["holdings", "orders", "risk_metrics"],
            "enforcement": "audit_logging",
        },
        "rbi_disclosure": {
            "description": "Disclosure — material conflicts of interest must be disclosed",
            "silos": ["portfolio"],
            "categories": ["fees", "margin"],
            "enforcement": "audit_logging",
        },
    },
    "finra_rules": {
        "finra_2111_suitability": {
            "description": "Suitability — recommendations must be suitable for the customer",
            "silos": ["portfolio"],
            "categories": ["holdings", "risk_metrics", "margin"],
            "enforcement": "audit_logging",
        },
        "finra_3110_supervision": {
            "description": "Supervision — supervise trading activity for compliance",
            "silos": ["auth"],
            "categories": ["trade_surveillance", "compliance_alerts"],
            "enforcement": "rbac_enforced",
        },
        "finra_4512_records": {
            "description": "Records — maintain books and records for required periods",
            "silos": ["identity", "portfolio", "auth"],
            "categories": ["*"],
            "enforcement": "audit_retention",
        },
    },
    "sec_17a_4_records": {
        "17a_4_retention": {
            "description": "Record retention — preserve records for 5-6 years",
            "silos": ["identity", "portfolio", "auth"],
            "categories": ["*"],
            "enforcement": "audit_retention",
        },
    },
    "aml_bsa": {
        "aml_kyc": {
            "description": "Customer identification — verify identity before opening account",
            "silos": ["identity"],
            "categories": ["kyc_documents", "ssn", "beneficial_ownership"],
            "enforcement": "consent_required",
        },
        "aml_sar": {
            "description": "Suspicious activity reporting — flag and report suspicious transactions",
            "silos": ["auth"],
            "categories": ["compliance_alerts", "trade_surveillance"],
            "enforcement": "audit_logging",
        },
    },
}


# ---------------------------------------------------------------------------
# Investment Consent Flows
# ---------------------------------------------------------------------------

class InvestmentConsentFlowType:
    """Standard investment consent flow types."""
    ACCOUNT_OPENING = "account_opening"       # KYC/AML for new accounts
    TRADE_EXECUTION = "trade_execution"       # Trade order execution
    ADVISORY = "advisory"                      # Investment advice delivery
    AUDIT_REVIEW = "audit_review"              # Regulatory audit access
    THIRD_PARTY_SHARING = "third_party_sharing"  # Data sharing with custodian/clearing


@dataclass
class InvestmentConsentFlowConfig:
    """Configuration for an investment consent flow pattern."""
    flow_type: str
    source_silo: str
    target_silo: str
    categories: List[str]
    scope: str
    default_ttl_seconds: int
    require_reason: bool
    sec_finra_sections: List[str] = field(default_factory=list)
    description: str = ""


INVESTMENT_CONSENT_FLOWS = {
    # Account opening: KYC/AML verification for new client accounts
    # Reg S-P 248.13, AML/BSA
    "account_opening": InvestmentConsentFlowConfig(
        flow_type=InvestmentConsentFlowType.ACCOUNT_OPENING,
        source_silo="identity",
        target_silo="portfolio",
        categories=["demographics", "ssn", "employment", "income",
                     "accreditation", "kyc_documents", "beneficial_ownership"],
        scope="read",
        default_ttl_seconds=86400,  # 24 hours — account opening takes time
        require_reason=True,
        sec_finra_sections=["sp_248_13_safeguards", "aml_kyc"],
        description="Account opening — KYC/AML verification for new client. "
                    "Cross-silo consent links identity data to portfolio for "
                    "suitability determination and accreditation verification.",
    ),
    # Trade execution: Client authorizes trade execution
    # FINRA 2111 (suitability), Reg BI (best interest)
    "trade_execution": InvestmentConsentFlowConfig(
        flow_type=InvestmentConsentFlowType.TRADE_EXECUTION,
        source_silo="portfolio",
        target_silo="identity",
        categories=["holdings", "orders", "margin", "risk_metrics"],
        scope="write",
        default_ttl_seconds=300,   # 5 minutes — trades execute quickly
        require_reason=True,
        sec_finra_sections=["finra_2111_suitability", "rbi_15l_duty"],
        description="Trade execution — client authorizes order execution. "
                    "Short TTL, full audit trail per FINRA 4512.",
    ),
    # Advisory: Investment advice delivery
    # Reg BI (best interest), FINRA 2111 (suitability)
    "advisory": InvestmentConsentFlowConfig(
        flow_type=InvestmentConsentFlowType.ADVISORY,
        source_silo="portfolio",
        target_silo="identity",
        categories=["holdings", "performance", "risk_metrics", "fees"],
        scope="read",
        default_ttl_seconds=3600,  # 1 hour
        require_reason=True,
        sec_finra_sections=["rbi_15l_duty", "rbi_disclosure", "finra_2111_suitability"],
        description="Advisory — advisor accesses portfolio for recommendations. "
                    "Best interest obligation per Reg BI; conflicts disclosed.",
    ),
    # Audit review: Regulator or internal audit reviews
    # SEC 17a-4, FINRA 4512
    "audit_review": InvestmentConsentFlowConfig(
        flow_type=InvestmentConsentFlowType.AUDIT_REVIEW,
        source_silo="auth",
        target_silo="portfolio",
        categories=["trade_surveillance", "compliance_alerts"],
        scope="read",
        default_ttl_seconds=86400,  # 24 hours — audits take time
        require_reason=True,
        sec_finra_sections=["finra_3110_supervision", "17a_4_retention"],
        description="Audit review — regulator or internal compliance reviews "
                    "trade surveillance and compliance alerts. Full audit trail "
                    "per SEC 17a-4 retention requirements.",
    ),
    # Third-party sharing: Data sharing with custodian/clearing firm
    # Reg S-P 248.7 (opt-out), 248.13 (safeguards)
    "third_party_sharing": InvestmentConsentFlowConfig(
        flow_type=InvestmentConsentFlowType.THIRD_PARTY_SHARING,
        source_silo="identity",
        target_silo="portfolio",
        categories=["demographics", "contact", "account_balances", "holdings"],
        scope="read",
        default_ttl_seconds=3600,
        require_reason=True,
        sec_finra_sections=["sp_248_7_opt_out", "sp_248_13_safeguards"],
        description="Third-party sharing — client authorizes sharing with "
                    "custodian or clearing firm. Opt-out right per Reg S-P. "
                    "Only minimum necessary data flows.",
    ),
}


# ---------------------------------------------------------------------------
# Investment Role-Portal Mapping
# ---------------------------------------------------------------------------

INVESTMENT_ROLES = {
    "client": {
        "portals": ["patient"],  # Self-service portal
        "permissions": [
            "data.read", "consent.request", "consent.approve",
        ],
        "description": "Investment client accessing their own portfolio.",
        "sec_minimum_necessary": False,  # Clients see all their own data
    },
    "advisor": {
        "portals": ["provider"],
        "permissions": [
            "data.read", "data.write", "consent.request", "consent.approve",
            "cert.issue", "audit.read",
        ],
        "description": "Registered investment advisor. Best interest obligation.",
        "sec_minimum_necessary": True,
    },
    "trader": {
        "portals": ["provider"],
        "permissions": [
            "data.read", "data.write", "consent.request", "audit.read",
        ],
        "description": "Trader executing orders. Suitability obligation.",
        "sec_minimum_necessary": True,
    },
    "compliance": {
        "portals": ["admin"],
        "permissions": [
            "data.read", "consent.request", "node.register", "node.quarantine",
            "audit.read", "cert.issue", "cert.revoke",
        ],
        "description": "Compliance officer. Supervision per FINRA 3110.",
        "sec_minimum_necessary": True,
    },
    "regulator": {
        "portals": ["partner"],
        "permissions": [
            "data.read", "audit.read",
        ],
        "description": "SEC/FINRA examiner. Read-only audit access.",
        "sec_minimum_necessary": True,
    },
}


# ---------------------------------------------------------------------------
# Investment Template Class
# ---------------------------------------------------------------------------

class InvestmentTemplate:
    """Pre-configured Bedrock instance for investment applications.

    Sets up silos, consent flows, roles, and configuration tuned for
    SEC Regulation S-P, Regulation Best Interest, and FINRA compliance.

    Usage:
        template = InvestmentTemplate()
        client = template.create_client()

        # Create investment silos
        silos = template.create_silos(silo_manager)

        # Start an account opening consent flow
        consent = template.request_account_opening("client-42")
    """

    def __init__(self, mode: str = "developer"):
        self.mode = mode
        self._silo_manager: Optional[SiloManager] = None
        self._consent_gate: Optional[ConsentGate] = None

    def create_silos(self, silo_manager: SiloManager) -> Dict[str, Silo]:
        """Create the standard investment silo configuration."""
        silos = {}
        for name, config in INVESTMENT_SILOS.items():
            silo = silo_manager.create_silo(
                name=name,
                display_name=config["display_name"],
                categories=config["categories"],
                description=config["description"],
                hkdf_info=config["hkdf_info"],
            )
            silos[name] = silo
        return silos

    def request_account_opening(self, client_id: str,
                                reason: str = "") -> ConsentEvent:
        """Start an account opening flow (KYC/AML verification)."""
        if not self._consent_gate:
            self._consent_gate = ConsentGate()
        flow = INVESTMENT_CONSENT_FLOWS["account_opening"]
        return self._consent_gate.request_consent(
            requesting_node_id=client_id,
            source_silo=flow.source_silo,
            target_silo=flow.target_silo,
            categories=flow.categories,
            scope=flow.scope,
            reason=reason or flow.description,
        )

    def request_trade_execution(self, client_id: str,
                                reason: str = "") -> ConsentEvent:
        """Start a trade execution flow (order authorization)."""
        if not self._consent_gate:
            self._consent_gate = ConsentGate()
        flow = INVESTMENT_CONSENT_FLOWS["trade_execution"]
        return self._consent_gate.request_consent(
            requesting_node_id=client_id,
            source_silo=flow.source_silo,
            target_silo=flow.target_silo,
            categories=flow.categories,
            scope=flow.scope,
            reason=reason or flow.description,
        )

    def request_advisory(self, advisor_id: str,
                         client_id: str,
                         reason: str = "") -> ConsentEvent:
        """Start an advisory flow (investment advice delivery)."""
        if not self._consent_gate:
            self._consent_gate = ConsentGate()
        flow = INVESTMENT_CONSENT_FLOWS["advisory"]
        return self._consent_gate.request_consent(
            requesting_node_id=advisor_id,
            source_silo=flow.source_silo,
            target_silo=flow.target_silo,
            categories=flow.categories,
            scope=flow.scope,
            reason=reason or flow.description,
        )

    def get_config(self) -> CoreConfig:
        """Get a CoreConfig pre-configured for SEC/FINRA compliance.

        Applies investment-specific settings:
        - 6-year audit retention (SEC 17a-4)
        - Short trade execution TTL (5 minutes)
        - MFA required for all remote access
        - Strict consent mode
        """
        return CoreConfig(
            environment="production" if self.mode != "developer" else "development",
            data_separation=DataSeparationConfig(
                silo_strict_mode=True,
                consent_default_ttl_seconds=1800,  # 30 minutes
                consent_max_ttl_seconds=86400,        # 24 hours max
                consent_require_reason=True,
            ),
            audit=AuditConfig(
                retention_years=6,  # SEC 17a-4 requires 5-6 years
                chain_export_format="jsonl",
            ),
            access_control=AccessControlConfig(
                mfa_required=True,  # Required for remote access
                session_ttl_seconds=1800,   # 30 minutes
                session_max_ttl_seconds=28800,  # 8 hours max
                lockout_max_attempts=5,
                lockout_duration_seconds=900,  # 15 minutes
                rate_limit_enabled=True,
                rate_limit_requests_per_minute=60,
            ),
            licensing=LicensingConfig(
                tier=self.mode,
                dev_mode=(self.mode == "developer"),
            ),
        )

    @staticmethod
    def sec_finra_compliance_report() -> Dict:
        """Generate a SEC/FINRA compliance mapping report.

        Maps each regulation to the Bedrock features that enforce it.
        """
        return {
            "template": "investment",
            "version": "1.0.0",
            "regulation": "SEC Regulation S-P, Regulation Best Interest, FINRA Rules",
            "silos": list(INVESTMENT_SILOS.keys()),
            "consent_flows": list(INVESTMENT_CONSENT_FLOWS.keys()),
            "mappings": SEC_FINRA_MAPPINGS,
            "enforcement_summary": {
                "encryption_at_rest": "All silos encrypted with AES-256-GCM, "
                                      "per-silo HKDF-derived keys",
                "consent_required": "Cross-silo data access gated by explicit consent "
                                    "(Reg S-P opt-out rights)",
                "minimum_necessary": "Silo categories limit disclosure scope per "
                                     "Reg BI best interest obligation",
                "audit_trail": "SHA-256 hash chain, 6-year retention per SEC 17a-4, "
                               "tamper-evident",
                "access_control": "RBAC with MFA, session scoping, suitability "
                                  "tracking per FINRA 2111",
                "breach_isolation": "Self-healing mesh isolates compromised nodes",
                "supervision": "Trade surveillance and compliance alerts in auth silo "
                              "per FINRA 3110",
            },
        }