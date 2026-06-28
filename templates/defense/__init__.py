"""
Defense Vertical Template — CMMC/DFARS-compliant data architecture.

Pre-configured silo definitions, consent flows, and compliance mappings
for defense contractors, cleared facilities, and CUI handling.

This template provides:
1. Silo definitions (identity, cui, auth) with CMMC category mapping
2. Consent flows (clearance_verification, cui_access, export_review, audit_review)
3. Role-portal mappings with clearance-level gating
4. CMMC/DFARS compliance mapping report
5. Configuration presets tuned for NIST 800-171 and CMMC Level 2/3

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
# Defense Silo Definitions
# ---------------------------------------------------------------------------

DEFENSE_SILOS = {
    "identity": {
        "display_name": "Personnel Identity",
        "categories": [
            "demographics", "contact", "ssn", "clearance_level",
            "clearance_type", "sponsorship", "investigation_status",
            "citizenship", "adjudication",
        ],
        "description": "PII + clearance silo — personnel identity, clearance level, "
                       "investigation status, citizenship. Breach reveals identity "
                       "and clearance status but never CUI content.",
        "hkdf_info": "bedrock:silo:defense:identity:v1",
    },
    "cui": {
        "display_name": "Controlled Unclassified Information",
        "categories": [
            "technical_data", "drawings", "specifications", "source_code",
            "operational_plans", "personnel_rosters", "logistics",
            "intelligence_reports", "mission_data", "communications",
        ],
        "description": "CUI silo — controlled unclassified information per NIST 800-171 "
                       "and 32 CFR 2002. Contains technical data, drawings, specifications, "
                       "operational plans. Breach reveals CUI but cannot link to personnel.",
        "hkdf_info": "bedrock:silo:defense:cui:v1",
    },
    "auth": {
        "display_name": "Authentication & Audit",
        "categories": [
            "credentials", "sessions", "mfa", "cui_access_logs",
            "export_reviews", "audit_tokens", "incident_reports",
        ],
        "description": "Auth & audit silo — login credentials, session tokens, MFA, "
                       "CUI access logs, export review records, incident reports. "
                       "Isolated from both identity and CUI data.",
        "hkdf_info": "bedrock:silo:defense:auth:v1",
    },
}

# Clearance levels for role gating
CLEARANCE_LEVELS = {
    "public": 0,
    "cui": 1,
    "secret": 2,
    "top_secret": 3,
    "top_secret_sci": 4,
}

# CMMC/DFARS mapping: which requirements apply to which silos/categories
CMMC_DFARS_MAPPINGS = {
    "cmmc_level_2": {
        "ac_1_access_control_policy": {
            "description": "Access control policy and procedures",
            "silos": ["identity", "cui", "auth"],
            "categories": ["*"],
            "enforcement": "rbac_enforced",
        },
        "ac_2_account_management": {
            "description": "Account management — unique IDs, role-based access",
            "silos": ["auth"],
            "categories": ["credentials", "sessions"],
            "enforcement": "unique_node_id",
        },
        "ac_3_access_enforcement": {
            "description": "Access enforcement — need-to-know, clearance-gated",
            "silos": ["identity", "cui"],
            "categories": ["clearance_level", "technical_data", "specifications"],
            "enforcement": "consent_required",
        },
        "au_2_audit_events": {
            "description": "Audit events — log all CUI access",
            "silos": ["auth"],
            "categories": ["cui_access_logs", "export_reviews"],
            "enforcement": "audit_logging",
        },
        "au_3_audit_content": {
            "description": "Audit content — capture who, what, when, where",
            "silos": ["identity", "cui", "auth"],
            "categories": ["*"],
            "enforcement": "audit_logging",
        },
        "au_6_audit_review": {
            "description": "Audit review — analyze audit logs for anomalies",
            "silos": ["auth"],
            "categories": ["cui_access_logs", "incident_reports"],
            "enforcement": "audit_chain",
        },
        "cm_2_configuration_management": {
            "description": "Configuration management — baseline and change control",
            "silos": ["auth"],
            "categories": ["*"],
            "enforcement": "rbac_enforced",
        },
        "ia_1_identification_authentication": {
            "description": "Identification and authentication — MFA for CUI access",
            "silos": ["auth"],
            "categories": ["credentials", "mfa", "sessions"],
            "enforcement": "mfa_required",
        },
        "mp_1_media_protection": {
            "description": "Media protection — protect CUI on media",
            "silos": ["cui"],
            "categories": ["*"],
            "enforcement": "encryption_at_rest",
        },
        "pe_1_physical_protection": {
            "description": "Physical protection — protect CUI systems",
            "silos": [],
            "categories": [],
            "enforcement": "infrastructure_control",
        },
        "sc_1_system_communications_protection": {
            "description": "System and communications protection — encrypt CUI in transit",
            "silos": ["cui", "auth"],
            "categories": ["*"],
            "enforcement": "tls_enforcement",
        },
    },
    "dfars_252_204_7012": {
        "7012_b_protection": {
            "description": "DFARS 7012 — Protect CUI as required by NIST 800-171",
            "silos": ["cui"],
            "categories": ["*"],
            "enforcement": "encryption_at_rest",
        },
        "7012_c_reporting": {
            "description": "DFARS 7012(c) — Report CUI breaches to DoD within 72 hours",
            "silos": ["auth"],
            "categories": ["incident_reports"],
            "enforcement": "breach_protocol",
        },
        "7012_d_flow_down": {
            "description": "DFARS 7012(d) — Flow down CUI requirements to subcontractors",
            "silos": ["identity", "cui", "auth"],
            "categories": ["*"],
            "enforcement": "policy_enforcement",
        },
    },
    "nist_800_171": {
        "3_1_access_control": {
            "description": "NIST 800-171 §3.1 — Limit system access to authorized users",
            "silos": ["identity", "cui"],
            "categories": ["clearance_level", "technical_data"],
            "enforcement": "rbac_enforced",
        },
        "3_3_audit_accountability": {
            "description": "NIST 800-171 §3.3 — Audit and accountability",
            "silos": ["auth"],
            "categories": ["cui_access_logs", "audit_tokens"],
            "enforcement": "audit_chain",
        },
        "3_5_identification_authentication": {
            "description": "NIST 800-171 §3.5 — Identification and authentication",
            "silos": ["auth"],
            "categories": ["credentials", "mfa", "sessions"],
            "enforcement": "mfa_required",
        },
        "3_10_media_protection": {
            "description": "NIST 800-171 §3.10 — Media protection",
            "silos": ["cui"],
            "categories": ["*"],
            "enforcement": "encryption_at_rest",
        },
        "3_13_system_protection": {
            "description": "NIST 800-171 §3.13 — System and communications protection",
            "silos": ["cui", "auth"],
            "categories": ["*"],
            "enforcement": "tls_enforcement",
        },
    },
}


# ---------------------------------------------------------------------------
# Defense Consent Flows
# ---------------------------------------------------------------------------

class DefenseConsentFlowType:
    """Standard defense consent flow types."""
    CLEARANCE_VERIFICATION = "clearance_verification"  # Verify clearance before CUI access
    CUI_ACCESS = "cui_access"                          # Access CUI after clearance check
    EXPORT_REVIEW = "export_review"                    # ITAR/EAR export control review
    AUDIT_REVIEW = "audit_review"                      # Inspector/auditor review


@dataclass
class DefenseConsentFlowConfig:
    """Configuration for a defense consent flow pattern."""
    flow_type: str
    source_silo: str
    target_silo: str
    categories: List[str]
    scope: str
    default_ttl_seconds: int
    require_reason: bool
    min_clearance: str
    cmmc_sections: List[str] = field(default_factory=list)
    description: str = ""


DEFENSE_CONSENT_FLOWS = {
    # Clearance verification: Verify clearance level before CUI access
    # NIST 800-171 §3.1, CMMC AC.3
    "clearance_verification": DefenseConsentFlowConfig(
        flow_type=DefenseConsentFlowType.CLEARANCE_VERIFICATION,
        source_silo="identity",
        target_silo="cui",
        categories=["clearance_level", "clearance_type", "investigation_status", "adjudication"],
        scope="read",
        default_ttl_seconds=28800,  # 8 hours — full workday
        require_reason=True,
        min_clearance="cui",
        cmmc_sections=["ac_3_access_enforcement", "3_1_access_control"],
        description="Clearance verification — confirm personnel clearance level "
                    "before granting CUI access. Cross-silo consent links "
                    "clearance status to CUI access authorization.",
    ),
    # CUI access: Access controlled unclassified information
    # NIST 800-171 §3.1, §3.10, CMMC MP.1, SC.1
    "cui_access": DefenseConsentFlowConfig(
        flow_type=DefenseConsentFlowType.CUI_ACCESS,
        source_silo="cui",
        target_silo="identity",
        categories=["technical_data", "drawings", "specifications", "operational_plans"],
        scope="read",
        default_ttl_seconds=3600,   # 1 hour — short for sensitive data
        require_reason=True,
        min_clearance="cui",
        cmmc_sections=["ac_3_access_enforcement", "mp_1_media_protection",
                        "sc_1_system_communications_protection"],
        description="CUI access — authorized personnel access controlled "
                    "unclassified information. Need-to-know basis, "
                    "minimum CUI clearance required.",
    ),
    # Export review: ITAR/EAR compliance review before data transfer
    # DFARS 7012(d), ITAR §126.1
    "export_review": DefenseConsentFlowConfig(
        flow_type=DefenseConsentFlowType.EXPORT_REVIEW,
        source_silo="cui",
        target_silo="identity",
        categories=["technical_data", "drawings", "specifications", "source_code"],
        scope="read",
        default_ttl_seconds=86400,  # 24 hours — reviews take time
        require_reason=True,
        min_clearance="secret",
        cmmc_sections=["7012_d_flow_down", "3_1_access_control"],
        description="Export review — ITAR/EAR compliance review before "
                    "data transfer to foreign persons or destinations. "
                    "Minimum Secret clearance required for reviewer.",
    ),
    # Audit review: DCSA/DoD inspector review
    # NIST 800-171 §3.3, CMMC AU.2, AU.6
    "audit_review": DefenseConsentFlowType.EXPORT_REVIEW  # placeholder, will be overwritten
    if False else None,
}

# Fix: replace None with proper config
DEFENSE_CONSENT_FLOWS["audit_review"] = DefenseConsentFlowConfig(
    flow_type=DefenseConsentFlowType.AUDIT_REVIEW,
    source_silo="auth",
    target_silo="cui",
    categories=["cui_access_logs", "export_reviews", "incident_reports"],
    scope="read",
    default_ttl_seconds=86400,  # 24 hours
    require_reason=True,
    min_clearance="secret",
    cmmc_sections=["au_2_audit_events", "au_6_audit_review", "3_3_audit_accountability"],
    description="Audit review — DCSA/DoD inspector reviews CUI access logs "
                "and export reviews. Full audit trail per NIST 800-171 §3.3.",
)

# Remove the placeholder None entry created by the conditional
if None in DEFENSE_CONSENT_FLOWS.values():
    # This won't happen since we overwrote audit_review above
    pass


# ---------------------------------------------------------------------------
# Defense Role-Portal Mapping
# ---------------------------------------------------------------------------

DEFENSE_ROLES = {
    "cleared_staff": {
        "portals": ["provider"],
        "permissions": [
            "data.read", "data.write", "consent.request", "consent.approve",
            "cert.issue", "audit.read",
        ],
        "description": "Cleared staff member with CUI access authorization.",
        "min_clearance": "cui",
        "dfars_minimum_necessary": True,
    },
    "program_manager": {
        "portals": ["admin"],
        "permissions": [
            "data.read", "data.write", "consent.request", "consent.approve",
            "cert.issue", "cert.revoke", "node.register", "node.quarantine",
            "audit.read",
        ],
        "description": "Program manager with full project access.",
        "min_clearance": "secret",
        "dfars_minimum_necessary": True,
    },
    "fso": {
        "portals": ["admin"],
        "permissions": [
            "data.read", "consent.request", "consent.approve",
            "cert.issue", "cert.revoke", "node.register", "node.quarantine",
            "audit.read",
        ],
        "description": "Facility Security Officer — clearance verification, "
                       "incident response, CUI access management.",
        "min_clearance": "top_secret",
        "dfars_minimum_necessary": True,
    },
    "subcontractor": {
        "portals": ["partner"],
        "permissions": [
            "data.read", "consent.request", "audit.read",
        ],
        "description": "Subcontractor with flow-down CUI requirements per DFARS 7012(d).",
        "min_clearance": "cui",
        "dfars_minimum_necessary": True,
    },
    "auditor": {
        "portals": ["partner"],
        "permissions": [
            "data.read", "audit.read",
        ],
        "description": "DCSA/DoD auditor. Read-only access to audit logs.",
        "min_clearance": "secret",
        "dfars_minimum_necessary": True,
    },
}


# ---------------------------------------------------------------------------
# Defense Template Class
# ---------------------------------------------------------------------------

class DefenseTemplate:
    """Pre-configured Bedrock instance for defense applications.

    Sets up silos, consent flows, roles, and configuration tuned for
    CMMC Level 2/3 and DFARS 252.204-7012 compliance.

    Usage:
        template = DefenseTemplate()
        client = template.create_client()

        # Create defense silos
        silos = template.create_silos(silo_manager)

        # Start a clearance verification flow
        consent = template.request_clearance_verification(
            personnel_id="staff-001",
            min_clearance="cui",
        )
    """

    def __init__(self, mode: str = "developer"):
        self.mode = mode
        self._silo_manager: Optional[SiloManager] = None
        self._consent_gate: Optional[ConsentGate] = None

    def create_silos(self, silo_manager: SiloManager) -> Dict[str, Silo]:
        """Create the standard defense silo configuration."""
        silos = {}
        for name, config in DEFENSE_SILOS.items():
            silo = silo_manager.create_silo(
                name=name,
                display_name=config["display_name"],
                categories=config["categories"],
                description=config["description"],
                hkdf_info=config["hkdf_info"],
            )
            silos[name] = silo
        return silos

    def request_clearance_verification(self, personnel_id: str,
                                       reason: str = "") -> ConsentEvent:
        """Start a clearance verification flow (pre-CUI access check)."""
        if not self._consent_gate:
            self._consent_gate = ConsentGate()
        flow = DEFENSE_CONSENT_FLOWS["clearance_verification"]
        return self._consent_gate.request_consent(
            requesting_node_id=personnel_id,
            source_silo=flow.source_silo,
            target_silo=flow.target_silo,
            categories=flow.categories,
            scope=flow.scope,
            reason=reason or flow.description,
        )

    def request_cui_access(self, personnel_id: str,
                           reason: str = "") -> ConsentEvent:
        """Start a CUI access flow (after clearance verification)."""
        if not self._consent_gate:
            self._consent_gate = ConsentGate()
        flow = DEFENSE_CONSENT_FLOWS["cui_access"]
        return self._consent_gate.request_consent(
            requesting_node_id=personnel_id,
            source_silo=flow.source_silo,
            target_silo=flow.target_silo,
            categories=flow.categories,
            scope=flow.scope,
            reason=reason or flow.description,
        )

    def get_config(self) -> CoreConfig:
        """Get a CoreConfig pre-configured for CMMC/DFARS compliance.

        Applies defense-specific settings:
        - 6-year audit retention (DFARS/DoD)
        - Strict consent mode (need-to-know)
        - MFA required for all CUI access
        - Short session timeouts
        - Account lockout after 3 attempts
        """
        return CoreConfig(
            environment="production" if self.mode != "developer" else "development",
            data_separation=DataSeparationConfig(
                silo_strict_mode=True,
                consent_default_ttl_seconds=3600,  # 1 hour
                consent_max_ttl_seconds=28800,       # 8 hours max
                consent_require_reason=True,          # Need-to-know
            ),
            audit=AuditConfig(
                retention_years=6,  # DFARS/DoD requirement
                chain_export_format="jsonl",
            ),
            access_control=AccessControlConfig(
                mfa_required=True,  # CMMC IA.1
                session_ttl_seconds=1800,   # 30 minutes
                session_max_ttl_seconds=28800,  # 8 hours (full workday)
                lockout_max_attempts=3,      # Strict for defense
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
    def check_clearance(role: str, required_level: str) -> bool:
        """Check if a role meets the minimum clearance requirement.

        Args:
            role: Role name from DEFENSE_ROLES
            required_level: Minimum clearance level required

        Returns:
            True if the role's clearance meets or exceeds the requirement
        """
        if role not in DEFENSE_ROLES:
            return False
        role_clearance = DEFENSE_ROLES[role]["min_clearance"]
        return CLEARANCE_LEVELS.get(role_clearance, 0) >= CLEARANCE_LEVELS.get(required_level, 0)

    @staticmethod
    def cmmc_compliance_report() -> Dict:
        """Generate a CMMC/DFARS compliance mapping report.

        Maps each CMMC practice and DFARS clause to the Bedrock features
        that enforce it.
        """
        return {
            "template": "defense",
            "version": "1.0.0",
            "regulation": "CMMC Level 2, DFARS 252.204-7012, NIST 800-171",
            "silos": list(DEFENSE_SILOS.keys()),
            "consent_flows": list(DEFENSE_CONSENT_FLOWS.keys()),
            "clearance_levels": CLEARANCE_LEVELS,
            "mappings": CMMC_DFARS_MAPPINGS,
            "enforcement_summary": {
                "encryption_at_rest": "All silos encrypted with AES-256-GCM, "
                                      "per-silo HKDF-derived keys",
                "consent_required": "Cross-silo data access gated by explicit consent "
                                    "(need-to-know basis)",
                "minimum_necessary": "Silo categories limit disclosure to minimum "
                                     "necessary per CMMC AC.3",
                "audit_trail": "SHA-256 hash chain, 6-year retention per DFARS, "
                               "tamper-evident",
                "access_control": "RBAC with MFA, clearance-gated access, "
                                  "3-attempt lockout per CMMC IA.1",
                "breach_isolation": "Self-healing mesh isolates compromised nodes",
                "breach_reporting": "72-hour breach notification per DFARS 7012(c)",
                "flow_down": "Subcontractor role enforces DFARS 7012(d) flow-down",
            },
        }