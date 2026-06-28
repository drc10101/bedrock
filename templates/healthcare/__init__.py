"""
Healthcare Vertical Template — HIPAA-compliant data architecture.

Pre-configured silo definitions, consent flows, and compliance mappings
extracted from InFill's proven PIR/ePRR patterns.

This template provides:
1. Silo definitions (identity, medical, auth) with HIPAA category mapping
2. Consent flow patterns (PIR, ePRR, treatment, research)
3. Role-portal mappings for healthcare
4. Example configuration and usage

SPDX-License-Identifier: BSL-1.1 — See LICENSE for details.
"""

from dataclasses import dataclass, field
from datetime import timedelta
from typing import Dict, List, Optional

from bedrock.config import (
    CoreConfig, EncryptionConfig, IdentityConfig,
    DataSeparationConfig, AuditConfig, AccessControlConfig,
    MeshConfig, LicensingConfig,
)
from bedrock.data_separation.silo import Silo, SiloManager
from bedrock.data_separation.consent import ConsentGate, ConsentEvent, ConsentStatus


# ---------------------------------------------------------------------------
# Healthcare Silo Definitions
# ---------------------------------------------------------------------------

HEALTHCARE_SILOS = {
    "identity": {
        "display_name": "Personal Information",
        "categories": ["demographics", "contact", "insurance", "ssn", "employment"],
        "description": "PII silo — demographics, contact info, insurance, SSN. "
                       "Breach reveals personal identity only, never medical data.",
        "hkdf_info": "bedrock:silo:healthcare:identity:v1",
    },
    "medical": {
        "display_name": "Medical Records",
        "categories": ["diagnosis", "medications", "vitals", "lab_results", "imaging", "procedures"],
        "description": "PHI silo — diagnoses, medications, vitals, lab results, imaging. "
                       "Breach reveals medical data but cannot link to identity without consent.",
        "hkdf_info": "bedrock:silo:healthcare:medical:v1",
    },
    "auth": {
        "display_name": "Authentication",
        "categories": ["credentials", "sessions", "mfa", "audit_tokens"],
        "description": "Auth silo — login credentials, session tokens, MFA secrets. "
                       "Isolated from both identity and medical data.",
        "hkdf_info": "bedrock:silo:healthcare:auth:v1",
    },
}

# HIPAA mapping: which regulation sections apply to which silos/categories
HIPAA_MAPPINGS = {
    "privacy_rule": {
        "164.502_uses_disclosures": {
            "description": "Uses and disclosures of PHI — requires minimum necessary standard",
            "silos": ["medical"],
            "categories": ["diagnosis", "medications", "vitals", "lab_results", "imaging", "procedures"],
            "enforcement": "consent_required",
        },
        "164.508_uses_disclosures_authorization": {
            "description": "Authorization for uses/disclosures — explicit written authorization",
            "silos": ["identity", "medical"],
            "categories": ["demographics", "diagnosis", "medications"],
            "enforcement": "consent_required_with_reason",
        },
        "164.510_notifications": {
            "description": "Notifications — can use identity silo for contact info",
            "silos": ["identity"],
            "categories": ["contact"],
            "enforcement": "consent_not_required",
        },
        "164.524_access": {
            "description": "Access of individuals to PHI — patient right to inspect/copy",
            "silos": ["medical"],
            "categories": ["diagnosis", "medications", "vitals", "lab_results", "imaging"],
            "enforcement": "patient_right",
        },
        "164.526_amendments": {
            "description": "Amendment of PHI — patient right to request corrections",
            "silos": ["medical"],
            "categories": ["diagnosis", "medications", "procedures"],
            "enforcement": "patient_right",
        },
    },
    "security_rule": {
        "164.312_access_control": {
            "description": "Access control — unique user ID, emergency access, automatic logoff",
            "silos": ["auth"],
            "categories": ["credentials", "sessions"],
            "enforcement": "rbac_enforced",
        },
        "164.312_encryption": {
            "description": "Encryption — protect ePHI at rest and in transit",
            "silos": ["identity", "medical", "auth"],
            "categories": ["*"],
            "enforcement": "encryption_at_rest",
        },
        "164.312_integrity": {
            "description": "Integrity — protect ePHI from improper alteration",
            "silos": ["medical"],
            "categories": ["diagnosis", "medications", "lab_results"],
            "enforcement": "audit_chain",
        },
        "164.312_audit": {
            "description": "Audit controls — record and examine information system activity",
            "silos": ["identity", "medical", "auth"],
            "categories": ["*"],
            "enforcement": "audit_logging",
        },
    },
    "breach_notification": {
        "164.408_notification": {
            "description": "Breach notification — notify individuals within 60 days",
            "silos": ["identity"],
            "categories": ["contact"],
            "enforcement": "breach_protocol",
        },
    },
}


# ---------------------------------------------------------------------------
# Healthcare Consent Flows
# ---------------------------------------------------------------------------

class ConsentFlowType:
    """Standard healthcare consent flow types."""
    PIR = "pir"           # Personal Information Request (InFill pattern)
    EPRR = "eprr"         # Electronic Patient Record Request (InFill pattern)
    TREATMENT = "treatment"  # Treatment consent
    RESEARCH = "research"    # Research authorization
    INSURANCE = "insurance"  # Insurance/claims authorization


@dataclass
class ConsentFlowConfig:
    """Configuration for a consent flow pattern."""
    flow_type: str
    source_silo: str
    target_silo: str
    categories: List[str]
    scope: str
    default_ttl_seconds: int
    require_reason: bool
    hipaa_sections: List[str] = field(default_factory=list)
    description: str = ""


HEALTHCARE_CONSENT_FLOWS = {
    # PIR: Provider requests patient demographics from identity silo
    # InFill pattern: separate consent for personal info vs medical records
    "pir": ConsentFlowConfig(
        flow_type=ConsentFlowType.PIR,
        source_silo="identity",
        target_silo="medical",
        categories=["demographics", "contact", "insurance"],
        scope="read",
        default_ttl_seconds=3600,  # 1 hour
        require_reason=True,
        hipaa_sections=["164.508_uses_disclosures_authorization"],
        description="Personal Information Request — provider requests patient demographics "
                    "for treatment coordination. Patient must approve separately from medical records.",
    ),
    # ePRR: Provider requests medical records from medical silo
    # InFill pattern: the medical consent is separate from personal info consent
    "eprr": ConsentFlowConfig(
        flow_type=ConsentFlowType.EPRR,
        source_silo="medical",
        target_silo="medical",
        categories=["diagnosis", "medications", "vitals", "lab_results", "imaging"],
        scope="read",
        default_ttl_seconds=3600,  # 1 hour
        require_reason=True,
        hipaa_sections=["164.502_uses_disclosures", "164.524_access"],
        description="Electronic Patient Record Request — provider requests medical records. "
                    "This consent is separate from PIR. Patient can approve medical without "
                    "approving personal information.",
    ),
    # Treatment: Patient consents to treatment plan (write scope)
    "treatment": ConsentFlowConfig(
        flow_type=ConsentFlowType.TREATMENT,
        source_silo="medical",
        target_silo="medical",
        categories=["diagnosis", "medications", "procedures"],
        scope="write",
        default_ttl_seconds=86400,  # 24 hours (treatment plans last longer)
        require_reason=False,
        hipaa_sections=["164.502_uses_disclosures", "164.526_amendments"],
        description="Treatment consent — patient authorizes treatment plan modifications. "
                    "Write scope allows adding diagnoses, prescribing medications, "
                    "and scheduling procedures.",
    ),
    # Research: De-identified data access for clinical studies
    "research": ConsentFlowConfig(
        flow_type=ConsentFlowType.RESEARCH,
        source_silo="medical",
        target_silo="identity",
        categories=["diagnosis", "medications", "vitals", "lab_results"],
        scope="read",
        default_ttl_seconds=604800,  # 7 days (research studies run longer)
        require_reason=True,
        hipaa_sections=["164.508_uses_disclosures_authorization"],
        description="Research authorization — patient consents to de-identified data access "
                    "for clinical research. Only anonymous IDs flow to researchers; "
                    "identity resolution requires separate consent.",
    ),
    # Insurance: Claims authorization
    "insurance": ConsentFlowConfig(
        flow_type=ConsentFlowType.INSURANCE,
        source_silo="identity",
        target_silo="medical",
        categories=["demographics", "insurance", "diagnosis", "procedures"],
        scope="read",
        default_ttl_seconds=86400,  # 24 hours
        require_reason=True,
        hipaa_sections=["164.508_uses_disclosures_authorization"],
        description="Insurance claims authorization — patient consents to sharing "
                    "diagnosis and procedure codes with their insurer. Minimum necessary "
                    "standard applied: only billing-relevant categories flow.",
    ),
}


# ---------------------------------------------------------------------------
# Healthcare Role-Portal Mapping
# ---------------------------------------------------------------------------

HEALTHCARE_ROLES = {
    "provider": {
        "portals": ["provider"],
        "permissions": [
            "data.read", "data.write", "consent.request", "consent.approve",
            "cert.issue", "node.register", "audit.read",
        ],
        "description": "Licensed healthcare provider (physician, nurse, therapist).",
        "hipaa_minimum_necessary": True,
    },
    "patient": {
        "portals": ["patient"],
        "permissions": [
            "data.read", "consent.request", "consent.approve", "audit.read",
        ],
        "description": "Patient accessing their own records.",
        "hipaa_minimum_necessary": False,  # Patients have right to all their own data
    },
    "admin": {
        "portals": ["admin"],
        "permissions": [
            "data.read", "data.write", "consent.request", "consent.approve",
            "cert.issue", "cert.revoke", "node.register", "node.quarantine",
            "audit.read",
        ],
        "description": "System administrator with full access.",
        "hipaa_minimum_necessary": True,
    },
    "researcher": {
        "portals": ["partner"],
        "permissions": [
            "data.read", "consent.request", "audit.read",
        ],
        "description": "Clinical researcher with de-identified data access only.",
        "hipaa_minimum_necessary": True,
    },
    "insurer": {
        "portals": ["partner"],
        "permissions": [
            "data.read", "consent.request", "audit.read",
        ],
        "description": "Insurance claims processor. Minimum necessary only.",
        "hipaa_minimum_necessary": True,
    },
}


# ---------------------------------------------------------------------------
# Healthcare Template Class
# ---------------------------------------------------------------------------

class HealthcareTemplate:
    """Pre-configured Bedrock instance for healthcare applications.

    Sets up silos, consent flows, roles, and configuration tuned for HIPAA compliance.
    Extracted from InFill's proven PIR/ePRR architecture.

    Usage:
        template = HealthcareTemplate()
        client = template.create_client()

        # Register a provider
        provider = client.identity.register("provider-alice")

        # Create the healthcare silos
        silos = template.create_silos(client)

        # Start a PIR consent flow
        consent = template.request_pir(provider.node_id.uuid, "patient-42")
    """

    def __init__(self, mode: str = "developer"):
        self.mode = mode
        self._silo_manager: Optional[SiloManager] = None
        self._consent_gate: Optional[ConsentGate] = None

    def create_silos(self, silo_manager: SiloManager) -> Dict[str, Silo]:
        """Create the standard healthcare silo configuration.

        Returns a dict mapping silo name to Silo object.
        """
        silos = {}
        for name, config in HEALTHCARE_SILOS.items():
            silo = silo_manager.create_silo(
                name=name,
                display_name=config["display_name"],
                categories=config["categories"],
                description=config["description"],
                hkdf_info=config["hkdf_info"],
            )
            silos[name] = silo
        return silos

    def request_pir(self, requesting_node_id: str, patient_id: str,
                    reason: str = "") -> ConsentEvent:
        """Start a Personal Information Request (PIR) flow.

        PIR is the InFill pattern where a provider requests patient demographics
        separately from medical records. The patient must approve this consent
        before any identity data flows to the medical silo.

        Args:
            requesting_node_id: The provider requesting access
            patient_id: Anonymous ID of the patient
            reason: Human-readable reason for the request

        Returns:
            A PENDING ConsentEvent awaiting patient approval
        """
        if not self._consent_gate:
            self._consent_gate = ConsentGate()

        flow = HEALTHCARE_CONSENT_FLOWS["pir"]
        return self._consent_gate.request_consent(
            requesting_node_id=requesting_node_id,
            source_silo=flow.source_silo,
            target_silo=flow.target_silo,
            categories=flow.categories,
            scope=flow.scope,
            reason=reason or flow.description,
        )

    def request_eprr(self, requesting_node_id: str, patient_id: str,
                     reason: str = "") -> ConsentEvent:
        """Start an Electronic Patient Record Request (ePRR) flow.

        ePRR is the InFill pattern for requesting medical records. This is
        separate from PIR — the patient can approve medical record access
        without approving personal information access.

        Args:
            requesting_node_id: The provider requesting access
            patient_id: Anonymous ID of the patient
            reason: Human-readable reason for the request

        Returns:
            A PENDING ConsentEvent awaiting patient approval
        """
        if not self._consent_gate:
            self._consent_gate = ConsentGate()

        flow = HEALTHCARE_CONSENT_FLOWS["eprr"]
        return self._consent_gate.request_consent(
            requesting_node_id=requesting_node_id,
            source_silo=flow.source_silo,
            target_silo=flow.target_silo,
            categories=flow.categories,
            scope=flow.scope,
            reason=reason or flow.description,
        )

    def get_config(self) -> CoreConfig:
        """Get a CoreConfig pre-configured for healthcare HIPAA compliance.

        Applies healthcare-specific settings:
        - 6-year audit retention (HIPAA)
        - Strict consent mode (minimum necessary standard)
        - MFA required for all provider access
        - Session timeouts aligned with HIPAA access control
        """
        return CoreConfig(
            environment="production" if self.mode != "developer" else "development",
            data_separation=DataSeparationConfig(
                silo_strict_mode=True,  # Enforce minimum necessary
                consent_default_ttl_seconds=3600,
                consent_max_ttl_seconds=86400,
                consent_require_reason=True,  # HIPAA requires reason for disclosure
            ),
            audit=AuditConfig(
                retention_years=6,  # HIPAA minimum
                chain_export_format="jsonl",
            ),
            access_control=AccessControlConfig(
                mfa_required=True,  # HIPAA access control
                session_ttl_seconds=3600,
                session_max_ttl_seconds=28800,
                lockout_max_attempts=5,
                lockout_duration_seconds=1800,
                rate_limit_enabled=True,
                rate_limit_requests_per_minute=60,
            ),
            licensing=LicensingConfig(
                tier=self.mode,
                dev_mode=(self.mode == "developer"),
            ),
        )

    @staticmethod
    def hipaa_compliance_report() -> Dict:
        """Generate a HIPAA compliance mapping report.

        Maps each HIPAA Security Rule and Privacy Rule section to the
        Bedrock features that enforce it.
        """
        return {
            "template": "healthcare",
            "version": "1.0.0",
            "regulation": "HIPAA (45 CFR Parts 160, 164)",
            "silos": list(HEALTHCARE_SILOS.keys()),
            "consent_flows": list(HEALTHCARE_CONSENT_FLOWS.keys()),
            "mappings": HIPAA_MAPPINGS,
            "enforcement_summary": {
                "encryption_at_rest": "All silos encrypted with AES-256-GCM, "
                                      "per-silo HKDF-derived keys",
                "consent_required": "Cross-silo data access gated by explicit consent",
                "minimum_necessary": "Silo categories limit disclosure scope",
                "audit_trail": "SHA-256 hash chain, 6-year retention, tamper-evident",
                "access_control": "RBAC with MFA, session scoping, account lockout",
                "breach_isolation": "Self-healing mesh isolates compromised nodes",
            },
        }