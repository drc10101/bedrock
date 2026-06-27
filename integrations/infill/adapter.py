"""
InFill Adapter — Bridge between InFill domain and Bedrock Core.

Maps InFill concepts to Bedrock modules:
- Patient → NodeRegistry node with CertificateManager certificate
- Intake Questionnaire → SiloManager medical silo (encrypted via FieldEncryptor)
- PIR (Patient Information Request) → ConsentGate consent flow
- ePRR (Electronic Patient Records Release) → ConsentGate consent flow
- E2EE Message → E2EEDeliverer encrypted channel
- Audit Chain → AuditChain SHA-256 hash chain
- Data storage → FieldEncryptor per-field encryption + in-memory stores

This adapter layer preserves InFill's domain language while
leveraging Bedrock's security architecture underneath.

Trade Secret — InFill Systems, LLC. All rights reserved.
"""

import hashlib
import os
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional
import uuid as uuid_mod

from bedrock.config import CoreConfig
from bedrock.identity.registration import NodeRegistry
from bedrock.identity.certificates import CertificateManager, LicenseTier
from bedrock.key_management.keys import KeyManager
from bedrock.encryption.engine import FieldEncryptor
from bedrock.data_separation.silo import SiloManager
from bedrock.data_separation.consent import ConsentGate
from bedrock.audit.chain import AuditChain, AuditAction


# ── InFill Domain Enums ──

class PatientRole(Enum):
    """InFill participant roles."""
    PATIENT = "patient"
    PROVIDER = "provider"
    ADMIN = "admin"
    SUPER_ADMIN = "super_admin"


class IntakeStatus(Enum):
    """InFill intake questionnaire status."""
    DRAFT = "draft"
    IN_PROGRESS = "in_progress"
    SUBMITTED = "submitted"
    UNDER_REVIEW = "under_review"
    APPROVED = "approved"
    REJECTED = "rejected"


class PIRStatus(Enum):
    """Patient Information Request status."""
    PENDING = "pending"
    APPROVED = "approved"
    DENIED = "denied"
    EXPIRED = "expired"


class EPRRStatus(Enum):
    """Electronic Patient Records Release status."""
    PENDING = "pending"
    APPROVED = "approved"
    DENIED = "denied"
    RELEASED = "released"
    EXPIRED = "expired"


class E2EEStatus(Enum):
    """E2EE message delivery status."""
    PENDING = "pending"
    DELIVERED = "delivered"
    READ = "read"
    EXPIRED = "expired"


# ── InFill Domain Models ──

@dataclass
class Patient:
    """InFill Patient — mapped to Bedrock NodeRegistry node."""
    uuid: str
    name: str
    email: str
    phone: str
    role: PatientRole = PatientRole.PATIENT
    date_of_birth: Optional[str] = None
    ssn_last4: Optional[str] = None
    created_at: Optional[str] = None
    node_id: Optional[str] = None
    certificate_serial: Optional[str] = None


@dataclass
class IntakeQuestionnaire:
    """InFill Intake Questionnaire — stored in medical silo."""
    uuid: str
    patient_uuid: str
    status: IntakeStatus = IntakeStatus.DRAFT
    responses: Dict = field(default_factory=dict)
    submitted_at: Optional[str] = None
    reviewed_by: Optional[str] = None
    reviewed_at: Optional[str] = None


@dataclass
class PIR:
    """Patient Information Request — mapped to ConsentGate."""
    uuid: str
    patient_uuid: str
    requester_uuid: str
    purpose: str = "patient_portal"
    categories: List[str] = field(default_factory=list)
    status: PIRStatus = PIRStatus.PENDING
    consent_id: Optional[str] = None
    created_at: Optional[str] = None
    expires_at: Optional[str] = None


@dataclass
class EPRR:
    """Electronic Patient Records Release — mapped to ConsentGate."""
    uuid: str
    patient_uuid: str
    recipient_uuid: str
    record_categories: List[str] = field(default_factory=list)
    status: EPRRStatus = EPRRStatus.PENDING
    consent_id: Optional[str] = None
    release_token: Optional[str] = None
    created_at: Optional[str] = None
    expires_at: Optional[str] = None


@dataclass
class E2EEMessage:
    """E2EE Message — mapped to Bedrock Transport."""
    uuid: str
    sender_uuid: str
    recipient_uuid: str
    subject: str = ""
    body: str = ""
    status: E2EEStatus = E2EEStatus.PENDING
    sent_at: Optional[str] = None
    read_at: Optional[str] = None
    expires_at: Optional[str] = None


# ── InFill Adapter ──

class InFillAdapter:
    """Bridge between InFill domain and Bedrock Core.

    Maps InFill concepts to Bedrock modules:
    - Patient registration → NodeRegistry node + CertificateManager certificate
    - Intake data → FieldEncryptor + in-memory medical store
    - PIR → ConsentGate consent request
    - ePRR → ConsentGate consent request
    - E2EE messages → FieldEncryptor encrypted delivery
    - Audit events → AuditChain SHA-256 hash chain

    Uses the Healthcare Template's 3-silo architecture:
    - identity: identity, demographics, ssn
    - medical: medical, diagnosis, prescription, lab
    - auth: auth, mfa, session
    """

    def __init__(self, config: Optional[CoreConfig] = None):
        """Initialize the InFill adapter with Bedrock Core modules.

        Args:
            config: Bedrock CoreConfig. Defaults to development config.
        """
        self.config = config or CoreConfig(environment="development", debug=True)
        self._registry = NodeRegistry()
        self._certificates = CertificateManager(
            license_tier=LicenseTier.BUSINESS,
            default_ttl_hours=24,
        )
        self._key_manager = KeyManager()
        self._master_key = os.urandom(32)  # In production, loaded from env/HSM
        self._encryptor = FieldEncryptor(
            key_manager=self._key_manager,
            master_key=self._master_key,
        )
        self._silos = SiloManager()
        self._consent = ConsentGate()
        self._audit = AuditChain()

        # In-memory stores (in production, backed by SQLCipher)
        self._patients: Dict[str, Patient] = {}
        self._patient_data: Dict[str, Dict] = {}  # encrypted data store
        self._intakes: Dict[str, IntakeQuestionnaire] = {}
        self._pirs: Dict[str, PIR] = {}
        self._eprs: Dict[str, EPRR] = {}
        self._messages: Dict[str, E2EEMessage] = {}

        # Initialize healthcare silos
        self._init_healthcare_silos()

    def _init_healthcare_silos(self):
        """Initialize the 3 healthcare silos: identity, medical, auth."""
        self._silos.create_silo(
            name="identity",
            display_name="Identity Data",
            categories=["identity", "demographics", "ssn"],
            hkdf_info="bedrock:healthcare:identity:v1",
        )
        self._silos.create_silo(
            name="medical",
            display_name="Medical Records",
            categories=["medical", "diagnosis", "prescription", "lab"],
            hkdf_info="bedrock:healthcare:medical:v1",
        )
        self._silos.create_silo(
            name="auth",
            display_name="Authentication",
            categories=["auth", "mfa", "session"],
            hkdf_info="bedrock:healthcare:auth:v1",
        )

    # ── Helper: encrypt/decrypt data for a silo ──

    def _encrypt_data(self, data: Dict, silo: str, record_id: str) -> Dict[str, str]:
        """Encrypt a dict of data fields using Bedrock FieldEncryptor.

        Each field is individually encrypted with the silo's key,
        providing field-level granularity for consent-gated access.
        """
        encrypted = {}
        for key, value in data.items():
            if value is not None:
                encrypted[key] = self._encryptor.encrypt(
                    plaintext=str(value),
                    silo=silo,
                    record_id=record_id,
                    scope=key,
                )
            else:
                encrypted[key] = None
        return encrypted

    def _decrypt_data(self, encrypted: Dict[str, str], silo: str,
                      record_id: str) -> Dict[str, str]:
        """Decrypt a dict of encrypted data fields."""
        decrypted = {}
        for key, value in encrypted.items():
            if value is not None:
                decrypted[key] = self._encryptor.decrypt(
                    ciphertext=value,
                    silo=silo,
                    record_id=record_id,
                    scope=key,
                )
            else:
                decrypted[key] = None
        return decrypted

    # ── Patient Management ──

    def register_patient(self, name: str, email: str, phone: str,
                          role: PatientRole = PatientRole.PATIENT,
                          date_of_birth: Optional[str] = None,
                          ssn_last4: Optional[str] = None) -> Patient:
        """Register a patient in InFill via Bedrock Identity Fabric.

        Creates a Bedrock node, issues a certificate, encrypts PII
        with FieldEncryptor, and stores data per-silo.
        """
        # Register node in NodeRegistry
        node = self._registry.register(name=name, node_type=role.value)

        # Issue certificate
        pk_hash = hashlib.sha256(node.node_id.public_key).hexdigest()
        cert = self._certificates.issue_certificate(
            node_uuid=node.node_id.uuid,
            node_name=name,
            public_key_hash=pk_hash,
            capabilities=["read"],
        )

        # Create Patient domain object
        patient = Patient(
            uuid=node.node_id.uuid,
            name=name,
            email=email,
            phone=phone,
            role=role,
            date_of_birth=date_of_birth,
            ssn_last4=ssn_last4,
            node_id=node.node_id.uuid,
            certificate_serial=cert.serial,
        )

        # Encrypt and store identity data in identity silo
        identity_data = {
            "uuid": node.node_id.uuid,
            "name": name,
            "email": email,
            "phone": phone,
            "role": role.value,
            "certificate_serial": cert.serial,
        }
        encrypted_identity = self._encrypt_data(
            identity_data, silo="identity", record_id=f"patient:{node.node_id.uuid}"
        )
        self._patient_data[f"patient:{node.node_id.uuid}"] = encrypted_identity

        # Encrypt and store PII separately in identity silo
        if date_of_birth or ssn_last4:
            pii_data = {
                "date_of_birth": date_of_birth,
                "ssn_last4": ssn_last4,
            }
            encrypted_pii = self._encrypt_data(
                pii_data, silo="identity", record_id=f"patient:{node.node_id.uuid}:pii"
            )
            self._patient_data[f"patient:{node.node_id.uuid}:pii"] = encrypted_pii

        # Audit event
        self._audit.append(
            action="patient_registered",
            actor_id="system",
            target_id=node.node_id.uuid,
            silo="identity",
            details={"name": name, "role": role.value},
        )

        self._patients[node.node_id.uuid] = patient
        return patient

    def get_patient(self, patient_uuid: str) -> Optional[Patient]:
        """Retrieve a patient by UUID."""
        return self._patients.get(patient_uuid)

    def lookup_patient(self, name: str = None, email: str = None) -> Optional[Patient]:
        """Look up a patient by name or email."""
        for patient in self._patients.values():
            if name and patient.name == name:
                return patient
            if email and patient.email == email:
                return patient
        return None

    def decrypt_patient_data(self, patient_uuid: str) -> Optional[Dict]:
        """Decrypt a patient's stored identity data."""
        encrypted = self._patient_data.get(f"patient:{patient_uuid}")
        if encrypted is None:
            return None
        return self._decrypt_data(encrypted, silo="identity", record_id=f"patient:{patient_uuid}")

    def decrypt_patient_pii(self, patient_uuid: str) -> Optional[Dict]:
        """Decrypt a patient's stored PII (DOB, SSN)."""
        encrypted = self._patient_data.get(f"patient:{patient_uuid}:pii")
        if encrypted is None:
            return None
        return self._decrypt_data(encrypted, silo="identity", record_id=f"patient:{patient_uuid}:pii")

    # ── Intake Management ──

    def create_intake(self, patient_uuid: str) -> IntakeQuestionnaire:
        """Create a new intake questionnaire for a patient.

        Metadata stored encrypted in the medical silo.
        """
        intake_uuid = str(uuid_mod.uuid4())

        intake = IntakeQuestionnaire(
            uuid=intake_uuid,
            patient_uuid=patient_uuid,
        )

        # Encrypt and store intake metadata in medical silo
        intake_data = {
            "uuid": intake_uuid,
            "patient_uuid": patient_uuid,
            "status": IntakeStatus.DRAFT.value,
        }
        encrypted_intake = self._encrypt_data(
            intake_data, silo="medical", record_id=f"intake:{intake_uuid}"
        )
        self._patient_data[f"intake:{intake_uuid}"] = encrypted_intake

        # Audit event
        self._audit.append(
            action="intake_created",
            actor_id=patient_uuid,
            target_id=intake_uuid,
            silo="medical",
            details={"patient_uuid": patient_uuid},
        )

        self._intakes[intake_uuid] = intake
        return intake

    def submit_intake(self, intake_uuid: str, responses: Dict) -> IntakeQuestionnaire:
        """Submit an intake questionnaire with responses.

        Responses are encrypted field-by-field in the medical silo.
        """
        intake = self._intakes.get(intake_uuid)
        if intake is None:
            raise KeyError(f"Intake '{intake_uuid}' not found")

        intake.responses = responses
        intake.status = IntakeStatus.SUBMITTED

        # Encrypt and store responses in medical silo
        encrypted_responses = self._encrypt_data(
            responses, silo="medical", record_id=f"intake:{intake_uuid}:responses"
        )
        self._patient_data[f"intake:{intake_uuid}:responses"] = encrypted_responses

        # Update intake status
        intake_data = {
            "uuid": intake_uuid,
            "patient_uuid": intake.patient_uuid,
            "status": IntakeStatus.SUBMITTED.value,
        }
        self._patient_data[f"intake:{intake_uuid}"] = self._encrypt_data(
            intake_data, silo="medical", record_id=f"intake:{intake_uuid}"
        )

        # Audit event
        self._audit.append(
            action="intake_submitted",
            actor_id=intake.patient_uuid,
            target_id=intake_uuid,
            silo="medical",
            details={"patient_uuid": intake.patient_uuid},
        )

        return intake

    def get_intake(self, intake_uuid: str) -> Optional[IntakeQuestionnaire]:
        """Retrieve an intake questionnaire by UUID."""
        return self._intakes.get(intake_uuid)

    # ── PIR (Patient Information Request) ──

    def create_pir(self, patient_uuid: str, requester_uuid: str,
                   categories: List[str],
                   purpose: str = "patient_portal") -> PIR:
        """Create a Patient Information Request via Bedrock ConsentGate.

        Maps to a consent request between identity and medical silos.
        The patient must approve before the requester can access the data.
        """
        pir_uuid = str(uuid_mod.uuid4())

        # Create Bedrock consent request
        consent = self._consent.request_consent(
            requesting_node_id=requester_uuid,
            source_silo="identity",
            target_silo="medical",
            categories=categories,
            scope=purpose,
            reason=f"PIR: {purpose}",
        )

        pir = PIR(
            uuid=pir_uuid,
            patient_uuid=patient_uuid,
            requester_uuid=requester_uuid,
            purpose=purpose,
            categories=categories,
            consent_id=consent.consent_id,
        )

        # Audit event
        self._audit.append(
            action="pir_created",
            actor_id=requester_uuid,
            target_id=patient_uuid,
            silo="identity",
            details={"pir_uuid": pir_uuid, "purpose": purpose, "categories": categories},
        )

        self._pirs[pir_uuid] = pir
        return pir

    def approve_pir(self, pir_uuid: str) -> PIR:
        """Approve a PIR — patient consents to data access."""
        pir = self._pirs.get(pir_uuid)
        if pir is None:
            raise KeyError(f"PIR '{pir_uuid}' not found")

        pir.status = PIRStatus.APPROVED

        # Approve consent in Bedrock
        if pir.consent_id:
            self._consent.approve_consent(
                consent_id=pir.consent_id,
                data_owner_id=pir.patient_uuid,
            )

        # Audit event
        self._audit.append(
            action="pir_approved",
            actor_id=pir.patient_uuid,
            target_id=pir_uuid,
            silo="identity",
            details={"requester": pir.requester_uuid},
        )

        return pir

    def deny_pir(self, pir_uuid: str) -> PIR:
        """Deny a PIR — patient refuses data access."""
        pir = self._pirs.get(pir_uuid)
        if pir is None:
            raise KeyError(f"PIR '{pir_uuid}' not found")

        pir.status = PIRStatus.DENIED

        # Deny consent in Bedrock
        if pir.consent_id:
            self._consent.deny_consent(
                consent_id=pir.consent_id,
                data_owner_id=pir.patient_uuid,
                reason="PIR denied by patient",
            )

        # Audit event
        self._audit.append(
            action="pir_denied",
            actor_id=pir.patient_uuid,
            target_id=pir_uuid,
            silo="identity",
            details={"requester": pir.requester_uuid},
        )

        return pir

    # ── ePRR (Electronic Patient Records Release) ──

    def create_eprr(self, patient_uuid: str, recipient_uuid: str,
                    record_categories: List[str]) -> EPRR:
        """Create an Electronic Patient Records Release via Bedrock ConsentGate.

        Maps to a consent request for medical data release.
        """
        eprr_uuid = str(uuid_mod.uuid4())

        # Create Bedrock consent request
        consent = self._consent.request_consent(
            requesting_node_id=recipient_uuid,
            source_silo="medical",
            target_silo="identity",
            categories=record_categories,
            scope="ePRR",
            reason="Electronic Patient Records Release",
        )

        eprr = EPRR(
            uuid=eprr_uuid,
            patient_uuid=patient_uuid,
            recipient_uuid=recipient_uuid,
            record_categories=record_categories,
            consent_id=consent.consent_id,
        )

        # Audit event
        self._audit.append(
            action="eprr_created",
            actor_id=patient_uuid,
            target_id=recipient_uuid,
            silo="medical",
            details={"eprr_uuid": eprr_uuid, "categories": record_categories},
        )

        self._eprs[eprr_uuid] = eprr
        return eprr

    def release_eprr(self, eprr_uuid: str) -> EPRR:
        """Release records after ePRR approval."""
        eprr = self._eprs.get(eprr_uuid)
        if eprr is None:
            raise KeyError(f"EPRR '{eprr_uuid}' not found")

        eprr.status = EPRRStatus.RELEASED
        eprr.release_token = str(uuid_mod.uuid4())

        # Approve consent in Bedrock
        if eprr.consent_id:
            self._consent.approve_consent(
                consent_id=eprr.consent_id,
                data_owner_id=eprr.patient_uuid,
            )

        # Audit event
        self._audit.append(
            action="eprr_released",
            actor_id=eprr.patient_uuid,
            target_id=eprr_uuid,
            silo="medical",
            details={"recipient": eprr.recipient_uuid},
        )

        return eprr

    # ── E2EE Messaging ──

    def send_message(self, sender_uuid: str, recipient_uuid: str,
                     subject: str, body: str,
                     ttl_seconds: int = 86400) -> E2EEMessage:
        """Send an E2EE message using Bedrock FieldEncryptor.

        Both subject and body are encrypted with the recipient's silo key.
        """
        msg_uuid = str(uuid_mod.uuid4())

        # Encrypt message content
        encrypted_subject = self._encryptor.encrypt(
            plaintext=subject,
            silo="auth",
            record_id=f"msg:{msg_uuid}",
            scope="subject",
        )
        encrypted_body = self._encryptor.encrypt(
            plaintext=body,
            silo="auth",
            record_id=f"msg:{msg_uuid}",
            scope="body",
        )

        message = E2EEMessage(
            uuid=msg_uuid,
            sender_uuid=sender_uuid,
            recipient_uuid=recipient_uuid,
            subject=encrypted_subject,  # Stored encrypted
            body=encrypted_body,          # Stored encrypted
            status=E2EEStatus.DELIVERED,
        )

        # Audit event
        self._audit.append(
            action="message_sent",
            actor_id=sender_uuid,
            target_id=recipient_uuid,
            silo="auth",
            details={"message_uuid": msg_uuid},
        )

        self._messages[msg_uuid] = message
        return message

    def decrypt_message(self, message: E2EEMessage) -> E2EEMessage:
        """Decrypt a message's subject and body."""
        decrypted_subject = self._encryptor.decrypt(
            ciphertext=message.subject,
            silo="auth",
            record_id=f"msg:{message.uuid}",
            scope="subject",
        )
        decrypted_body = self._encryptor.decrypt(
            ciphertext=message.body,
            silo="auth",
            record_id=f"msg:{message.uuid}",
            scope="body",
        )
        return E2EEMessage(
            uuid=message.uuid,
            sender_uuid=message.sender_uuid,
            recipient_uuid=message.recipient_uuid,
            subject=decrypted_subject,
            body=decrypted_body,
            status=message.status,
        )

    # ── Audit ──

    def get_audit_trail(self, limit: int = 100) -> List[Dict]:
        """Get the audit trail from Bedrock AuditChain."""
        entries = self._audit.query(limit=limit)
        return [
            {
                "action": entry.action,
                "actor_id": entry.actor_id,
                "target_id": entry.target_id,
                "silo": entry.silo,
                "timestamp": entry.timestamp.isoformat() if hasattr(entry.timestamp, 'isoformat') else str(entry.timestamp),
                "details": entry.details,
            }
            for entry in entries
        ]

    def verify_integrity(self) -> bool:
        """Verify the integrity of the audit chain."""
        return self._audit.verify()