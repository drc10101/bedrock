"""
Tests for the InFill Adapter — Bridge between InFill domain and Bedrock Core.

Verifies that InFill domain operations correctly use Bedrock modules
underneath: Identity Fabric, Silos, Consent, Audit, Transport.
"""

import hashlib
import pytest

from bedrock.config import CoreConfig
from infill.adapter import (
    InFillAdapter,
    Patient,
    PatientRole,
    IntakeQuestionnaire,
    IntakeStatus,
    PIR,
    PIRStatus,
    EPRR,
    EPRRStatus,
    E2EEMessage,
    E2EEStatus,
)


# ── Fixtures ──

@pytest.fixture
def config():
    """Create a test CoreConfig."""
    return CoreConfig(environment="development", debug=True)


@pytest.fixture
def adapter(config):
    """Create an InFillAdapter with test config."""
    return InFillAdapter(config=config)


@pytest.fixture
def patient(adapter):
    """Register a test patient."""
    return adapter.register_patient(
        name="Jane Doe",
        email="jane@example.com",
        phone="555-0101",
        date_of_birth="1985-03-15",
        ssn_last4="6789",
    )


@pytest.fixture
def provider(adapter):
    """Register a test provider."""
    return adapter.register_patient(
        name="Dr. Smith",
        email="smith@example.com",
        phone="555-0202",
        role=PatientRole.PROVIDER,
    )


# ── Patient Registration ──

class TestPatientRegistration:
    """Test patient registration via Bedrock Identity Fabric."""

    def test_register_patient_basic(self, adapter):
        patient = adapter.register_patient(
            name="Jane Doe",
            email="jane@example.com",
            phone="555-0101",
        )
        assert patient.uuid is not None
        assert patient.name == "Jane Doe"
        assert patient.email == "jane@example.com"
        assert patient.phone == "555-0101"
        assert patient.role == PatientRole.PATIENT

    def test_register_patient_with_pii(self, adapter):
        patient = adapter.register_patient(
            name="John Smith",
            email="john@example.com",
            phone="555-0303",
            date_of_birth="1990-07-22",
            ssn_last4="1234",
        )
        assert patient.date_of_birth == "1990-07-22"
        assert patient.ssn_last4 == "1234"

    def test_register_provider(self, adapter):
        provider = adapter.register_patient(
            name="Dr. Johnson",
            email="johnson@example.com",
            phone="555-0404",
            role=PatientRole.PROVIDER,
        )
        assert provider.role == PatientRole.PROVIDER

    def test_register_patient_gets_node_id(self, adapter):
        patient = adapter.register_patient(
            name="Test Node",
            email="node@example.com",
            phone="555-0505",
        )
        assert patient.node_id is not None
        assert patient.node_id == patient.uuid  # node_id = uuid from NodeRegistry

    def test_register_patient_gets_certificate(self, adapter):
        patient = adapter.register_patient(
            name="Test Cert",
            email="cert@example.com",
            phone="555-0606",
        )
        assert patient.certificate_serial is not None
        assert patient.certificate_serial.startswith("bedrock-")

    def test_register_multiple_patients(self, adapter):
        patients = []
        for i in range(5):
            p = adapter.register_patient(
                name=f"Patient {i}",
                email=f"patient{i}@example.com",
                phone=f"555-{i:04d}",
            )
            patients.append(p)
        # All should have unique UUIDs
        uuids = [p.uuid for p in patients]
        assert len(set(uuids)) == 5


# ── Patient Lookup ──

class TestPatientLookup:
    """Test patient retrieval and lookup."""

    def test_get_patient_by_uuid(self, adapter, patient):
        found = adapter.get_patient(patient.uuid)
        assert found is not None
        assert found.uuid == patient.uuid

    def test_get_patient_not_found(self, adapter):
        found = adapter.get_patient("nonexistent-uuid")
        assert found is None

    def test_lookup_patient_by_name(self, adapter, patient):
        found = adapter.lookup_patient(name="Jane Doe")
        assert found is not None
        assert found.uuid == patient.uuid

    def test_lookup_patient_by_email(self, adapter, patient):
        found = adapter.lookup_patient(email="jane@example.com")
        assert found is not None
        assert found.uuid == patient.uuid

    def test_lookup_patient_not_found(self, adapter):
        found = adapter.lookup_patient(name="Nonexistent")
        assert found is None


# ── Data Encryption ──

class TestDataEncryption:
    """Test that patient data is encrypted and decryptable."""

    def test_decrypt_patient_identity(self, adapter, patient):
        decrypted = adapter.decrypt_patient_data(patient.uuid)
        assert decrypted is not None
        assert decrypted["name"] == "Jane Doe"
        assert decrypted["email"] == "jane@example.com"
        assert decrypted["phone"] == "555-0101"

    def test_decrypt_patient_pii(self, adapter, patient):
        pii = adapter.decrypt_patient_pii(patient.uuid)
        assert pii is not None
        assert pii["date_of_birth"] == "1985-03-15"
        assert pii["ssn_last4"] == "6789"

    def test_decrypt_nonexistent_patient(self, adapter):
        result = adapter.decrypt_patient_data("nonexistent-uuid")
        assert result is None

    def test_decrypt_nonexistent_pii(self, adapter):
        # Patient without PII
        patient = adapter.register_patient(
            name="No PII",
            email="nopii@example.com",
            phone="555-9999",
        )
        pii = adapter.decrypt_patient_pii(patient.uuid)
        assert pii is None  # No PII was stored for this patient


# ── Intake Management ──

class TestIntakeManagement:
    """Test intake questionnaire management via Bedrock medical silo."""

    def test_create_intake(self, adapter, patient):
        intake = adapter.create_intake(patient.uuid)
        assert intake is not None
        assert intake.patient_uuid == patient.uuid
        assert intake.status == IntakeStatus.DRAFT

    def test_submit_intake(self, adapter, patient):
        intake = adapter.create_intake(patient.uuid)
        responses = {
            "chief_complaint": "Headache",
            "history_of_present_illness": "Recurring for 2 weeks",
            "medications": "ibuprofen",
        }
        submitted = adapter.submit_intake(intake.uuid, responses)
        assert submitted.status == IntakeStatus.SUBMITTED
        assert submitted.responses == responses

    def test_submit_intake_not_found(self, adapter):
        with pytest.raises(KeyError, match="not found"):
            adapter.submit_intake("nonexistent-uuid", {})

    def test_get_intake(self, adapter, patient):
        intake = adapter.create_intake(patient.uuid)
        found = adapter.get_intake(intake.uuid)
        assert found is not None
        assert found.uuid == intake.uuid

    def test_get_intake_not_found(self, adapter):
        found = adapter.get_intake("nonexistent-uuid")
        assert found is None


# ── PIR (Patient Information Request) ──

class TestPIR:
    """Test Patient Information Request via Bedrock consent flow."""

    def test_create_pir(self, adapter, patient, provider):
        pir = adapter.create_pir(
            patient_uuid=patient.uuid,
            requester_uuid=provider.uuid,
            categories=["identity", "demographics"],
            purpose="patient_portal",
        )
        assert pir is not None
        assert pir.patient_uuid == patient.uuid
        assert pir.requester_uuid == provider.uuid
        assert pir.status == PIRStatus.PENDING
        assert pir.consent_id is not None

    def test_approve_pir(self, adapter, patient, provider):
        pir = adapter.create_pir(
            patient_uuid=patient.uuid,
            requester_uuid=provider.uuid,
            categories=["identity"],
            purpose="patient_portal",
        )
        approved = adapter.approve_pir(pir.uuid)
        assert approved.status == PIRStatus.APPROVED

    def test_deny_pir(self, adapter, patient, provider):
        pir = adapter.create_pir(
            patient_uuid=patient.uuid,
            requester_uuid=provider.uuid,
            categories=["identity"],
            purpose="patient_portal",
        )
        denied = adapter.deny_pir(pir.uuid)
        assert denied.status == PIRStatus.DENIED

    def test_approve_pir_not_found(self, adapter):
        with pytest.raises(KeyError, match="not found"):
            adapter.approve_pir("nonexistent-uuid")

    def test_deny_pir_not_found(self, adapter):
        with pytest.raises(KeyError, match="not found"):
            adapter.deny_pir("nonexistent-uuid")

    def test_pir_categories_preserved(self, adapter, patient, provider):
        categories = ["identity", "demographics", "medical"]
        pir = adapter.create_pir(
            patient_uuid=patient.uuid,
            requester_uuid=provider.uuid,
            categories=categories,
            purpose="patient_portal",
        )
        assert pir.categories == categories


# ── ePRR (Electronic Patient Records Release) ──

class TestEPRR:
    """Test Electronic Patient Records Release via Bedrock consent flow."""

    def test_create_eprr(self, adapter, patient, provider):
        eprr = adapter.create_eprr(
            patient_uuid=patient.uuid,
            recipient_uuid=provider.uuid,
            record_categories=["medical", "diagnosis", "prescription"],
        )
        assert eprr is not None
        assert eprr.patient_uuid == patient.uuid
        assert eprr.recipient_uuid == provider.uuid
        assert eprr.status == EPRRStatus.PENDING
        assert eprr.consent_id is not None

    def test_release_eprr(self, adapter, patient, provider):
        eprr = adapter.create_eprr(
            patient_uuid=patient.uuid,
            recipient_uuid=provider.uuid,
            record_categories=["medical"],
        )
        released = adapter.release_eprr(eprr.uuid)
        assert released.status == EPRRStatus.RELEASED
        assert released.release_token is not None

    def test_release_eprr_not_found(self, adapter):
        with pytest.raises(KeyError, match="not found"):
            adapter.release_eprr("nonexistent-uuid")

    def test_eprr_categories_preserved(self, adapter, patient, provider):
        categories = ["medical", "diagnosis", "prescription", "lab"]
        eprr = adapter.create_eprr(
            patient_uuid=patient.uuid,
            recipient_uuid=provider.uuid,
            record_categories=categories,
        )
        assert eprr.record_categories == categories


# ── E2EE Messaging ──

class TestE2EEMessaging:
    """Test E2EE messaging via Bedrock FieldEncryptor."""

    def test_send_message(self, adapter, patient, provider):
        message = adapter.send_message(
            sender_uuid=provider.uuid,
            recipient_uuid=patient.uuid,
            subject="Test Message",
            body="This is a test message.",
        )
        assert message is not None
        assert message.sender_uuid == provider.uuid
        assert message.recipient_uuid == patient.uuid
        assert message.status == E2EEStatus.DELIVERED

    def test_send_message_custom_ttl(self, adapter, patient, provider):
        message = adapter.send_message(
            sender_uuid=provider.uuid,
            recipient_uuid=patient.uuid,
            subject="Urgent",
            body="Please respond ASAP.",
            ttl_seconds=3600,
        )
        assert message is not None

    def test_decrypt_message(self, adapter, patient, provider):
        """Verify message content can be decrypted."""
        original_subject = "Secret Subject"
        original_body = "Secret body content."
        message = adapter.send_message(
            sender_uuid=provider.uuid,
            recipient_uuid=patient.uuid,
            subject=original_subject,
            body=original_body,
        )
        # The stored message has encrypted subject/body
        assert message.subject != original_subject  # Should be encrypted
        assert message.body != original_body  # Should be encrypted

        # Decrypt and verify
        decrypted = adapter.decrypt_message(message)
        assert decrypted.subject == original_subject
        assert decrypted.body == original_body


# ── Audit Trail ──

class TestAuditTrail:
    """Test audit trail via Bedrock AuditChain."""

    def test_audit_trail_records_patient_registration(self, adapter):
        adapter.register_patient(
            name="Audited Patient",
            email="audited@example.com",
            phone="555-0707",
        )
        trail = adapter.get_audit_trail()
        actions = [e["action"] for e in trail]
        assert "patient_registered" in actions

    def test_audit_trail_records_intake(self, adapter, patient):
        adapter.create_intake(patient.uuid)
        trail = adapter.get_audit_trail()
        actions = [e["action"] for e in trail]
        assert "intake_created" in actions

    def test_audit_trail_records_pir(self, adapter, patient, provider):
        adapter.create_pir(
            patient_uuid=patient.uuid,
            requester_uuid=provider.uuid,
            categories=["identity"],
            purpose="patient_portal",
        )
        trail = adapter.get_audit_trail()
        actions = [e["action"] for e in trail]
        assert "pir_created" in actions

    def test_audit_trail_records_pir_approval(self, adapter, patient, provider):
        pir = adapter.create_pir(
            patient_uuid=patient.uuid,
            requester_uuid=provider.uuid,
            categories=["identity"],
            purpose="patient_portal",
        )
        adapter.approve_pir(pir.uuid)
        trail = adapter.get_audit_trail()
        actions = [e["action"] for e in trail]
        assert "pir_approved" in actions

    def test_audit_trail_records_message(self, adapter, patient, provider):
        adapter.send_message(
            sender_uuid=provider.uuid,
            recipient_uuid=patient.uuid,
            subject="Audit Test",
            body="Testing audit trail.",
        )
        trail = adapter.get_audit_trail()
        actions = [e["action"] for e in trail]
        assert "message_sent" in actions

    def test_verify_integrity(self, adapter):
        """Audit chain integrity should be verifiable."""
        assert adapter.verify_integrity() is True


# ── Silo Integration ──

class TestSiloIntegration:
    """Test that InFill adapter initializes and uses Bedrock silos correctly."""

    def test_healthcare_silos_initialized(self, adapter):
        """Adapter should initialize 3 healthcare silos."""
        silos = adapter._silos.list_silos()
        silo_names = {s.name for s in silos}
        assert "identity" in silo_names
        assert "medical" in silo_names
        assert "auth" in silo_names

    def test_identity_silo_categories(self, adapter):
        """Identity silo should have healthcare identity categories."""
        silo = adapter._silos.get_silo("identity")
        assert "identity" in silo.categories
        assert "demographics" in silo.categories
        assert "ssn" in silo.categories

    def test_medical_silo_categories(self, adapter):
        """Medical silo should have healthcare medical categories."""
        silo = adapter._silos.get_silo("medical")
        assert "medical" in silo.categories
        assert "diagnosis" in silo.categories

    def test_auth_silo_categories(self, adapter):
        """Auth silo should have healthcare auth categories."""
        silo = adapter._silos.get_silo("auth")
        assert "auth" in silo.categories
        assert "mfa" in silo.categories

    def test_encrypted_patient_data_stored(self, adapter):
        """Patient data should be stored encrypted in identity silo."""
        patient = adapter.register_patient(
            name="Silo Test",
            email="silo@example.com",
            phone="555-0808",
        )
        # Retrieve encrypted data from internal store
        key = f"patient:{patient.uuid}"
        assert key in adapter._patient_data
        encrypted = adapter._patient_data[key]
        # Encrypted values should not match plaintext
        assert encrypted["name"] != "Silo Test"
        # But decrypted should match
        decrypted = adapter.decrypt_patient_data(patient.uuid)
        assert decrypted["name"] == "Silo Test"

    def test_pii_stored_separately(self, adapter):
        """PII (DOB, SSN) should be stored separately from identity data."""
        patient = adapter.register_patient(
            name="PII Test",
            email="pii@example.com",
            phone="555-0909",
            date_of_birth="1985-03-15",
            ssn_last4="6789",
        )
        pii = adapter.decrypt_patient_pii(patient.uuid)
        assert pii is not None
        assert pii["date_of_birth"] == "1985-03-15"
        assert pii["ssn_last4"] == "6789"


# ── Domain Models ──

class TestDomainModels:
    """Test InFill domain model dataclasses."""

    def test_patient_role_enum(self):
        assert PatientRole.PATIENT.value == "patient"
        assert PatientRole.PROVIDER.value == "provider"
        assert PatientRole.ADMIN.value == "admin"
        assert PatientRole.SUPER_ADMIN.value == "super_admin"

    def test_intake_status_enum(self):
        assert IntakeStatus.DRAFT.value == "draft"
        assert IntakeStatus.SUBMITTED.value == "submitted"
        assert IntakeStatus.APPROVED.value == "approved"

    def test_pir_status_enum(self):
        assert PIRStatus.PENDING.value == "pending"
        assert PIRStatus.APPROVED.value == "approved"
        assert PIRStatus.DENIED.value == "denied"

    def test_eprr_status_enum(self):
        assert EPRRStatus.PENDING.value == "pending"
        assert EPRRStatus.RELEASED.value == "released"

    def test_e2ee_status_enum(self):
        assert E2EEStatus.PENDING.value == "pending"
        assert E2EEStatus.DELIVERED.value == "delivered"
        assert E2EEStatus.READ.value == "read"

    def test_patient_defaults(self):
        patient = Patient(
            uuid="test-uuid",
            name="Test",
            email="test@example.com",
            phone="555-0000",
        )
        assert patient.role == PatientRole.PATIENT
        assert patient.date_of_birth is None
        assert patient.ssn_last4 is None
        assert patient.node_id is None