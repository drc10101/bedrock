"""SDK Integration Tests — End-to-end workflows through the Python SDK.

Tests that BedrockClient correctly wires all Core modules together
for realistic healthcare, banking, and multi-silo scenarios.

Trade Secret — InFill Systems, LLC. All rights reserved.
"""

import hashlib
import hmac
import struct
import time

import pytest
from bedrock_sdk import BedrockClient


def _generate_totp(secret_hex: str) -> str:
    """Generate a valid TOTP code for testing MFA."""
    key = bytes.fromhex(secret_hex)
    current_step = int(time.time()) // 30
    time_bytes = struct.pack(">Q", current_step)
    h = hmac.new(key, time_bytes, hashlib.sha1).digest()
    offset_val = h[-1] & 0x0F
    code_int = (
        ((h[offset_val] & 0x7F) << 24)
        | ((h[offset_val + 1] & 0xFF) << 16)
        | ((h[offset_val + 2] & 0xFF) << 8)
        | (h[offset_val + 3] & 0xFF)
    ) % 1000000
    return f"{code_int:06d}"


@pytest.fixture
def client():
    """Create a developer-mode BedrockClient."""
    return BedrockClient(mode="developer")


# ---------------------------------------------------------------------------
# Workflow 1: Healthcare — Register provider, encrypt PHI, consent, audit
# ---------------------------------------------------------------------------


class TestHealthcareWorkflow:
    """End-to-end healthcare scenario: PHI encryption with consent-gated access."""

    def test_full_healthcare_flow(self, client):
        # Register a provider node
        provider = client.identity.register("provider-alice")
        assert provider.name == "provider-alice"
        assert provider.node_id is not None

        # Issue a certificate for the provider
        cert = client.identity.issue_certificate(
            node_uuid=provider.node_id.uuid,
            node_name="provider-alice",
            public_key_hash="sha256:provider-public-key",
        )
        assert cert.status.value == "active"

        # Create a capability scope for medical data
        scope = client.identity.create_scope(
            node_id=provider.node_id.uuid,
            categories=["identity", "medical"],
        )
        # Categories are DataCategory enum values, check by .value
        assert any(c.value == "identity" for c in scope.categories)
        assert any(c.value == "medical" for c in scope.categories)

        # Encrypt a patient's medical record
        plaintext = "BP: 120/80, HR: 72, Temp: 98.6F"
        ciphertext = client.encryption.encrypt(
            plaintext=plaintext,
            silo="medical",
            record_id="patient-001-vitals",
            scope="read",
            operation="field",
        )
        assert ciphertext.startswith("v2:")
        assert plaintext != ciphertext

        # Decrypt it back
        decrypted = client.encryption.decrypt(
            ciphertext=ciphertext,
            silo="medical",
            record_id="patient-001-vitals",
            scope="read",
            operation="field",
        )
        assert decrypted == plaintext

        # Wrong silo should fail
        with pytest.raises(ValueError, match="AAD context mismatch"):
            client.encryption.decrypt(
                ciphertext=ciphertext,
                silo="identity",
                record_id="patient-001-vitals",
                scope="read",
                operation="field",
            )

        # Request cross-silo consent
        consent_id = client.data.request_consent(
            requesting_node_id=provider.node_id.uuid,
            source_silo="medical",
            target_silo="identity",
            categories=["identity"],
            scope="read",
            reason="Cross-reference patient identity",
        )
        assert consent_id is not None

        # Patient approves consent
        assert client.data.approve_consent(consent_id, "patient-001", ttl_seconds=3600)

        # Verify consent is valid
        assert client.data.check_consent(consent_id) is True

        # Audit the entire access
        chain_hash = client.audit.log(
            action="phi.access",
            actor_id=provider.node_id.uuid,
            target_id="patient-001",
            silo="medical",
            details={"consent_id": consent_id, "scope": "read"},
        )
        assert chain_hash is not None

        # Verify audit chain integrity
        assert client.audit.verify() is True

        # Query audit trail
        entries = client.audit.query(silo="medical")
        assert len(entries) >= 1
        assert entries[0]["action"] == "phi.access"

        # Revoke consent
        assert client.data.revoke_consent(consent_id) is True
        assert client.data.check_consent(consent_id) is False


# ---------------------------------------------------------------------------
# Workflow 2: Banking — Identity, transactions, RBAC
# ---------------------------------------------------------------------------


class TestBankingWorkflow:
    """End-to-end banking scenario: RBAC with MFA-gated operations."""

    def test_banking_rbac_flow(self, client):
        # Create users with different roles
        client.access.create_user("admin-bank", "secure123", "admin")
        client.access.create_user("teller-bob", "pass456", "operator")
        client.access.create_user("auditor-carol", "view789", "viewer")

        # Authenticate admin and verify MFA
        admin_session = client.access.authenticate("admin-bank", "secure123", "admin")
        assert admin_session is not None
        assert admin_session.role.value == "admin"

        # Get the TOTP secret and generate a valid code
        admin_account = client.access._controller._users["admin-bank"]
        admin_code = _generate_totp(admin_account.totp_secret)

        # MFA required for CERT_ISSUE
        assert client.access.check_permission(admin_session, "cert.issue") is False
        client.access.verify_mfa(admin_session.session_id, admin_code)
        assert client.access.check_permission(admin_session, "cert.issue") is True

        # Teller can read and write but not manage admin config
        teller_session = client.access.authenticate("teller-bob", "pass456", "provider")
        teller_account = client.access._controller._users["teller-bob"]
        teller_code = _generate_totp(teller_account.totp_secret)
        client.access.verify_mfa(teller_session.session_id, teller_code)
        assert client.access.check_permission(teller_session, "data.read") is True
        assert client.access.check_permission(teller_session, "data.write") is True
        # Operator does NOT have admin.config even with MFA
        assert client.access.check_permission(teller_session, "admin.config") is False

        # Viewer can only read
        viewer_session = client.access.authenticate("auditor-carol", "view789", "partner")
        assert client.access.check_permission(viewer_session, "data.read") is True
        assert client.access.check_permission(viewer_session, "data.write") is False

        # Encrypt a transaction amount
        amount = "$15,432.50"
        encrypted_amount = client.encryption.encrypt(
            plaintext=amount,
            silo="transaction",
            record_id="txn-2026-001",
            scope="read",
            operation="field",
        )

        # Decrypt with correct context
        assert client.encryption.decrypt(
            encrypted_amount, "transaction", "txn-2026-001", "read", "field",
        ) == amount

        # Audit the transaction access
        client.audit.log(
            "transaction.read",
            teller_session.user_id,
            "txn-2026-001",
            "transaction",
        )
        assert client.audit.verify() is True

        # Wrong password should fail (portal is required param)
        wrong_auth = client.access.authenticate("teller-bob", "wrong-password", "provider")
        assert wrong_auth is None


# ---------------------------------------------------------------------------
# Workflow 3: Defense — Mesh, attestation, healing
# ---------------------------------------------------------------------------


class TestDefenseMeshWorkflow:
    """End-to-end defense scenario: self-healing mesh under attack."""

    def test_mesh_attack_detection_and_healing(self, client):
        # Set instant healing for testing
        client.transport._mesh.healing_period_seconds = 0

        # Register nodes via transport (creates them in the mesh)
        target = client.transport.register_mesh_node("high-value-target")
        observer1 = client.transport.register_mesh_node("sensor-alpha")
        observer2 = client.transport.register_mesh_node("sensor-beta")

        # Add neighbor relationships
        client.transport._mesh.add_neighbor(target.node_id.uuid, observer1.node_id.uuid)
        client.transport._mesh.add_neighbor(target.node_id.uuid, observer2.node_id.uuid)

        # Two observers flag the target (reaches consensus threshold of 2)
        client.transport.flag_node(
            observer1.node_id.uuid, target.node_id.uuid, "credential_stuffing",
        )
        client.transport.flag_node(
            observer2.node_id.uuid, target.node_id.uuid, "lateral_movement",
        )

        # Round 1: ACTIVE -> SUSPECT
        quarantined = client.transport.process_flags()
        node = client.transport._mesh.get_node(target.node_id.uuid)
        assert node.state.value == "suspect"

        # Round 2: SUSPECT -> QUARANTINED
        quarantined = client.transport.process_flags()
        assert target.node_id.uuid in quarantined
        node = client.transport._mesh.get_node(target.node_id.uuid)
        assert node.state.value == "quarantined"

        # Begin healing (uses mesh with default healing_period, but
        # begin_healing succeeds immediately for QUARANTINED nodes)
        heal_result = client.transport.begin_healing(
            target.node_id.uuid,
            reason="Investigation complete, node restored",
        )
        assert heal_result["success"] is True
        assert heal_result["new_state"] == "healing"

        # Complete healing
        complete_result = client.transport.complete_healing(target.node_id.uuid)
        assert complete_result["success"] is True
        assert complete_result["new_state"] == "active"
        client.audit.log(
            "mesh.incident",
            "system",
            target.node_id.uuid,
            "identity",
            details={
                "signal_types": ["credential_stuffing", "lateral_movement"],
                "outcome": "quarantined_then_healing",
            },
        )
        assert client.audit.verify() is True


# ---------------------------------------------------------------------------
# Workflow 4: Multi-silo with anonymous IDs
# ---------------------------------------------------------------------------


class TestMultiSiloAnonymousWorkflow:
    """Cross-silo data access with anonymous ID mapping and right to be forgotten."""

    def test_anonymous_id_lifecycle(self, client):
        # Create anonymous IDs for a patient across silos
        med_anon = client.data.create_anonymous_id("patient-42", "medical")
        id_anon = client.data.create_anonymous_id("patient-42", "identity")
        txn_anon = client.data.create_anonymous_id("patient-42", "transaction")

        # Each silo gets a different anonymous ID
        assert med_anon != id_anon
        assert id_anon != txn_anon

        # Resolve back to real identity
        assert client.data.resolve_anonymous_id(med_anon) == "patient-42"
        assert client.data.resolve_anonymous_id(id_anon) == "patient-42"

        # Encrypt data using anonymous IDs
        data = "Diagnosis: cleared"
        encrypted = client.encryption.encrypt(
            plaintext=data,
            silo="medical",
            record_id=med_anon,
            scope="read",
            operation="field",
        )
        assert encrypted.startswith("v2:")

        # Decrypt with correct context
        decrypted = client.encryption.decrypt(
            encrypted, "medical", med_anon, "read", "field",
        )
        assert decrypted == data

        # Right to be forgotten — remove all anonymous IDs
        assert client.data.remove_identity("patient-42") is True
        assert client.data.resolve_anonymous_id(med_anon) is None
        assert client.data.resolve_anonymous_id(id_anon) is None
        assert client.data.resolve_anonymous_id(txn_anon) is None

        # Audit the deletion
        client.audit.log(
            "identity.deleted",
            "system",
            "patient-42",
            "identity",
            details={"reason": "right_to_be_forgotten"},
        )
        assert client.audit.verify() is True


# ---------------------------------------------------------------------------
# Workflow 5: Key rotation and chain continuity
# ---------------------------------------------------------------------------


class TestKeyRotationWorkflow:
    """Key rotation preserves audit chain and data access."""

    def test_key_rotation_preserves_chain(self, client):
        # Encrypt data with initial key
        data = "Confidential report v1"
        v1_ciphertext = client.encryption.encrypt(
            plaintext=data,
            silo="audit",
            record_id="report-001",
            scope="read",
            operation="field",
        )

        # Audit some events
        client.audit.log("data.write", "admin", "report-001", "audit")
        client.audit.log("data.read", "analyst", "report-001", "audit")

        # Rotate the master key
        new_key = client.encryption.rotate_master_key()
        assert new_key is not None

        # Encrypt new data with rotated key
        data_v2 = "Confidential report v2"
        v2_ciphertext = client.encryption.encrypt(
            plaintext=data_v2,
            silo="audit",
            record_id="report-001",
            scope="read",
            operation="field",
        )

        # Verify both ciphertexts exist
        assert v1_ciphertext != v2_ciphertext
        assert v1_ciphertext.startswith("v2:")
        assert v2_ciphertext.startswith("v2:")

        # Audit chain is still valid after rotation
        client.audit.log("key.rotation", "admin", "master-key", "audit")
        assert client.audit.verify() is True

        # Verify chain has all entries
        all_entries = client.audit.query()
        assert len(all_entries) == 3  # 2 before rotation + 1 rotation


# ---------------------------------------------------------------------------
# Workflow 6: Production mode configuration
# ---------------------------------------------------------------------------


class TestProductionModeWorkflow:
    """Production mode enforces stricter defaults."""

    def test_production_config(self):
        prod_client = BedrockClient(mode="production")
        assert prod_client.mode == "production"

    def test_developer_config(self):
        dev_client = BedrockClient(mode="developer")
        assert dev_client.mode == "developer"

    def test_default_is_developer(self):
        default_client = BedrockClient()
        assert default_client.mode == "developer"

    def test_production_tls_config(self, client):
        """Transport TLS in production mode requires CA certs."""
        config = client.transport.configure_tls(
            mode="production",
            cert_path="/certs/server.pem",
            key_path="/certs/server.key",
            ca_cert_path="/certs/ca.pem",
        )
        assert config.is_production_mode() is True
        assert config.min_version.value == "1.3"
        assert config.verify_client is True

    def test_developer_tls_config(self, client):
        """Transport TLS in developer mode allows self-signed."""
        config = client.transport.configure_tls(mode="developer")
        assert config.is_developer_mode() is True
        assert config.min_version.value == "1.2"
        assert config.verify_client is False

    def test_downgrade_detection_http(self, client):
        """HTTP is always a downgrade."""
        client.transport.configure_tls(mode="developer")
        result = client.transport.detect_downgrade({"x-forwarded-proto": "http"})
        assert result == "downgrade"

    def test_downgrade_detection_tls_version(self, client):
        """TLS version below minimum is a downgrade."""
        client.transport.configure_tls(mode="production")
        result = client.transport.detect_downgrade({
            "x-forwarded-proto": "https",
            "x-tls-version": "1.2",
        })
        assert result == "downgrade"

    def test_downgrade_detection_secure(self, client):
        """HTTPS with valid TLS version is secure."""
        client.transport.configure_tls(mode="developer")
        result = client.transport.detect_downgrade({
            "x-forwarded-proto": "https",
            "x-tls-version": "1.3",
        })
        assert result == "secure"


# ---------------------------------------------------------------------------
# Workflow 7: Certificate lifecycle
# ---------------------------------------------------------------------------


class TestCertificateLifecycle:
    """Certificate issuance, verification, and revocation."""

    def test_certificate_lifecycle(self, client):
        # Register node and issue certificate
        node = client.identity.register("lifecycle-node")
        cert = client.identity.issue_certificate(
            node_uuid=node.node_id.uuid,
            node_name="lifecycle-node",
            public_key_hash="sha256:lifecycle-key",
        )
        assert cert.status.value == "active"
        assert cert.node_uuid == node.node_id.uuid

        # Revoke the certificate
        revoked = client.identity.revoke_certificate(node.node_id.uuid, "key compromised")
        assert revoked.status.value == "revoked"

        # Attempt to revoke nonexistent should raise KeyError
        with pytest.raises(KeyError, match="No certificate found"):
            client.identity.revoke_certificate("nonexistent-uuid")

        # Audit the revocation
        client.audit.log(
            "cert.revoke",
            "admin",
            node.node_id.uuid,
            "identity",
            details={"reason": "key compromised"},
        )
        assert client.audit.verify() is True


# ---------------------------------------------------------------------------
# Workflow 8: Rate limiting
# ---------------------------------------------------------------------------


class TestRateLimiting:
    """Rate limiting protects against abuse."""

    def test_rate_limit_allows_normal_traffic(self, client):
        # Normal traffic should be allowed
        result = client.transport.check_rate_limit("node-1")
        assert result == "allowed"

    def test_rate_limit_different_keys(self, client):
        # Different keys should be tracked independently
        r1 = client.transport.check_rate_limit("node-1")
        r2 = client.transport.check_rate_limit("node-2")
        assert r1 == "allowed"
        assert r2 == "allowed"