"""Tests for the Bedrock Python SDK.

Validates that all SDK modules correctly wrap Core functionality
with a developer-friendly API.

Trade Secret — InFill Systems, LLC. All rights reserved.
"""

import pytest

from bedrock_sdk import BedrockClient
from bedrock.identity.node import NodeState
from bedrock.identity.certificates import LicenseExceededError
from bedrock.data_separation.consent import ConsentStatus
from bedrock.access_control.controller import Role, Portal, Permission, Session
from bedrock.mesh.detector import SignalType
from bedrock.identity.capabilities import DataCategory


# ---------------------------------------------------------------------------
# 1. Client Initialization
# ---------------------------------------------------------------------------

class TestClientInit:
    """Test BedrockClient initialization."""

    def test_developer_mode(self):
        client = BedrockClient(mode="developer")
        assert client.mode == "developer"

    def test_production_mode(self):
        client = BedrockClient(mode="production")
        assert client.mode == "production"

    def test_modules_accessible(self):
        client = BedrockClient(mode="developer")
        assert client.identity is not None
        assert client.encryption is not None
        assert client.data is not None
        assert client.audit is not None
        assert client.access is not None
        assert client.transport is not None


# ---------------------------------------------------------------------------
# 2. Identity Module
# ---------------------------------------------------------------------------

class TestIdentityModule:
    """Test SDK identity operations."""

    def setup_method(self):
        self.client = BedrockClient(mode="developer")

    def test_register_node(self):
        node = self.client.identity.register("test-server")
        assert node is not None
        assert node.name == "test-server"
        assert node.state == NodeState.ACTIVE
        assert node.node_id is not None
        assert node.node_id.uuid is not None

    def test_get_node(self):
        node = self.client.identity.register("my-node")
        found = self.client.identity.get(node.node_id.uuid)
        assert found is not None
        assert found.node_id.uuid == node.node_id.uuid

    def test_unregister_node(self):
        node = self.client.identity.register("temp-node")
        assert self.client.identity.unregister(node.node_id.uuid) is True
        assert self.client.identity.get(node.node_id.uuid) is None

    def test_unregister_nonexistent(self):
        assert self.client.identity.unregister("nonexistent") is False

    def test_issue_certificate(self):
        node = self.client.identity.register("cert-node")
        cert = self.client.identity.issue_certificate(
            node_uuid=node.node_id.uuid,
            node_name="cert-node",
            public_key_hash="abc123",
        )
        assert cert is not None
        assert cert.node_uuid == node.node_id.uuid
        assert cert.status.value == "active"

    def test_revoke_certificate(self):
        node = self.client.identity.register("revoke-node")
        self.client.identity.issue_certificate(
            node_uuid=node.node_id.uuid,
            node_name="revoke-node",
            public_key_hash="def456",
        )
        revoked = self.client.identity.revoke_certificate(
            node_uuid=node.node_id.uuid,
            reason="Compromised",
        )
        assert revoked.status.value == "revoked"

    def test_developer_license_limit(self):
        client = BedrockClient(mode="developer")
        for i in range(3):
            node = client.identity.register(f"dev-node-{i}")
            client.identity.issue_certificate(
                node_uuid=node.node_id.uuid,
                node_name=f"dev-node-{i}",
                public_key_hash=f"hash-{i}",
            )
        node4 = client.identity.register("dev-node-4")
        with pytest.raises(LicenseExceededError):
            client.identity.issue_certificate(
                node_uuid=node4.node_id.uuid,
                node_name="dev-node-4",
                public_key_hash="hash-4",
            )

    def test_create_scope(self):
        node = self.client.identity.register("scoped-node")
        scope = self.client.identity.create_scope(
            node_id=node.node_id.uuid,
            categories=["identity", "medical"],
        )
        assert scope is not None
        assert DataCategory.IDENTITY in scope.categories
        assert DataCategory.MEDICAL in scope.categories

    def test_register_baseline(self):
        # Should not raise
        self.client.identity.register_baseline(
            node_type="edge-gateway",
            version="1.0.0",
            baseline_hash="sha256:abc123",
        )


# ---------------------------------------------------------------------------
# 3. Encryption Module
# ---------------------------------------------------------------------------

class TestEncryptionModule:
    """Test SDK encryption operations."""

    def setup_method(self):
        self.client = BedrockClient(mode="developer")

    def test_encrypt_decrypt(self):
        ciphertext = self.client.encryption.encrypt(
            plaintext="Sensitive patient data",
            silo="medical",
            record_id="rec-001",
        )
        assert ciphertext != "Sensitive patient data"

        plaintext = self.client.encryption.decrypt(
            ciphertext=ciphertext,
            silo="medical",
            record_id="rec-001",
        )
        assert plaintext == "Sensitive patient data"

    def test_wrong_silo_fails(self):
        ciphertext = self.client.encryption.encrypt(
            plaintext="Secret data",
            silo="identity",
            record_id="rec-002",
        )
        with pytest.raises(Exception):
            self.client.encryption.decrypt(
                ciphertext=ciphertext,
                silo="medical",
                record_id="rec-002",
            )

    def test_e2ee_encrypt_decrypt(self):
        priv, pub = self.client.encryption.generate_key_pair()
        ciphertext = self.client.encryption.e2ee_encrypt(
            plaintext="Secret message",
            recipient_public_key=pub,
            sender_private_key=priv,
        )
        plaintext = self.client.encryption.e2ee_decrypt(
            ciphertext=ciphertext,
            recipient_private_key=priv,
            sender_public_key=pub,
        )
        assert plaintext == "Secret message"

    def test_rotate_master_key(self):
        new_key = self.client.encryption.rotate_master_key()
        assert isinstance(new_key, str)
        assert len(new_key) > 0


# ---------------------------------------------------------------------------
# 4. Data Module
# ---------------------------------------------------------------------------

class TestDataModule:
    """Test SDK data separation and consent operations."""

    def setup_method(self):
        self.client = BedrockClient(mode="developer")

    def test_consent_lifecycle(self):
        node = self.client.identity.register("provider")
        consent_id = self.client.data.request_consent(
            requesting_node_id=node.node_id.uuid,
            source_silo="medical",
            target_silo="research",
            categories=["diagnosis"],
            scope="read",
            reason="Research study",
        )
        assert consent_id is not None

        approved = self.client.data.approve_consent(
            consent_id=consent_id,
            data_owner_id="patient-001",
            ttl_seconds=3600,
        )
        assert approved is True

        assert self.client.data.check_consent(consent_id) is True

        assert self.client.data.revoke_consent(consent_id) is True
        assert self.client.data.check_consent(consent_id) is False

    def test_anonymous_id(self):
        anon_id = self.client.data.create_anonymous_id("real-001", "medical")
        assert anon_id is not None

        resolved = self.client.data.resolve_anonymous_id(anon_id)
        assert resolved == "real-001"

    def test_remove_identity(self):
        self.client.data.create_anonymous_id("real-002", "identity")
        assert self.client.data.remove_identity("real-002") is True


# ---------------------------------------------------------------------------
# 5. Audit Module
# ---------------------------------------------------------------------------

class TestAuditModule:
    """Test SDK audit chain operations."""

    def setup_method(self):
        self.client = BedrockClient(mode="developer")

    def test_log_and_verify(self):
        self.client.audit.log(
            action="node.register",
            actor_id="registration-service",
            target_id="node-001",
            silo="identity",
        )
        assert self.client.audit.verify() is True

    def test_log_with_details(self):
        self.client.audit.log(
            action="field.encrypt",
            actor_id="node-001",
            target_id="record-123",
            silo="medical",
            details={"category": "DIAGNOSIS"},
        )
        assert self.client.audit.verify() is True

    def test_query_by_action(self):
        self.client.audit.log(
            action="consent.approve",
            actor_id="patient-001",
            target_id="provider-001",
            silo="consent",
        )
        results = self.client.audit.query(action="consent.approve")
        assert len(results) == 1
        assert results[0]["action"] == "consent.approve"

    def test_query_by_actor(self):
        self.client.audit.log(
            action="field.encrypt",
            actor_id="actor-001",
            target_id="target-001",
            silo="medical",
        )
        results = self.client.audit.query(actor_id="actor-001")
        assert len(results) >= 1

    def test_export_chain(self):
        self.client.audit.log(
            action="node.register",
            actor_id="test",
            target_id="node-001",
            silo="identity",
        )
        exported = self.client.audit.export_chain()
        assert exported is not None
        assert len(exported) > 0

    def test_head_and_tail_hash(self):
        self.client.audit.log(
            action="node.register",
            actor_id="test",
            target_id="node-001",
            silo="identity",
        )
        assert self.client.audit.head_hash() is not None
        assert self.client.audit.tail_hash() is not None


# ---------------------------------------------------------------------------
# 6. Access Module
# ---------------------------------------------------------------------------

class TestAccessModule:
    """Test SDK access control operations."""

    def setup_method(self):
        self.client = BedrockClient(mode="developer")

    def test_create_user_and_authenticate(self):
        user_id = self.client.access.create_user(
            username="admin-user",
            password="SecurePass123!",
            role="admin",
        )
        assert user_id is not None

        session = self.client.access.authenticate(
            username="admin-user",
            password="SecurePass123!",
            portal="admin",
        )
        assert session is not None
        assert self.client.access.check_permission(session, "data.read") is True

    def test_viewer_cannot_write(self):
        self.client.access.create_user(
            username="viewer-user",
            password="ViewerPass123!",
            role="viewer",
        )
        session = self.client.access.authenticate(
            username="viewer-user",
            password="ViewerPass123!",
            portal="patient",
        )
        assert session is not None
        assert self.client.access.check_permission(session, "data.read") is True
        assert self.client.access.check_permission(session, "data.write") is False

    def test_end_session(self):
        self.client.access.create_user(
            username="temp-user",
            password="TempPass123!",
            role="operator",
        )
        session = self.client.access.authenticate(
            username="temp-user",
            password="TempPass123!",
            portal="provider",
        )
        assert session is not None
        assert self.client.access.end_session(session.session_id) is True


# ---------------------------------------------------------------------------
# 7. Transport Module
# ---------------------------------------------------------------------------

class TestTransportModule:
    """Test SDK transport and mesh operations."""

    def setup_method(self):
        self.client = BedrockClient(mode="developer")

    def test_configure_tls_developer(self):
        config = self.client.transport.configure_tls(
            mode="developer",
            cert_path="/path/to/cert",
            key_path="/path/to/key",
        )
        assert config.is_developer_mode() is True

    def test_configure_tls_production(self):
        config = self.client.transport.configure_tls(
            mode="production",
            cert_path="/path/to/cert",
            key_path="/path/to/key",
            ca_cert_path="/path/to/ca",
        )
        assert config.is_developer_mode() is False

    def test_detect_downgrade(self):
        self.client.transport.configure_tls(
            mode="production",
            cert_path="/path/to/cert",
            key_path="/path/to/key",
            ca_cert_path="/path/to/ca",
        )
        headers = {"x-forwarded-proto": "http"}
        result = self.client.transport.detect_downgrade(headers)
        assert result == "downgrade"

    def test_secure_headers(self):
        self.client.transport.configure_tls(
            mode="production",
            cert_path="/path/to/cert",
            key_path="/path/to/key",
            ca_cert_path="/path/to/ca",
        )
        headers = {"x-forwarded-proto": "https", "x-tls-version": "1.3"}
        result = self.client.transport.detect_downgrade(headers)
        assert result == "secure"

    def test_mesh_register_and_flag(self):
        from bedrock.identity.node import Node, NodeID
        from bedrock.identity.capabilities import CapabilityScope

        n1 = Node(node_id=NodeID.generate(), name="observer-1", state=NodeState.ACTIVE)
        n2 = Node(node_id=NodeID.generate(), name="observer-2", state=NodeState.ACTIVE)
        target = Node(node_id=NodeID.generate(), name="suspect", state=NodeState.ACTIVE)

        for node in [n1, n2, target]:
            scope = CapabilityScope(
                node_id=node.node_id.uuid,
                categories=[DataCategory.IDENTITY],
            )
            self.client.transport._mesh.register_node(node, scope)

        self.client.transport.flag_node(
            source_id=n1.node_id.uuid,
            target_id=target.node_id.uuid,
            signal_type="silent_node",
        )
        self.client.transport.flag_node(
            source_id=n2.node_id.uuid,
            target_id=target.node_id.uuid,
            signal_type="silent_node",
        )

        assert self.client.transport.check_consensus(target.node_id.uuid) is True

    def test_mesh_healing(self):
        from bedrock.identity.node import Node, NodeID
        from bedrock.identity.capabilities import CapabilityScope
        from bedrock.mesh.healing import SelfHealingMesh

        # Use a mesh with zero healing period for testing
        mesh = SelfHealingMesh(healing_period_seconds=0)
        transport_mod = self.client.transport
        transport_mod._mesh = mesh

        n1 = Node(node_id=NodeID.generate(), name="obs-1", state=NodeState.ACTIVE)
        n2 = Node(node_id=NodeID.generate(), name="obs-2", state=NodeState.ACTIVE)
        target = Node(node_id=NodeID.generate(), name="target", state=NodeState.ACTIVE)

        for node in [n1, n2, target]:
            scope = CapabilityScope(
                node_id=node.node_id.uuid,
                categories=[DataCategory.IDENTITY],
            )
            mesh.register_node(node, scope)

        # Flag and process twice: ACTIVE → SUSPECT → QUARANTINED
        mesh.flag_node(n1.node_id.uuid, target.node_id.uuid, SignalType.SILENT_NODE)
        mesh.flag_node(n2.node_id.uuid, target.node_id.uuid, SignalType.SILENT_NODE)
        mesh.process_flags()  # SUSPECT
        mesh.process_flags()  # QUARANTINED

        # Begin healing
        result = transport_mod.begin_healing(target.node_id.uuid, reason="Test healing")
        assert result["success"] is True

        # Complete healing (period=0 so it completes immediately)
        result = transport_mod.complete_healing(target.node_id.uuid)
        assert result["success"] is True


# ---------------------------------------------------------------------------
# 8. Cross-Module Integration (SDK Level)
# ---------------------------------------------------------------------------

class TestSDKIntegration:
    """Integration tests at the SDK level."""

    def test_full_patient_data_flow(self):
        """Complete patient data flow via SDK: register, encrypt, consent, audit."""
        client = BedrockClient(mode="developer")

        # 1. Register patient and provider
        patient = client.identity.register("patient-001")
        provider = client.identity.register("provider-001")

        # 2. Create user accounts and authenticate
        client.access.create_user(
            username="provider-001",
            password="SecurePass!",
            role="operator",
        )
        session = client.access.authenticate(
            username="provider-001",
            password="SecurePass!",
            portal="provider",
        )
        assert session is not None

        # 3. Encrypt patient data
        ciphertext = client.encryption.encrypt(
            plaintext="Patient health record: normal",
            silo="medical",
            record_id="record-001",
            scope="read",
        )

        # 4. Request and approve consent
        consent_id = client.data.request_consent(
            requesting_node_id=provider.node_id.uuid,
            source_silo="medical",
            target_silo="research",
            categories=["diagnosis"],
            scope="read",
            reason="Treatment coordination",
        )

        approved = client.data.approve_consent(
            consent_id=consent_id,
            data_owner_id=patient.node_id.uuid,
            ttl_seconds=86400,
        )
        assert approved is True

        # 5. Decrypt
        plaintext = client.encryption.decrypt(
            ciphertext=ciphertext,
            silo="medical",
            record_id="record-001",
            scope="read",
        )
        assert plaintext == "Patient health record: normal"

        # 6. Audit everything
        client.audit.log(
            action="node.register",
            actor_id="registration-service",
            target_id=patient.node_id.uuid,
            silo="identity",
        )
        client.audit.log(
            action="field.encrypt",
            actor_id=provider.node_id.uuid,
            target_id="record-001",
            silo="medical",
        )
        client.audit.log(
            action="consent.approve",
            actor_id=patient.node_id.uuid,
            target_id=provider.node_id.uuid,
            silo="consent",
        )

        # 7. Verify audit chain
        assert client.verify_integrity() is True

        # 8. Revoke consent
        client.data.revoke_consent(consent_id)
        assert client.data.check_consent(consent_id) is False

    def test_anonymous_id_with_encryption(self):
        """Use anonymous IDs alongside encryption for full identity separation."""
        client = BedrockClient(mode="developer")

        # Create anonymous ID
        anon_id = client.data.create_anonymous_id("real-patient-001", "medical")
        assert anon_id is not None

        # Encrypt data under the anonymous ID
        ciphertext = client.encryption.encrypt(
            plaintext="Diagnosis data",
            silo="medical",
            record_id=anon_id,
        )
        plaintext = client.encryption.decrypt(
            ciphertext=ciphertext,
            silo="medical",
            record_id=anon_id,
        )
        assert plaintext == "Diagnosis data"

        # Right to be forgotten
        client.data.remove_identity("real-patient-001")
        assert client.data.resolve_anonymous_id(anon_id) is None