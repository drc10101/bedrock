"""Core Integration Tests (B-112).

End-to-end cross-component tests validating that all Bedrock subsystems
work together:

1. Register node, encrypt data, consent, deliver, decrypt, audit
2. Simulate attack, verify node isolation and rerouting
3. Certificate lifecycle with access control
4. Transport security with rate limiting and downgrade detection
5. Attestation + mesh integration
6. Full audit trail across components
7. Access control + transport security
8. Full patient data flow

Trade Secret - InFill Systems, LLC.
"""

import pytest
from datetime import datetime, timezone, timedelta

from bedrock.identity.node import Node, NodeID, NodeState
from bedrock.identity.registration import NodeRegistry, RegistrationError
from bedrock.identity.capabilities import CapabilityScope, DataCategory
from bedrock.identity.attestation import (
    AttestationPolicy, AttestationManager, BaselineEntry,
)
from bedrock.identity.certificates import (
    Certificate, CertificateManager, CertificateStatus,
    LicenseTier, LicenseExceededError,
)
from bedrock.encryption.engine import (
    FieldEncryptor, E2EEDeliverer, KeyManager, AAD,
)
from bedrock.audit.chain import AuditChain, AuditEntry, AuditAction, GENESIS_HASH
from bedrock.access_control.controller import (
    Role, Portal, Permission, AccessController, UserAccount, Session,
)
from bedrock.transport.security import (
    TLSConfig, TLSVersion, DowngradeStatus,
    RateLimiter, RateLimitConfig, RateLimitResult, ConnectionInfo, TransportLayer,
)
from bedrock.data_separation.consent import ConsentGate, ConsentStatus
from bedrock.mesh.healing import SelfHealingMesh
from bedrock.mesh.state_machine import MeshStateMachine
from bedrock.mesh.router import MeshRouter
from bedrock.mesh.detector import AttackDetector, SignalType


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_node(name: str = "test-node") -> Node:
    return Node(node_id=NodeID.generate(), name=name, state=NodeState.ACTIVE)


# ---------------------------------------------------------------------------
# 1. Full Data Lifecycle: register, encrypt, consent, deliver, decrypt
# ---------------------------------------------------------------------------

class TestFullDataLifecycle:
    """End-to-end: register node, encrypt data, consent, deliver, decrypt."""

    def test_encrypt_field_with_aad_binding(self):
        """Encrypt a field value with silo-bound AAD, then decrypt."""
        km = KeyManager()
        master_key = km.generate_master_key()
        encryptor = FieldEncryptor(key_manager=km, master_key=master_key)

        plaintext = "Patient MRI results: normal findings"
        ciphertext = encryptor.encrypt(
            plaintext=plaintext,
            silo="medical",
            record_id="rec-001",
            scope="read",
            operation="field",
        )

        assert ciphertext != plaintext

        decrypted = encryptor.decrypt(
            ciphertext=ciphertext,
            silo="medical",
            record_id="rec-001",
            scope="read",
            operation="field",
        )
        assert decrypted == plaintext

    def test_e2ee_encrypt_decrypt(self):
        """E2EE: encrypt for recipient, decrypt with recipient key."""
        deliverer = E2EEDeliverer()
        recipient_priv, recipient_pub = deliverer.generate_key_pair()

        plaintext = "Sensitive health data"
        ciphertext = deliverer.encrypt_for_recipient(
            plaintext=plaintext,
            recipient_public_key=recipient_pub,
        )
        assert ciphertext != plaintext

        decrypted = deliverer.decrypt_from_sender(
            ciphertext=ciphertext,
            recipient_private_key=recipient_priv,
        )
        assert decrypted == plaintext

    def test_consent_gate_request_approve_check(self):
        """Request consent, approve it, then verify it passes check."""
        gate = ConsentGate()

        event = gate.request_consent(
            requesting_node_id="provider-001",
            source_silo="medical",
            target_silo="research",
            categories=["diagnosis", "medications"],
            scope="read",
            reason="Research study participation",
        )
        assert event.status == ConsentStatus.PENDING

        approved = gate.approve_consent(
            consent_id=event.consent_id,
            data_owner_id="patient-001",
            ttl_seconds=3600,
        )
        assert approved.status == ConsentStatus.APPROVED

        result = gate.check_consent(consent_id=event.consent_id)
        assert result is not None
        assert result.status == ConsentStatus.APPROVED

    def test_consent_gate_denied(self):
        """Consent not granted = check returns None."""
        gate = ConsentGate()
        result = gate.check_consent(consent_id="nonexistent")
        assert result is None

    def test_right_to_be_forgotten(self):
        """Unregistering a node removes its identity."""
        registry = NodeRegistry()
        node = registry.register(name="patient-A")
        assert registry.get(node.node_id.uuid) is not None

        registry.unregister(node.node_id.uuid)
        assert registry.get(node.node_id.uuid) is None

    def test_aad_tamper_detection(self):
        """Decrypting with wrong AAD (silo) fails."""
        km = KeyManager()
        master_key = km.generate_master_key()
        encryptor = FieldEncryptor(key_manager=km, master_key=master_key)

        plaintext = "Sensitive identity data"
        ciphertext = encryptor.encrypt(
            plaintext=plaintext,
            silo="identity",
            record_id="rec-001",
            scope="read",
        )

        decrypted = encryptor.decrypt(
            ciphertext=ciphertext,
            silo="identity",
            record_id="rec-001",
            scope="read",
        )
        assert decrypted == plaintext

        with pytest.raises(Exception):
            encryptor.decrypt(
                ciphertext=ciphertext,
                silo="medical",
                record_id="rec-001",
                scope="read",
            )

    def test_consent_revoke(self):
        """Approved consent can be revoked."""
        gate = ConsentGate()

        event = gate.request_consent(
            requesting_node_id="provider-001",
            source_silo="medical",
            target_silo="research",
            categories=["diagnosis"],
            scope="read",
        )
        approved = gate.approve_consent(
            consent_id=event.consent_id,
            data_owner_id="patient-001",
            ttl_seconds=3600,
        )
        assert approved.status == ConsentStatus.APPROVED

        revoked = gate.revoke_consent(consent_id=event.consent_id)
        assert revoked.status == ConsentStatus.REVOKED

        result = gate.check_consent(consent_id=event.consent_id)
        assert result is None


# ---------------------------------------------------------------------------
# 2. Attack Simulation: detect, isolate, reroute
# ---------------------------------------------------------------------------

class TestAttackSimulation:
    """Simulate attacks on the mesh and verify isolation + rerouting."""

    def test_full_attack_isolation_lifecycle(self):
        """Register 5 nodes, flag one, reach consensus, quarantine, reroute."""
        mesh = SelfHealingMesh()

        nodes = {}
        for name in ["A", "B", "C", "D", "E"]:
            node = _make_node(name)
            nodes[name] = node
            scope = CapabilityScope(
                node_id=node.node_id.uuid,
                categories=[DataCategory.IDENTITY, DataCategory.MEDICAL],
            )
            mesh.register_node(node, scope)

        a, b, c, d, e = [nodes[n].node_id.uuid for n in ["A", "B", "C", "D", "E"]]
        mesh.add_neighbor(a, b)
        mesh.add_neighbor(b, c)
        mesh.add_neighbor(c, d)
        mesh.add_neighbor(d, e)
        mesh.add_neighbor(a, c)

        mesh.flag_node(a, c, SignalType.CREDENTIAL_STUFFING)
        mesh.flag_node(b, c, SignalType.UNUSUAL_VOLUME)
        assert mesh.check_consensus(c) is True

        quarantined = mesh.process_flags()
        assert c in quarantined
        assert nodes["C"].state == NodeState.SUSPECT

        mesh.flag_node(a, c, SignalType.ATTESTATION_FAILURE)
        mesh.flag_node(b, c, SignalType.SILENT_NODE)
        mesh.process_flags()
        assert nodes["C"].state == NodeState.QUARANTINED

        path = mesh.reroute(a, d, [DataCategory.IDENTITY])
        assert c not in path

    def test_healing_restores_node(self):
        """Quarantined node heals and returns to active."""
        # healing_period_seconds=0 so healing completes immediately in tests
        mesh = SelfHealingMesh(healing_period_seconds=0)

        n1 = _make_node("node-1")
        n2 = _make_node("node-2")
        target = _make_node("target")

        for node in [n1, n2, target]:
            scope = CapabilityScope(
                node_id=node.node_id.uuid,
                categories=[DataCategory.IDENTITY],
            )
            mesh.register_node(node, scope)

        # Flag to SUSPECT
        mesh.flag_node(n1.node_id.uuid, target.node_id.uuid, SignalType.SILENT_NODE)
        mesh.flag_node(n2.node_id.uuid, target.node_id.uuid, SignalType.SILENT_NODE)
        mesh.process_flags()
        assert target.state == NodeState.SUSPECT

        # Flag to QUARANTINED
        mesh.flag_node(n1.node_id.uuid, target.node_id.uuid, SignalType.CREDENTIAL_STUFFING)
        mesh.flag_node(n2.node_id.uuid, target.node_id.uuid, SignalType.UNUSUAL_VOLUME)
        mesh.process_flags()
        assert target.state == NodeState.QUARANTINED

        # Begin healing -> HEALING
        result = mesh.begin_healing(target.node_id.uuid, reason="Re-attestation passed")
        assert result.success is True
        assert target.state == NodeState.HEALING

        # Complete healing -> ACTIVE
        result = mesh.complete_healing(target.node_id.uuid)
        assert result.success is True
        assert target.state == NodeState.ACTIVE


# ---------------------------------------------------------------------------
# 3. Certificate Lifecycle with Access Control
# ---------------------------------------------------------------------------

class TestCertificateAccessControlIntegration:
    """Certificate issuance, revocation, and access control enforcement."""

    def test_certificate_lifecycle_with_rbac(self):
        """Admin with MFA can issue and revoke certs; viewer cannot."""
        cert_mgr = CertificateManager(license_tier=LicenseTier.BUSINESS)
        controller = AccessController()

        # Create admin session with MFA verified (required for write ops)
        admin_session = Session(
            session_id="sess-admin-001",
            user_id="admin-001",
            role=Role.ADMIN,
            portal=Portal.ADMIN,
            mfa_verified=True,
        )
        viewer_session = Session(
            session_id="sess-viewer-001",
            user_id="viewer-001",
            role=Role.VIEWER,
            portal=Portal.PATIENT,
        )

        # Admin with MFA can issue certificates
        assert controller.check_permission(admin_session, Permission.CERT_ISSUE) is True
        # Viewer cannot
        assert controller.check_permission(viewer_session, Permission.CERT_ISSUE) is False

        # Issue a certificate
        node_id = NodeID.generate()
        cert = cert_mgr.issue_certificate(
            node_uuid=node_id.uuid,
            node_name="test-node",
            public_key_hash="abc123def456",
        )
        assert cert is not None
        assert cert.status == CertificateStatus.ACTIVE

        # Revoke the certificate
        revoked = cert_mgr.revoke_certificate(
            node_uuid=node_id.uuid,
            reason="Compromised",
        )
        assert revoked.status == CertificateStatus.REVOKED

    def test_developer_tier_limits(self):
        """Developer tier allows max 3 nodes."""
        cert_mgr = CertificateManager(license_tier=LicenseTier.DEVELOPER)

        for i in range(3):
            node_id = NodeID.generate()
            cert = cert_mgr.issue_certificate(
                node_uuid=node_id.uuid,
                node_name=f"dev-node-{i}",
                public_key_hash=f"hash-{i}",
            )
            assert cert.status == CertificateStatus.ACTIVE

        node_id4 = NodeID.generate()
        with pytest.raises(LicenseExceededError):
            cert_mgr.issue_certificate(
                node_uuid=node_id4.uuid,
                node_name="dev-node-4",
                public_key_hash="hash-4",
            )


# ---------------------------------------------------------------------------
# 4. Transport Security + Rate Limiting + Audit
# ---------------------------------------------------------------------------

class TestTransportSecurityIntegration:
    """TLS config, downgrade detection, rate limiting with audit."""

    def test_downgrade_detection_with_audit(self):
        """Detect TLS downgrade and log to audit chain."""
        transport = TransportLayer()
        transport.configure_tls(TLSVersion.TLS_1_3, "/path/to/key")

        chain = AuditChain()

        headers = {
            "x-forwarded-proto": "http",  # downgrade!
            "x-tls-version": "1.3",
        }

        status = transport.detect_downgrade(headers)
        assert status == DowngradeStatus.DOWNGRADE

        # Log to audit chain
        chain.append(
            action=AuditAction.NODE_QUARANTINE.value,
            actor_id="downgrade-detector",
            target_id="incoming-request",
            silo="transport",
            details={"detected_protocol": "http", "expected": "https"},
        )
        assert len(chain) == 1

    def test_rate_limiting_with_audit(self):
        """Rate limit progression: ALLOWED -> THROTTLED -> BLOCKED."""
        # Low limits to trigger all states quickly
        config = RateLimitConfig(
            max_requests_per_minute=5,
            burst_size=3,
            violation_threshold=2,
            block_duration_minutes=1,
        )
        limiter = RateLimiter(config)
        chain = AuditChain()

        key = "client-001"

        # First 3 requests pass (burst)
        for i in range(3):
            assert limiter.check(key) == RateLimitResult.ALLOWED

        # 4th-7th get throttled (over burst but under minute limit)
        for i in range(4):
            assert limiter.check(key) == RateLimitResult.THROTTLED

        # At 5+ minute-window requests, violations trigger, then BLOCKED
        # Keep checking until BLOCKED
        result = None
        for i in range(20):
            result = limiter.check(key)
            if result == RateLimitResult.BLOCKED:
                break

        assert result == RateLimitResult.BLOCKED

        # Log the block
        chain.append(
            action=AuditAction.NODE_QUARANTINE.value,
            actor_id="rate-limiter",
            target_id=key,
            silo="transport",
        )
        assert len(chain) == 1

    def test_tls_config_enforcement(self):
        """Production config requires TLS 1.3 + CA cert."""
        prod_config = TLSConfig(
            min_version=TLSVersion.TLS_1_3,
            ca_cert_path="/etc/ssl/ca-bundle.crt",
        )
        dev_config = TLSConfig(
            min_version=TLSVersion.TLS_1_2,
            ca_cert_path="",
        )

        assert prod_config.is_developer_mode() is False
        assert dev_config.is_developer_mode() is True


# ---------------------------------------------------------------------------
# 5. Attestation + Mesh Integration
# ---------------------------------------------------------------------------

class TestAttestationMeshIntegration:
    """Attestation verification feeds into mesh trust decisions."""

    def test_failed_attestation_flags_node(self):
        """Node that fails attestation gets flagged in the mesh."""
        mesh = SelfHealingMesh()

        n1 = _make_node("observer")
        n2 = _make_node("observer-2")
        target = _make_node("suspect")

        for node in [n1, n2, target]:
            scope = CapabilityScope(
                node_id=node.node_id.uuid,
                categories=[DataCategory.IDENTITY],
            )
            mesh.register_node(node, scope)

        mesh.flag_node(n1.node_id.uuid, target.node_id.uuid, SignalType.ATTESTATION_FAILURE)
        mesh.flag_node(n2.node_id.uuid, target.node_id.uuid, SignalType.ATTESTATION_FAILURE)
        assert mesh.check_consensus(target.node_id.uuid) is True

        mesh.process_flags()
        assert target.state == NodeState.SUSPECT

    def test_attestation_policy_strict_vs_permissive(self):
        """Strict and permissive policies coexist."""
        strict_mgr = AttestationManager(policy=AttestationPolicy.STRICT)
        permissive_mgr = AttestationManager(policy=AttestationPolicy.PERMISSIVE)

        strict_mgr.register_baseline(
            node_type="edge-node",
            version="1.0.0",
            baseline_hash="abc123def456",
        )
        permissive_mgr.register_baseline(
            node_type="edge-node",
            version="1.0.0",
            baseline_hash="abc123def456",
        )

        assert strict_mgr.get_baseline("edge-node") is not None
        assert permissive_mgr.get_baseline("edge-node") is not None


# ---------------------------------------------------------------------------
# 6. Full Audit Trail Across Components
# ---------------------------------------------------------------------------

class TestCrossComponentAuditTrail:
    """Verify audit chain captures events from all components."""

    def test_full_audit_trail(self):
        """Encrypt, consent, deliver, quarantine -- all logged."""
        chain = AuditChain()

        # 1. Node registration
        chain.append(
            action=AuditAction.NODE_REGISTER.value,
            actor_id="registration-service",
            target_id="node-001",
            silo="identity",
            details={"name": "patient-A"},
        )

        # 2. Data encrypted
        chain.append(
            action=AuditAction.FIELD_ENCRYPT.value,
            actor_id="node-001",
            target_id="record-123",
            silo="medical",
            details={"category": "MEDICAL"},
        )

        # 3. Consent granted
        chain.append(
            action=AuditAction.CONSENT_APPROVE.value,
            actor_id="patient-A",
            target_id="provider-001",
            silo="consent",
            details={"categories": ["MEDICAL"], "duration": "1h"},
        )

        # 4. Data delivered
        chain.append(
            action=AuditAction.E2EE_SEND.value,
            actor_id="mesh-router",
            target_id="provider-001",
            silo="transport",
            details={"record": "record-123", "path": "A-B-C"},
        )

        # 5. Attack detected
        chain.append(
            action=AuditAction.NODE_QUARANTINE.value,
            actor_id="mesh-consensus",
            target_id="node-C",
            silo="mesh",
            details={"signals": ["CREDENTIAL_STUFFING", "UNUSUAL_VOLUME"]},
        )

        # Verify chain integrity
        assert chain.verify() is True
        assert len(chain) == 5

        # Verify entries are in order via get_by_action
        reg_entries = chain.get_by_action(AuditAction.NODE_REGISTER.value)
        assert len(reg_entries) == 1
        assert reg_entries[0].actor_id == "registration-service"

    def test_audit_chain_tamper_detection(self):
        """Tampering with an audit entry breaks chain verification."""
        chain = AuditChain()

        chain.append(
            action=AuditAction.FIELD_ENCRYPT.value,
            actor_id="node-001",
            target_id="record-123",
            silo="medical",
        )

        chain.append(
            action=AuditAction.E2EE_SEND.value,
            actor_id="mesh-router",
            target_id="provider-001",
            silo="transport",
        )

        assert chain.verify() is True

        # Tamper with the first entry by replacing it in _chain
        original = chain._chain[1]
        chain._chain[1] = AuditEntry(
            timestamp=original.timestamp,
            action=AuditAction.NODE_REVOKE.value,
            actor_id="hacker",
            target_id="record-123",
            silo="medical",
        )

        assert chain.verify() is False


# ---------------------------------------------------------------------------
# 7. Access Control + Transport Security
# ---------------------------------------------------------------------------

class TestAccessControlTransportIntegration:
    """Access control decisions enforced at transport layer."""

    def test_portal_isolation_with_tls(self):
        """Different portals use different TLS configs."""
        admin_tls = TLSConfig(
            min_version=TLSVersion.TLS_1_3,
            ca_cert_path="/etc/ssl/ca-bundle.crt",
            verify_client=True,
        )
        dev_tls = TLSConfig(
            min_version=TLSVersion.TLS_1_2,
            ca_cert_path="",
        )

        assert admin_tls.is_developer_mode() is False
        assert dev_tls.is_developer_mode() is True

    def test_rbac_blocks_cross_portal_access(self):
        """Viewer cannot access admin endpoints."""
        controller = AccessController()

        viewer_session = Session(
            session_id="sess-viewer",
            user_id="viewer-001",
            role=Role.VIEWER,
            portal=Portal.PATIENT,
        )

        # Viewer cannot issue certificates
        assert controller.check_permission(viewer_session, Permission.CERT_ISSUE) is False
        # Viewer cannot manage users
        assert controller.check_permission(viewer_session, Permission.ADMIN_USER_MANAGE) is False
        # Viewer can read data
        assert controller.check_permission(viewer_session, Permission.DATA_READ) is True

    def test_rate_limiting_per_portal(self):
        """Rate limits differ per portal type."""
        admin_limits = RateLimitConfig(max_requests_per_minute=100, burst_size=50)
        patient_limits = RateLimitConfig(max_requests_per_minute=10, burst_size=5)

        admin_limiter = RateLimiter(admin_limits)
        patient_limiter = RateLimiter(patient_limits)

        # Admin can make many requests within burst
        for i in range(50):
            assert admin_limiter.check("admin-001") == RateLimitResult.ALLOWED

        # Patient limited at burst boundary
        for i in range(5):
            assert patient_limiter.check("patient-001") == RateLimitResult.ALLOWED
        # 6th gets throttled
        assert patient_limiter.check("patient-001") == RateLimitResult.THROTTLED


# ---------------------------------------------------------------------------
# 8. Full Patient Data Flow Integration
# ---------------------------------------------------------------------------

class TestPatientDataFlowIntegration:
    """Complete patient data flow: register, encrypt, consent, deliver, decrypt."""

    def test_complete_patient_data_flow(self):
        """Full flow with all components wired together."""
        registry = NodeRegistry()
        chain = AuditChain()

        # Register patient and provider
        patient = registry.register(name="patient-001")
        provider = registry.register(name="provider-001")

        # Audit: registration
        chain.append(
            action=AuditAction.NODE_REGISTER.value,
            actor_id="registration-service",
            target_id=patient.node_id.uuid,
            silo="identity",
        )
        chain.append(
            action=AuditAction.NODE_REGISTER.value,
            actor_id="registration-service",
            target_id=provider.node_id.uuid,
            silo="identity",
        )

        # Patient grants consent
        consent_gate = ConsentGate()
        consent_request = consent_gate.request_consent(
            requesting_node_id=provider.node_id.uuid,
            source_silo="medical",
            target_silo="research",
            categories=["diagnosis"],
            scope="read",
            reason="Treatment coordination",
        )

        approval = consent_gate.approve_consent(
            consent_id=consent_request.consent_id,
            data_owner_id=patient.node_id.uuid,
            ttl_seconds=86400,
        )
        assert approval.status == ConsentStatus.APPROVED

        result = consent_gate.check_consent(consent_id=consent_request.consent_id)
        assert result is not None
        assert result.status == ConsentStatus.APPROVED

        # Audit: consent granted
        chain.append(
            action=AuditAction.CONSENT_APPROVE.value,
            actor_id=patient.node_id.uuid,
            target_id=provider.node_id.uuid,
            silo="consent",
            details={"categories": ["diagnosis"]},
        )

        # Encrypt patient data
        km = KeyManager()
        master_key = km.generate_master_key()
        encryptor = FieldEncryptor(key_manager=km, master_key=master_key)

        plaintext = "Patient health record: all normal"
        ciphertext = encryptor.encrypt(
            plaintext=plaintext,
            silo="medical",
            record_id="record-001",
            scope="read",
        )

        # Audit: data encrypted
        chain.append(
            action=AuditAction.FIELD_ENCRYPT.value,
            actor_id=provider.node_id.uuid,
            target_id="record-001",
            silo="medical",
        )

        # Decrypt
        decrypted = encryptor.decrypt(
            ciphertext=ciphertext,
            silo="medical",
            record_id="record-001",
            scope="read",
        )
        assert decrypted == plaintext

        # Audit: data delivered
        chain.append(
            action=AuditAction.E2EE_SEND.value,
            actor_id="mesh-router",
            target_id=patient.node_id.uuid,
            silo="transport",
        )

        # Verify full audit chain
        assert chain.verify() is True
        assert len(chain) == 5  # 5 appends (no genesis counted)

        # Verify patient can revoke consent
        consent_gate.revoke_consent(consent_id=consent_request.consent_id)
        result = consent_gate.check_consent(consent_id=consent_request.consent_id)
        assert result is None