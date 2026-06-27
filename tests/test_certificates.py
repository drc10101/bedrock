"""Tests for Identity Fabric — Certificate Lifecycle (B-107)."""

import pytest
from datetime import datetime, timezone, timedelta

from bedrock.identity.certificates import (
    CertificateManager, Certificate, CertificateStatus,
    LicenseTier, LicenseExceededError, NODE_LIMITS,
)
from bedrock.identity.node import Node, NodeID, NodeState
from bedrock.identity.registration import NodeRegistry
from bedrock.identity.capabilities import DataCategory


class TestLicenseTier:
    """Test license tier configuration and node limits."""

    def test_developer_limit(self):
        assert NODE_LIMITS[LicenseTier.DEVELOPER] == 3

    def test_starter_limit(self):
        assert NODE_LIMITS[LicenseTier.STARTER] == 5

    def test_business_limit(self):
        assert NODE_LIMITS[LicenseTier.BUSINESS] == 25

    def test_enterprise_unlimited(self):
        assert NODE_LIMITS[LicenseTier.ENTERPRISE] == float("inf")


class TestCertificate:
    """Test Certificate dataclass."""

    def test_certificate_creation(self):
        now = datetime.now(timezone.utc)
        cert = Certificate(
            serial="bedrock-test-1",
            node_uuid="node-1",
            node_name="test-server",
            public_key_hash="abc123",
            capabilities=["identity", "medical"],
            issued_at=now,
            expires_at=now + timedelta(hours=24),
        )
        assert cert.serial == "bedrock-test-1"
        assert cert.node_uuid == "node-1"
        assert cert.status == CertificateStatus.ACTIVE
        assert cert.license_tier == LicenseTier.DEVELOPER

    def test_is_valid_active_cert(self):
        cert = Certificate(
            serial="bedrock-test-1",
            node_uuid="node-1",
            node_name="test-server",
            public_key_hash="abc123",
            capabilities=["read"],
            issued_at=datetime.now(timezone.utc) - timedelta(hours=1),
            expires_at=datetime.now(timezone.utc) + timedelta(hours=23),
        )
        assert cert.is_valid() is True

    def test_is_valid_expired_cert(self):
        cert = Certificate(
            serial="bedrock-test-1",
            node_uuid="node-1",
            node_name="test-server",
            public_key_hash="abc123",
            capabilities=["read"],
            issued_at=datetime.now(timezone.utc) - timedelta(hours=25),
            expires_at=datetime.now(timezone.utc) - timedelta(hours=1),
        )
        assert cert.is_valid() is False

    def test_is_valid_revoked_cert(self):
        cert = Certificate(
            serial="bedrock-test-1",
            node_uuid="node-1",
            node_name="test-server",
            public_key_hash="abc123",
            capabilities=["read"],
            status=CertificateStatus.REVOKED,
        )
        assert cert.is_valid() is False

    def test_is_valid_with_specific_time(self):
        now = datetime.now(timezone.utc)
        cert = Certificate(
            serial="bedrock-test-1",
            node_uuid="node-1",
            node_name="test-server",
            public_key_hash="abc123",
            capabilities=["read"],
            issued_at=now - timedelta(hours=1),
            expires_at=now + timedelta(hours=23),
        )
        # Valid at issuance time
        assert cert.is_valid(at=now) is True
        # Not valid 24 hours later
        assert cert.is_valid(at=now + timedelta(hours=25)) is False

    def test_days_until_expiry(self):
        cert = Certificate(
            serial="bedrock-test-1",
            node_uuid="node-1",
            node_name="test-server",
            public_key_hash="abc123",
            capabilities=["read"],
            issued_at=datetime.now(timezone.utc),
            expires_at=datetime.now(timezone.utc) + timedelta(hours=24),
        )
        days = cert.days_until_expiry()
        assert days is not None
        assert 0.9 < days < 1.1  # Approximately 1 day

    def test_needs_renewal(self):
        # Certificate with 3 hours left (within 4-hour window)
        cert_soon = Certificate(
            serial="bedrock-test-1",
            node_uuid="node-1",
            node_name="test-server",
            public_key_hash="abc123",
            capabilities=["read"],
            issued_at=datetime.now(timezone.utc) - timedelta(hours=21),
            expires_at=datetime.now(timezone.utc) + timedelta(hours=3),
        )
        assert cert_soon.needs_renewal() is True

        # Certificate with 10 hours left (outside window)
        cert_later = Certificate(
            serial="bedrock-test-2",
            node_uuid="node-2",
            node_name="test-server-2",
            public_key_hash="def456",
            capabilities=["read"],
            issued_at=datetime.now(timezone.utc) - timedelta(hours=14),
            expires_at=datetime.now(timezone.utc) + timedelta(hours=10),
        )
        assert cert_later.needs_renewal() is False


class TestCertificateManager:
    """Test certificate lifecycle: issue, renew, revoke, CRL."""

    def setup_method(self):
        self.manager = CertificateManager(license_tier=LicenseTier.BUSINESS)

    def _make_node(self, name="test-node"):
        """Helper: register a node and return its details."""
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        private_key = Ed25519PrivateKey.generate()
        public_key = private_key.public_key().public_bytes_raw()
        import hashlib
        pk_hash = hashlib.sha256(public_key).hexdigest()
        return {
            "uuid": f"node-{name}",
            "name": name,
            "public_key_hash": pk_hash,
        }

    def test_issue_certificate(self):
        node = self._make_node("server-01")
        cert = self.manager.issue_certificate(
            node_uuid=node["uuid"],
            node_name=node["name"],
            public_key_hash=node["public_key_hash"],
            capabilities=["identity", "medical"],
        )
        assert cert.serial.startswith("bedrock-")
        assert cert.node_uuid == node["uuid"]
        assert cert.node_name == "server-01"
        assert cert.status == CertificateStatus.ACTIVE
        assert cert.capabilities == ["identity", "medical"]
        assert cert.issuer == "bedrock-ca"

    def test_issue_certificate_developer_mode(self):
        dev_manager = CertificateManager(license_tier=LicenseTier.DEVELOPER)
        node = self._make_node("dev-node")
        cert = dev_manager.issue_certificate(
            node_uuid=node["uuid"],
            node_name=node["name"],
            public_key_hash=node["public_key_hash"],
        )
        assert cert.issuer == "bedrock-self-signed"
        assert cert.license_tier == LicenseTier.DEVELOPER

    def test_issue_custom_ttl(self):
        node = self._make_node("short-lived")
        cert = self.manager.issue_certificate(
            node_uuid=node["uuid"],
            node_name=node["name"],
            public_key_hash=node["public_key_hash"],
            ttl_hours=4,
        )
        # Should expire in approximately 4 hours
        days = cert.days_until_expiry()
        assert days is not None
        assert 0.1 < days < 0.2  # ~4-5 hours = 0.17 days

    def test_renew_certificate(self):
        node = self._make_node("server-01")
        original = self.manager.issue_certificate(
            node_uuid=node["uuid"],
            node_name=node["name"],
            public_key_hash=node["public_key_hash"],
            capabilities=["identity", "transaction"],
        )

        renewed = self.manager.renew_certificate(node["uuid"])

        # New certificate has different serial
        assert renewed.serial != original.serial
        # Same capabilities
        assert renewed.capabilities == original.capabilities
        # Same node
        assert renewed.node_uuid == original.node_uuid
        # Old cert is pending renewal
        assert original.status == CertificateStatus.PENDING_RENEWAL
        # New cert is active
        assert renewed.status == CertificateStatus.ACTIVE

    def test_renew_nonexistent_certificate(self):
        with pytest.raises(KeyError, match="No certificate found"):
            self.manager.renew_certificate("nonexistent-node")

    def test_revoke_certificate(self):
        node = self._make_node("compromised-node")
        cert = self.manager.issue_certificate(
            node_uuid=node["uuid"],
            node_name=node["name"],
            public_key_hash=node["public_key_hash"],
        )

        revoked = self.manager.revoke_certificate(
            node["uuid"], reason="attestation failure — firmware tampered"
        )

        assert revoked.status == CertificateStatus.REVOKED
        assert revoked.revoked_at is not None
        assert "firmware tampered" in revoked.revocation_reason
        assert self.manager.check_crl(cert.serial) is True

    def test_revoke_nonexistent_certificate(self):
        with pytest.raises(KeyError, match="No certificate found"):
            self.manager.revoke_certificate("nonexistent", reason="test")

    def test_crl_distribution(self):
        """CRL accumulates revoked serial numbers."""
        nodes = [self._make_node(f"node-{i}") for i in range(3)]
        certs = []
        for node in nodes:
            cert = self.manager.issue_certificate(
                node_uuid=node["uuid"],
                node_name=node["name"],
                public_key_hash=node["public_key_hash"],
            )
            certs.append(cert)

        # Revoke first two
        self.manager.revoke_certificate(nodes[0]["uuid"], reason="compromised")
        self.manager.revoke_certificate(nodes[1]["uuid"], reason="failed attestation")

        crl = self.manager.get_crl()
        assert len(crl) == 2
        assert certs[0].serial in crl
        assert certs[1].serial in crl
        assert certs[2].serial not in crl  # Third node is still active

    def test_get_certificate_by_serial(self):
        node = self._make_node("server-01")
        cert = self.manager.issue_certificate(
            node_uuid=node["uuid"],
            node_name=node["name"],
            public_key_hash=node["public_key_hash"],
        )
        found = self.manager.get_certificate(cert.serial)
        assert found is cert

    def test_get_node_certificate(self):
        node = self._make_node("server-01")
        cert = self.manager.issue_certificate(
            node_uuid=node["uuid"],
            node_name=node["name"],
            public_key_hash=node["public_key_hash"],
        )
        found = self.manager.get_node_certificate(node["uuid"])
        assert found is cert

    def test_list_certificates_by_status(self):
        nodes = [self._make_node(f"node-{i}") for i in range(3)]
        certs = []
        for node in nodes:
            cert = self.manager.issue_certificate(
                node_uuid=node["uuid"],
                node_name=node["name"],
                public_key_hash=node["public_key_hash"],
            )
            certs.append(cert)

        self.manager.revoke_certificate(nodes[0]["uuid"], reason="test")

        active = self.manager.list_certificates(status=CertificateStatus.ACTIVE)
        revoked = self.manager.list_certificates(status=CertificateStatus.REVOKED)
        assert len(active) == 2
        assert len(revoked) == 1


class TestLicenseEnforcement:
    """Test that certificate issuance respects license limits."""

    def test_developer_limit_3_nodes(self):
        manager = CertificateManager(license_tier=LicenseTier.DEVELOPER)
        for i in range(3):
            manager.issue_certificate(
                node_uuid=f"dev-node-{i}",
                node_name=f"dev-node-{i}",
                public_key_hash=f"hash-{i}",
            )
        # 4th node should fail
        with pytest.raises(LicenseExceededError, match="License limit reached"):
            manager.issue_certificate(
                node_uuid="dev-node-3",
                node_name="dev-node-3",
                public_key_hash="hash-3",
            )

    def test_starter_limit_5_nodes(self):
        manager = CertificateManager(license_tier=LicenseTier.STARTER)
        for i in range(5):
            manager.issue_certificate(
                node_uuid=f"starter-node-{i}",
                node_name=f"starter-node-{i}",
                public_key_hash=f"hash-{i}",
            )
        with pytest.raises(LicenseExceededError):
            manager.issue_certificate(
                node_uuid="starter-node-5",
                node_name="starter-node-5",
                public_key_hash="hash-5",
            )

    def test_business_limit_25_nodes(self):
        manager = CertificateManager(license_tier=LicenseTier.BUSINESS)
        for i in range(25):
            manager.issue_certificate(
                node_uuid=f"biz-node-{i}",
                node_name=f"biz-node-{i}",
                public_key_hash=f"hash-{i}",
            )
        with pytest.raises(LicenseExceededError):
            manager.issue_certificate(
                node_uuid="biz-node-25",
                node_name="biz-node-25",
                public_key_hash="hash-25",
            )

    def test_enterprise_no_limit(self):
        manager = CertificateManager(license_tier=LicenseTier.ENTERPRISE)
        # Issue 30 certificates — should all succeed
        for i in range(30):
            manager.issue_certificate(
                node_uuid=f"ent-node-{i}",
                node_name=f"ent-node-{i}",
                public_key_hash=f"hash-{i}",
            )
        assert len(manager.list_certificates()) == 30

    def test_revoked_cert_frees_license_slot(self):
        """Revoking a certificate frees up a license slot."""
        manager = CertificateManager(license_tier=LicenseTier.DEVELOPER)
        for i in range(3):
            manager.issue_certificate(
                node_uuid=f"dev-node-{i}",
                node_name=f"dev-node-{i}",
                public_key_hash=f"hash-{i}",
            )
        # Should be at limit
        with pytest.raises(LicenseExceededError):
            manager.issue_certificate(
                node_uuid="dev-node-3",
                node_name="dev-node-3",
                public_key_hash="hash-3",
            )

        # Revoke one
        manager.revoke_certificate("dev-node-0", reason="compromised")

        # Now we can issue again
        cert = manager.issue_certificate(
            node_uuid="dev-node-3",
            node_name="dev-node-3",
            public_key_hash="hash-3",
        )
        assert cert.status == CertificateStatus.ACTIVE

    def test_check_license_limit(self):
        manager = CertificateManager(license_tier=LicenseTier.DEVELOPER)
        assert manager.check_license_limit() is True  # 0/3

        for i in range(2):
            manager.issue_certificate(
                node_uuid=f"dev-node-{i}",
                node_name=f"dev-node-{i}",
                public_key_hash=f"hash-{i}",
            )
        assert manager.check_license_limit() is True  # 2/3

        manager.issue_certificate(
            node_uuid="dev-node-2",
            node_name="dev-node-2",
            public_key_hash="hash-2",
        )
        assert manager.check_license_limit() is False  # 3/3 — at limit

    def test_cannot_renew_revoked_certificate(self):
        manager = CertificateManager(license_tier=LicenseTier.BUSINESS)
        manager.issue_certificate(
            node_uuid="compromised-node",
            node_name="compromised-node",
            public_key_hash="hash-1",
        )
        manager.revoke_certificate("compromised-node", reason="hacked")

        with pytest.raises(ValueError, match="Cannot renew revoked"):
            manager.renew_certificate("compromised-node")


class TestCertificateLifecycleIntegration:
    """Integration: certificate lifecycle + node registration + attestation."""

    def test_full_lifecycle(self):
        """Register → Attest → Issue Cert → Active → Revoke → Quarantine."""
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from bedrock.identity.attestation import (
            AttestationManager, AttestationClaim, AttestationPolicy, compute_state_hash,
        )
        import hashlib

        # Setup
        registry = NodeRegistry()
        cert_mgr = CertificateManager(license_tier=LicenseTier.BUSINESS)
        attest_mgr = AttestationManager(policy=AttestationPolicy.STRICT)

        # 1. Register node
        pk = Ed25519PrivateKey.generate()
        node = registry.register(name="warehouse-sensor-01", node_type="iot", private_key=pk)

        # 2. Register attestation baseline
        good_hash = compute_state_hash(b"firmware-v2", b"os-v6", b"config-prod")
        attest_mgr.register_baseline("iot", "v2.1.0", good_hash)
        attest_mgr.register_public_key(node.node_id.uuid, node.node_id.public_key)

        # 3. Attest
        claim = AttestationClaim(
            node_uuid=node.node_id.uuid,
            state_hash=good_hash,
            components=["firmware", "os", "config"],
        )
        claim.sign(pk)
        result = attest_mgr.verify_attestation(claim, node_type="iot")
        assert result.status.value == "passed"

        # 4. Issue certificate
        pk_hash = hashlib.sha256(node.node_id.public_key).hexdigest()
        cert = cert_mgr.issue_certificate(
            node_uuid=node.node_id.uuid,
            node_name=node.name,
            public_key_hash=pk_hash,
            capabilities=["identity", "medical"],
        )
        assert cert.is_valid()
        assert cert.capabilities == ["identity", "medical"]

        # 5. Node is active
        assert node.state == NodeState.ACTIVE
        assert node.can_route()
        assert node.can_decrypt()

        # 6. Compromise detected — revoke certificate and quarantine
        cert_mgr.revoke_certificate(node.node_id.uuid, reason="firmware tampered")
        registry.transition(node.node_id.uuid, NodeState.SUSPECT, reason="attestation failed")
        registry.transition(node.node_id.uuid, NodeState.QUARANTINED, reason="attestation failed")

        # 7. Verify quarantine
        node = registry.get(node.node_id.uuid)
        assert node.state == NodeState.QUARANTINED
        assert not node.can_route()
        assert not node.can_decrypt()

        # 8. Verify cert is revoked
        cert = cert_mgr.get_node_certificate(node.node_id.uuid)
        assert cert.status == CertificateStatus.REVOKED
        assert cert_mgr.check_crl(cert.serial) is True