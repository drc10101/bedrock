"""
Mesh integration tests — Self-Healing Mesh wired into Bedrock subsystems.

Tests that when nodes are quarantined/revoked/healed:
- Certificates are revoked/re-issued
- Audit events are logged
- Access is blocked/restored
- Encryption keys are marked compromised
- Routes are recalculated
- Full lifecycle flows work end-to-end
"""

from bedrock.identity.node import Node, NodeState
from bedrock.identity.registration import NodeRegistry
from bedrock.identity.capabilities import CapabilityScope, DataCategory
from bedrock.identity.certificates import CertificateManager
from bedrock.audit.chain import AuditChain, AuditEntry
from bedrock.key_management.keys import KeyManager
from bedrock.mesh.healing import SelfHealingMesh
from bedrock.mesh.detector import SignalType
from bedrock.mesh.integration import MeshIntegrator, MeshEvent

import pytest


class TestMeshIntegratorQuarantine:
    """Test quarantine integration with Bedrock subsystems."""

    def setup_method(self):
        self.mesh = SelfHealingMesh(consensus_threshold=2)
        self.reg = NodeRegistry()
        self.cert_manager = CertificateManager(license_tier="enterprise")
        self.audit_chain = AuditChain()
        self.integrator = MeshIntegrator(
            mesh=self.mesh,
            cert_manager=self.cert_manager,
            audit_chain=self.audit_chain,
        )

        # Register 4 nodes in a mesh topology
        self.nodes = []
        for i in range(4):
            node = self.reg.register(name=f"node-{i}", node_type="provider")
            self.mesh.register_node(node)
            self.nodes.append(node)

        # Create a mesh topology: 0-1-2-3 (linear)
        for i in range(3):
            self.mesh.add_neighbor(self.nodes[i].node_id.uuid, self.nodes[i+1].node_id.uuid)

    def test_quarantine_revokes_certificate(self):
        """Quarantining a node revokes its certificate."""
        target_id = self.nodes[1].node_id.uuid

        # Issue a certificate for the target first
        self.cert_manager.issue_certificate(
            node_uuid=target_id,
            node_name=self.nodes[1].name,
            public_key_hash=self.nodes[1].node_id.public_key_hex(),
        )

        # Flag from 2 independent sources -> quarantine
        self.mesh.flag_node(self.nodes[0].node_id.uuid, target_id, SignalType.LATERAL_MOVEMENT)
        self.mesh.flag_node(self.nodes[2].node_id.uuid, target_id, SignalType.LATERAL_MOVEMENT)

        # Process through integrator
        event = self.integrator.on_quarantine(target_id, reason="Lateral movement detected")

        assert "certificate_revoked" in event.actions_taken
        assert event.event_type == "node_quarantined"
        assert event.new_state == NodeState.QUARANTINED

    def test_quarantine_logs_audit_event(self):
        """Quarantining a node logs an audit event."""
        target_id = self.nodes[1].node_id.uuid

        event = self.integrator.on_quarantine(target_id, reason="Credential stuffing")

        assert "audit_logged" in event.actions_taken
        # Verify audit chain has the entry
        entries = self.audit_chain.query(target_id=target_id)
        assert any(e.action == "node_quarantined" for e in entries)

    def test_quarantine_tracks_blocked_node(self):
        """Quarantined nodes are tracked as blocked."""
        target_id = self.nodes[1].node_id.uuid

        self.integrator.on_quarantine(target_id)

        assert self.integrator.is_node_blocked(target_id)
        assert target_id in self.integrator.get_blocked_nodes()

    def test_quarantine_without_subsystems(self):
        """Quarantine works even without certificate/audit subsystems."""
        mesh = SelfHealingMesh()
        integrator = MeshIntegrator(mesh=mesh)  # No cert_manager, no audit_chain

        node = self.reg.register(name="solo-node", node_type="provider")
        mesh.register_node(node)

        event = integrator.on_quarantine(node.node_id.uuid, reason="Test")

        assert event.event_type == "node_quarantined"
        assert "node_tracked" in event.actions_taken


class TestMeshIntegratorRevocation:
    """Test permanent revocation integration."""

    def setup_method(self):
        self.mesh = SelfHealingMesh()
        self.reg = NodeRegistry()
        self.cert_manager = CertificateManager(license_tier="enterprise")
        self.audit_chain = AuditChain()
        self.key_manager = KeyManager()
        self.integrator = MeshIntegrator(
            mesh=self.mesh,
            cert_manager=self.cert_manager,
            audit_chain=self.audit_chain,
            key_manager=self.key_manager,
        )

        self.nodes = []
        for i in range(3):
            node = self.reg.register(name=f"node-{i}", node_type="provider")
            self.mesh.register_node(node)
            self.nodes.append(node)

    def test_revocation_revokes_certificate(self):
        """Revoking a node revokes its certificate."""
        target_id = self.nodes[0].node_id.uuid

        # Issue certificate first so revocation succeeds
        self.cert_manager.issue_certificate(
            node_uuid=target_id,
            node_name=self.nodes[0].name,
            public_key_hash=self.nodes[0].node_id.public_key_hex(),
        )

        event = self.integrator.on_revoke(target_id, reason="Confirmed malicious")

        assert "certificate_revoked" in event.actions_taken
        assert event.event_type == "node_revoked"
        assert event.new_state == NodeState.REVOKED

    def test_revocation_marks_keys_compromised(self):
        """Revoking a node marks its encryption keys as compromised."""
        target_id = self.nodes[0].node_id.uuid

        event = self.integrator.on_revoke(target_id, reason="Confirmed breach")

        assert "keys_marked_compromised" in event.actions_taken

    def test_revocation_logs_audit(self):
        """Revoking a node logs an audit event."""
        target_id = self.nodes[0].node_id.uuid

        event = self.integrator.on_revoke(target_id)

        assert "audit_logged" in event.actions_taken
        entries = self.audit_chain.query(target_id=target_id)
        assert any(e.action == "node_revoked" for e in entries)

    def test_revoked_node_permanently_blocked(self):
        """Revoked nodes are permanently blocked."""
        target_id = self.nodes[0].node_id.uuid

        self.integrator.on_revoke(target_id)

        assert self.integrator.is_node_blocked(target_id)
        assert self.integrator.is_node_revoked(target_id)

    def test_revoked_node_not_in_quarantined(self):
        """Revoked nodes are tracked separately from quarantined."""
        target_id = self.nodes[0].node_id.uuid

        # First quarantine, then revoke
        self.integrator.on_quarantine(target_id)
        assert target_id in self.integrator._quarantined_nodes

        self.integrator.on_revoke(target_id)
        assert target_id not in self.integrator._quarantined_nodes
        assert target_id in self.integrator._revoked_nodes


class TestMeshIntegratorHealing:
    """Test healing integration with Bedrock subsystems."""

    def setup_method(self):
        self.mesh = SelfHealingMesh(healing_period_seconds=0)  # Instant healing for tests
        self.reg = NodeRegistry()
        self.cert_manager = CertificateManager(license_tier="enterprise")
        self.audit_chain = AuditChain()
        self.integrator = MeshIntegrator(
            mesh=self.mesh,
            cert_manager=self.cert_manager,
            audit_chain=self.audit_chain,
        )

        self.nodes = []
        for i in range(3):
            node = self.reg.register(name=f"node-{i}", node_type="provider")
            self.mesh.register_node(node)
            self.nodes.append(node)

    def test_healing_re_issues_certificate(self):
        """Healed nodes get a new certificate."""
        target_id = self.nodes[0].node_id.uuid

        # Quarantine first
        self.integrator.on_quarantine(target_id)

        # Begin healing through the mesh
        self.mesh.begin_healing(target_id)

        # Complete healing through integrator
        event = self.integrator.on_healing_complete(target_id)

        assert "certificate_issued" in event.actions_taken
        assert event.event_type == "node_healed"
        assert event.new_state == NodeState.ACTIVE

    def test_healing_logs_audit(self):
        """Healed nodes have an audit event logged."""
        target_id = self.nodes[0].node_id.uuid

        self.integrator.on_quarantine(target_id)
        self.mesh.begin_healing(target_id)

        event = self.integrator.on_healing_complete(target_id)

        assert "audit_logged" in event.actions_taken
        entries = self.audit_chain.query(target_id=target_id)
        assert any(e.action == "node_healed" for e in entries)

    def test_healing_untracks_blocked_node(self):
        """Healed nodes are removed from the blocked list."""
        target_id = self.nodes[0].node_id.uuid

        self.integrator.on_quarantine(target_id)
        assert self.integrator.is_node_blocked(target_id)

        self.mesh.begin_healing(target_id)
        self.integrator.on_healing_complete(target_id)

        assert not self.integrator.is_node_blocked(target_id)

    def test_healing_full_lifecycle(self):
        """Full lifecycle: flag -> quarantine -> heal -> restore."""
        target_id = self.nodes[0].node_id.uuid

        # Phase 1: Flag and quarantine (requires two process_flags calls:
        # first ACTIVE->SUSPECT, then SUSPECT->QUARANTINED)
        self.mesh.flag_node(self.nodes[1].node_id.uuid, target_id, SignalType.CREDENTIAL_STUFFING)
        self.mesh.flag_node(self.nodes[2].node_id.uuid, target_id, SignalType.CREDENTIAL_STUFFING)

        self.mesh.process_flags()  # ACTIVE -> SUSPECT
        self.mesh.process_flags()  # SUSPECT -> QUARANTINED

        # Integrate the quarantine
        event = self.integrator.on_quarantine(target_id)
        assert event.event_type == "node_quarantined"
        assert self.integrator.is_node_blocked(target_id)

        # Phase 2: Heal (node is QUARANTINED, process_full_healing handles begin + complete)
        events = self.integrator.process_full_healing(target_id)
        assert len(events) >= 1
        assert events[0].event_type == "node_healed"
        assert not self.integrator.is_node_blocked(target_id)


class TestMeshIntegratorFullFlow:
    """End-to-end mesh integration flows."""

    def setup_method(self):
        self.mesh = SelfHealingMesh(consensus_threshold=2, healing_period_seconds=0)
        self.reg = NodeRegistry()
        self.cert_manager = CertificateManager(license_tier="enterprise")
        self.audit_chain = AuditChain()
        self.integrator = MeshIntegrator(
            mesh=self.mesh,
            cert_manager=self.cert_manager,
            audit_chain=self.audit_chain,
        )

        # 5-node mesh topology: 0-1-2-3-4 (linear)
        self.nodes = []
        for i in range(5):
            node = self.reg.register(name=f"node-{i}", node_type="provider")
            self.mesh.register_node(node)
            self.nodes.append(node)

        for i in range(4):
            self.mesh.add_neighbor(self.nodes[i].node_id.uuid, self.nodes[i+1].node_id.uuid)

    def test_attack_detection_to_quarantine(self):
        """Attack detected -> flags raised -> consensus -> quarantine -> integration."""
        target_id = self.nodes[2].node_id.uuid

        # Two independent nodes flag the target
        self.mesh.flag_node(self.nodes[0].node_id.uuid, target_id, SignalType.LATERAL_MOVEMENT)
        self.mesh.flag_node(self.nodes[1].node_id.uuid, target_id, SignalType.CREDENTIAL_STUFFING)

        # Process through integrator
        events = self.integrator.process_full_quarantine(target_id)

        assert len(events) == 1
        event = events[0]
        assert event.node_id == target_id
        assert "audit_logged" in event.actions_taken

        # Node is blocked
        assert self.integrator.is_node_blocked(target_id)

    def test_revocation_permanent(self):
        """Full revocation flow — node can never be restored."""
        target_id = self.nodes[2].node_id.uuid

        events = self.integrator.process_full_revocation(target_id, reason="Confirmed breach")

        assert len(events) == 1
        assert events[0].event_type == "node_revoked"
        assert self.integrator.is_node_revoked(target_id)
        assert self.integrator.is_node_blocked(target_id)

        # REVOKED is terminal — no healing possible
        node = self.mesh.get_node(target_id)
        assert node.state == NodeState.REVOKED

    def test_multiple_attack_vectors(self):
        """Node flagged for multiple attack types triggers quarantine."""
        target_id = self.nodes[3].node_id.uuid

        # Flag from different sources for different reasons
        self.mesh.flag_node(self.nodes[0].node_id.uuid, target_id, SignalType.UNUSUAL_VOLUME)
        self.mesh.flag_node(self.nodes[1].node_id.uuid, target_id, SignalType.CERTIFICATE_ANOMALY)

        # Consensus reached (2 flags from different sources)
        assert self.mesh.check_consensus(target_id)

        events = self.integrator.process_full_quarantine(target_id)
        assert len(events) == 1
        assert events[0].new_state == NodeState.QUARANTINED

    def test_event_history_tracked(self):
        """All integration events are tracked and retrievable."""
        target_id = self.nodes[0].node_id.uuid

        # Quarantine
        self.integrator.on_quarantine(target_id, reason="Test quarantine")
        # Revoke
        self.integrator.on_revoke(target_id, reason="Test revocation")

        # Get all events for this node
        events = self.integrator.get_events(node_id=target_id)
        assert len(events) == 2
        assert events[0].event_type == "node_quarantined"
        assert events[1].event_type == "node_revoked"

    def test_get_all_events(self):
        """Get all events across all nodes."""
        target1 = self.nodes[0].node_id.uuid
        target2 = self.nodes[1].node_id.uuid

        self.integrator.on_quarantine(target1)
        self.integrator.on_revoke(target2)

        all_events = self.integrator.get_events()
        assert len(all_events) == 2

    def test_mesh_event_serialization(self):
        """MeshEvent can be serialized to dict."""
        target_id = self.nodes[0].node_id.uuid
        event = self.integrator.on_quarantine(target_id, reason="Test")

        d = event.to_dict()
        assert "event_type" in d
        assert "node_id" in d
        assert "old_state" in d
        assert "new_state" in d
        assert "actions_taken" in d
        assert "timestamp" in d
        assert d["new_state"] == "quarantined"


class TestMeshIntegratorAccessControl:
    """Test that mesh integration blocks access for isolated nodes."""

    def setup_method(self):
        self.mesh = SelfHealingMesh()
        self.reg = NodeRegistry()
        self.integrator = MeshIntegrator(mesh=self.mesh)

        self.node_active = self.reg.register(name="active-node", node_type="provider")
        self.node_suspicious = self.reg.register(name="suspect-node", node_type="provider")
        self.mesh.register_node(self.node_active)
        self.mesh.register_node(self.node_suspicious)

    def test_active_node_not_blocked(self):
        """Active nodes are not blocked."""
        assert not self.integrator.is_node_blocked(self.node_active.node_id.uuid)

    def test_quarantined_node_blocked(self):
        """Quarantined nodes are blocked from all access."""
        target_id = self.node_suspicious.node_id.uuid
        self.integrator.on_quarantine(target_id)

        assert self.integrator.is_node_blocked(target_id)
        assert not self.integrator.is_node_blocked(self.node_active.node_id.uuid)

    def test_revoked_node_blocked(self):
        """Revoked nodes are permanently blocked."""
        target_id = self.node_suspicious.node_id.uuid
        self.integrator.on_revoke(target_id)

        assert self.integrator.is_node_blocked(target_id)
        assert self.integrator.is_node_revoked(target_id)

    def test_healed_node_unblocked(self):
        """Healed nodes are removed from blocked list."""
        target_id = self.node_suspicious.node_id.uuid

        self.integrator.on_quarantine(target_id)
        assert self.integrator.is_node_blocked(target_id)

        # Heal through mesh + integrator
        self.mesh.begin_healing(target_id)
        self.mesh.complete_healing(target_id)
        self.integrator.on_healing_complete(target_id)

        assert not self.integrator.is_node_blocked(target_id)