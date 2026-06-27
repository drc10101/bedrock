"""Tests for Self-Healing Mesh (B-111)."""

import pytest
from datetime import datetime, timezone, timedelta

from bedrock.identity.node import Node, NodeID, NodeState
from bedrock.identity.capabilities import CapabilityScope, DataCategory
from bedrock.mesh.detector import AttackDetector, DetectionSignal, SignalType
from bedrock.mesh.state_machine import MeshStateMachine, TransitionRecord
from bedrock.mesh.router import MeshRouter
from bedrock.mesh.healing import SelfHealingMesh, HealingResult


# ── State Machine Tests ──────────────────────────────────────────────


class TestMeshStateMachine:
    """Test node state transitions."""

    def setup_method(self):
        self.sm = MeshStateMachine()

    def _make_node(self, node_id: str = "node-001",
                   state: NodeState = NodeState.ACTIVE) -> Node:
        return Node(node_id=NodeID.generate(), name=node_id, state=state)

    def test_active_to_suspect(self):
        node = self._make_node()
        result = self.sm.transition(node, NodeState.SUSPECT, reason="Flagged by neighbor")
        assert result.state == NodeState.SUSPECT

    def test_suspect_to_quarantined(self):
        node = self._make_node(state=NodeState.SUSPECT)
        result = self.sm.transition(node, NodeState.QUARANTINED, reason="Consensus reached")
        assert result.state == NodeState.QUARANTINED

    def test_suspect_to_active(self):
        """False alarm: flag cleared."""
        node = self._make_node(state=NodeState.SUSPECT)
        result = self.sm.transition(node, NodeState.ACTIVE, reason="False alarm cleared")
        assert result.state == NodeState.ACTIVE

    def test_quarantined_to_healing(self):
        node = self._make_node(state=NodeState.QUARANTINED)
        result = self.sm.transition(node, NodeState.HEALING, reason="Re-attestation passed")
        assert result.state == NodeState.HEALING

    def test_healing_to_active(self):
        node = self._make_node(state=NodeState.HEALING)
        result = self.sm.transition(node, NodeState.ACTIVE, reason="Healing complete")
        assert result.state == NodeState.ACTIVE

    def test_healing_to_quarantined(self):
        """New flag during healing sends node back to quarantine."""
        node = self._make_node(state=NodeState.HEALING)
        result = self.sm.transition(node, NodeState.QUARANTINED, reason="New flag during healing")
        assert result.state == NodeState.QUARANTINED

    def test_quarantined_to_revoked(self):
        node = self._make_node(state=NodeState.QUARANTINED)
        result = self.sm.transition(node, NodeState.REVOKED, reason="Confirmed malicious")
        assert result.state == NodeState.REVOKED

    def test_active_to_revoked(self):
        """Admin can revoke from any state."""
        node = self._make_node(state=NodeState.ACTIVE)
        result = self.sm.transition(node, NodeState.REVOKED, reason="Admin decision")
        assert result.state == NodeState.REVOKED

    def test_revoked_is_terminal(self):
        """REVOKED has no valid transitions."""
        node = self._make_node(state=NodeState.REVOKED)
        with pytest.raises(ValueError, match="Invalid transition"):
            self.sm.transition(node, NodeState.ACTIVE)

    def test_invalid_active_to_healing(self):
        """Cannot skip SUSPECT and QUARANTINED."""
        node = self._make_node(state=NodeState.ACTIVE)
        with pytest.raises(ValueError, match="Invalid transition"):
            self.sm.transition(node, NodeState.HEALING)

    def test_invalid_quarantined_to_active(self):
        """Cannot go directly from QUARANTINED to ACTIVE."""
        node = self._make_node(state=NodeState.QUARANTINED)
        with pytest.raises(ValueError, match="Invalid transition"):
            self.sm.transition(node, NodeState.ACTIVE)

    def test_can_transition(self):
        node = self._make_node()
        assert self.sm.can_transition(node, NodeState.SUSPECT) is True
        assert self.sm.can_transition(node, NodeState.QUARANTINED) is False

    def test_transition_history(self):
        node = self._make_node()
        self.sm.transition(node, NodeState.SUSPECT, reason="Flagged")
        self.sm.transition(node, NodeState.QUARANTINED, reason="Consensus")

        history = self.sm.get_transition_history(node.node_id)
        assert len(history) == 2
        assert history[0].from_state == NodeState.ACTIVE
        assert history[0].to_state == NodeState.SUSPECT
        assert history[1].from_state == NodeState.SUSPECT
        assert history[1].to_state == NodeState.QUARANTINED

    def test_last_transition(self):
        node = self._make_node()
        self.sm.transition(node, NodeState.SUSPECT, reason="Flagged")
        self.sm.transition(node, NodeState.QUARANTINED, reason="Consensus")

        last = self.sm.get_last_transition(node.node_id)
        assert last.to_state == NodeState.QUARANTINED

    def test_can_promote_to_active(self):
        """Healing node can be promoted after period elapses."""
        node = self._make_node(state=NodeState.QUARANTINED)
        self.sm.transition(node, NodeState.HEALING, reason="Re-attestation")
        # With 0 healing period, should be promotable
        assert self.sm.can_promote_to_active(node, healing_period_seconds=0) is True

    def test_cannot_promote_non_healing(self):
        node = self._make_node(state=NodeState.ACTIVE)
        assert self.sm.can_promote_to_active(node) is False

    def test_full_lifecycle(self):
        """ACTIVE → SUSPECT → QUARANTINED → HEALING → ACTIVE"""
        node = self._make_node()
        self.sm.transition(node, NodeState.SUSPECT, reason="Flag 1")
        self.sm.transition(node, NodeState.QUARANTINED, reason="Consensus")
        self.sm.transition(node, NodeState.HEALING, reason="Re-attestation")
        self.sm.transition(node, NodeState.ACTIVE, reason="Healed")

        assert node.state == NodeState.ACTIVE
        history = self.sm.get_transition_history(node.node_id)
        assert len(history) == 4


# ── Attack Detector Tests ────────────────────────────────────────────


class TestAttackDetector:
    """Test distributed attack detection."""

    def test_detect_signal(self):
        detector = AttackDetector(node_id="node-001")
        signal = detector.detect(
            SignalType.CREDENTIAL_STUFFING,
            target_node_id="node-002",
            details={"attempts": 10, "window_seconds": 60},
        )
        assert signal.signal_type == SignalType.CREDENTIAL_STUFFING
        assert signal.source_node_id == "node-001"
        assert signal.target_node_id == "node-002"
        assert signal.details["attempts"] == 10

    def test_get_flags_for_node(self):
        detector = AttackDetector(node_id="node-001")
        detector.detect(SignalType.SILENT_NODE, "node-002")
        detector.detect(SignalType.CREDENTIAL_STUFFING, "node-003")
        detector.detect(SignalType.UNUSUAL_VOLUME, "node-002")

        flags = detector.get_flags_for_node("node-002")
        assert len(flags) == 2
        assert all(f.target_node_id == "node-002" for f in flags)

    def test_should_isolate_with_consensus(self):
        """≥2 unique flaggers = isolate."""
        det1 = AttackDetector(node_id="node-001")
        det2 = AttackDetector(node_id="node-002")

        det1.detect(SignalType.CREDENTIAL_STUFFING, "node-003")
        det2.detect(SignalType.CREDENTIAL_STUFFING, "node-003")

        # Check from each detector's perspective
        # (In the mesh, signals from all detectors are collected)
        all_signals = det1.get_all_signals() + det2.get_all_signals()
        unique_flaggers = {s.source_node_id for s in all_signals if s.target_node_id == "node-003"}
        assert len(unique_flaggers) >= 2

    def test_should_not_isolate_single_flag(self):
        """1 flagger = alert only, not isolate."""
        detector = AttackDetector(node_id="node-001")
        detector.detect(SignalType.CREDENTIAL_STUFFING, "node-002")

        # Single source
        signals = detector.get_flags_for_node("node-002")
        unique_flaggers = {s.source_node_id for s in signals}
        assert len(unique_flaggers) < 2

    def test_clear_signals(self):
        detector = AttackDetector(node_id="node-001")
        detector.detect(SignalType.CREDENTIAL_STUFFING, "node-002")
        detector.detect(SignalType.SILENT_NODE, "node-003")

        cleared = detector.clear_signals("node-002")
        assert cleared == 1
        assert len(detector.get_all_signals()) == 1

    def test_clear_all_signals(self):
        detector = AttackDetector(node_id="node-001")
        detector.detect(SignalType.CREDENTIAL_STUFFING, "node-002")
        detector.detect(SignalType.SILENT_NODE, "node-003")

        cleared = detector.clear_signals()
        assert cleared == 2
        assert len(detector.get_all_signals()) == 0

    def test_signal_types(self):
        """All signal types are defined."""
        expected = [
            "CREDENTIAL_STUFFING", "LATERAL_MOVEMENT", "UNUSUAL_VOLUME",
            "ATTESTATION_FAILURE", "PATH_ANOMALY", "CERTIFICATE_ANOMALY",
            "AAD_MISMATCH", "SILENT_NODE",
        ]
        names = [st.name for st in SignalType]
        for name in expected:
            assert name in names

    def test_default_thresholds(self):
        detector = AttackDetector(node_id="node-001")
        assert SignalType.CREDENTIAL_STUFFING in detector.thresholds
        assert detector.thresholds[SignalType.SILENT_NODE]["timeout_seconds"] == 300


# ── Router Tests ──────────────────────────────────────────────────────


class TestMeshRouter:
    """Test capability-scoped routing."""

    def setup_method(self):
        self.router = MeshRouter()

    def _make_scope(self, node_id: str, categories: list) -> CapabilityScope:
        return CapabilityScope(node_id=node_id, categories=categories)

    def _make_nodes(self) -> dict:
        """Create a simple 5-node mesh: A-B-C-D-E"""
        nodes = {}
        for nid in ["A", "B", "C", "D", "E"]:
            nodes[nid] = Node(node_id=NodeID.generate(), name=nid, state=NodeState.ACTIVE)
        return nodes

    def test_register_neighbor_bidirectional(self):
        self.router.register_neighbor("A", "B")
        assert "B" in self.router.get_neighbors("A")
        assert "A" in self.router.get_neighbors("B")

    def test_remove_neighbor(self):
        self.router.register_neighbor("A", "B")
        self.router.remove_neighbor("A", "B")
        assert "B" not in self.router.get_neighbors("A")
        assert "A" not in self.router.get_neighbors("B")

    def test_find_path_linear(self):
        """A-B-C path."""
        nodes = self._make_nodes()
        self.router.register_neighbor("A", "B")
        self.router.register_neighbor("B", "C")

        for nid in ["A", "B", "C"]:
            self.router.register_scope(nid, self._make_scope(nid, [DataCategory.IDENTITY]))

        path = self.router.find_path("A", "C", [DataCategory.IDENTITY], nodes)
        assert path == ["A", "B", "C"]

    def test_find_path_no_route(self):
        """Disconnected nodes have no path."""
        nodes = self._make_nodes()
        path = self.router.find_path("A", "E", [DataCategory.IDENTITY], nodes)
        assert path == []

    def test_find_path_same_node(self):
        """Source == target returns [source]."""
        nodes = self._make_nodes()
        path = self.router.find_path("A", "A", [DataCategory.IDENTITY], nodes)
        assert path == ["A"]

    def test_find_path_skips_quarantined(self):
        """QUARANTINED nodes are not routable."""
        nodes = self._make_nodes()
        nodes["B"].state = NodeState.QUARANTINED

        self.router.register_neighbor("A", "B")
        self.router.register_neighbor("B", "C")

        for nid in ["A", "B", "C"]:
            self.router.register_scope(nid, self._make_scope(nid, [DataCategory.IDENTITY]))

        # B is quarantined, so A cannot reach C through B
        path = self.router.find_path("A", "C", [DataCategory.IDENTITY], nodes)
        assert path == []

    def test_find_path_healing_node_can_relay(self):
        """HEALING nodes can relay but not decrypt."""
        nodes = self._make_nodes()
        nodes["B"].state = NodeState.HEALING

        self.router.register_neighbor("A", "B")
        self.router.register_neighbor("B", "C")

        for nid in ["A", "B", "C"]:
            self.router.register_scope(nid, self._make_scope(nid, [DataCategory.IDENTITY]))

        path = self.router.find_path("A", "C", [DataCategory.IDENTITY], nodes)
        assert "B" in path

    def test_capability_scope_filtering(self):
        """Node without required category cannot relay."""
        nodes = self._make_nodes()
        self.router.register_neighbor("A", "B")
        self.router.register_neighbor("B", "C")

        self.router.register_scope("A", self._make_scope("A", [DataCategory.IDENTITY]))
        self.router.register_scope("B", self._make_scope("B", [DataCategory.MEDICAL]))  # No IDENTITY
        self.router.register_scope("C", self._make_scope("C", [DataCategory.IDENTITY]))

        # B cannot relay IDENTITY data
        path = self.router.find_path("A", "C", [DataCategory.IDENTITY], nodes)
        assert path == []

    def test_find_alternate_path(self):
        """Find alternate route when primary path fails."""
        nodes = self._make_nodes()
        # Linear: A-B-C, with alternate: A-D-C
        self.router.register_neighbor("A", "B")
        self.router.register_neighbor("B", "C")
        self.router.register_neighbor("A", "D")
        self.router.register_neighbor("D", "C")

        for nid in ["A", "B", "C", "D"]:
            self.router.register_scope(nid, self._make_scope(nid, [DataCategory.IDENTITY]))

        primary = self.router.find_path("A", "C", [DataCategory.IDENTITY], nodes)
        assert len(primary) > 0  # Primary path exists

        alternate = self.router.find_alternate_path("A", "C", [DataCategory.IDENTITY],
                                                     nodes, exclude_path=primary)
        assert len(alternate) > 0  # Alternate path exists
        assert alternate != primary  # Alternate is different from primary

    def test_verify_redundancy(self):
        """Check that nodes have alternate routes."""
        nodes = self._make_nodes()
        # Triangle: A-B, A-C, B-C
        self.router.register_neighbor("A", "B")
        self.router.register_neighbor("A", "C")
        self.router.register_neighbor("B", "C")

        for nid in ["A", "B", "C"]:
            self.router.register_scope(nid, self._make_scope(nid, [DataCategory.IDENTITY]))

        redundancy = self.router.verify_redundancy(nodes)
        # Each node should have alternate routes to the others
        assert redundancy["A"] >= 1


# ── Self-Healing Mesh Integration Tests ──────────────────────────────


class TestSelfHealingMesh:
    """Integration tests for the full mesh lifecycle."""

    def setup_method(self):
        self.mesh = SelfHealingMesh(consensus_threshold=2, healing_period_seconds=0)

    def _register_node(self, node_id: str, state: NodeState = NodeState.ACTIVE,
                       categories: list = None) -> Node:
        node = Node(node_id=NodeID.generate(), name=node_id, state=state)
        cats = categories or [DataCategory.IDENTITY]
        scope = CapabilityScope(node_id=node.node_id.uuid, categories=cats)
        self.mesh.register_node(node, scope)
        return node

    def test_register_node(self):
        node = self._register_node("node-001")
        key = node.node_id.uuid
        assert self.mesh.get_node(key) is not None
        assert self.mesh.get_detector(key) is not None

    def test_unregister_node(self):
        node = self._register_node("node-001")
        key = node.node_id.uuid
        self.mesh.unregister_node(key)
        assert self.mesh.get_node(key) is None

    def test_flag_and_consensus(self):
        """Two independent flags trigger consensus."""
        n1 = self._register_node("node-001")
        n2 = self._register_node("node-002")
        n3 = self._register_node("node-003")

        self.mesh.flag_node(n1.node_id.uuid, n3.node_id.uuid, SignalType.SILENT_NODE)
        self.mesh.flag_node(n2.node_id.uuid, n3.node_id.uuid, SignalType.CREDENTIAL_STUFFING)

        assert self.mesh.check_consensus(n3.node_id.uuid) is True

    def test_single_flag_no_consensus(self):
        """Single flag doesn't trigger consensus (threshold=2)."""
        n1 = self._register_node("node-001")
        n2 = self._register_node("node-002")

        self.mesh.flag_node(n1.node_id.uuid, n2.node_id.uuid, SignalType.SILENT_NODE)

        assert self.mesh.check_consensus(n2.node_id.uuid) is False

    def test_process_flags_quarantines(self):
        """process_flags quarantines nodes with consensus."""
        n1 = self._register_node("node-001")
        n2 = self._register_node("node-002")
        n3 = self._register_node("node-003")

        self.mesh.flag_node(n1.node_id.uuid, n3.node_id.uuid, SignalType.SILENT_NODE)
        self.mesh.flag_node(n2.node_id.uuid, n3.node_id.uuid, SignalType.SILENT_NODE)

        quarantined = self.mesh.process_flags()
        assert n3.node_id.uuid in quarantined
        assert self.mesh.get_node(n3.node_id.uuid).state == NodeState.SUSPECT

    def test_healing_lifecycle(self):
        """Full lifecycle: flag → quarantine → heal → restore."""
        n1 = self._register_node("node-001")
        n2 = self._register_node("node-002")
        target = self._register_node("node-003")

        # Flag and quarantine
        self.mesh.flag_node(n1.node_id.uuid, target.node_id.uuid, SignalType.SILENT_NODE)
        self.mesh.flag_node(n2.node_id.uuid, target.node_id.uuid, SignalType.SILENT_NODE)
        self.mesh.process_flags()

        # First round: ACTIVE → SUSPECT
        # Need second round with new flags for SUSPECT → QUARANTINED
        self.mesh.flag_node(n1.node_id.uuid, target.node_id.uuid, SignalType.SILENT_NODE)
        self.mesh.flag_node(n2.node_id.uuid, target.node_id.uuid, SignalType.CREDENTIAL_STUFFING)
        self.mesh.process_flags()

        assert target.state == NodeState.QUARANTINED

        # Begin healing
        result = self.mesh.begin_healing(target.node_id.uuid, reason="Re-attestation passed")
        assert result.success is True
        assert target.state == NodeState.HEALING

        # Complete healing
        result = self.mesh.complete_healing(target.node_id.uuid)
        assert result.success is True
        assert target.state == NodeState.ACTIVE

    def test_revoke_node(self):
        """REVOKED is terminal."""
        node = self._register_node("node-001")
        self.mesh.revoke_node(node.node_id.uuid, reason="Admin decision")
        assert node.state == NodeState.REVOKED

    def test_reroute_around_quarantined(self):
        """Traffic reroutes around quarantined nodes."""
        n1 = self._register_node("A", categories=[DataCategory.IDENTITY, DataCategory.MEDICAL])
        n2 = self._register_node("B", categories=[DataCategory.IDENTITY, DataCategory.MEDICAL])
        n3 = self._register_node("C", categories=[DataCategory.IDENTITY, DataCategory.MEDICAL])

        a_id, b_id, c_id = n1.node_id.uuid, n2.node_id.uuid, n3.node_id.uuid

        self.mesh.add_neighbor(a_id, b_id)
        self.mesh.add_neighbor(b_id, c_id)
        self.mesh.add_neighbor(a_id, c_id)

        # Quarantine B (must go through state machine: ACTIVE → SUSPECT → QUARANTINED)
        self.mesh.state_machine.transition(n2, NodeState.SUSPECT, reason="test")
        self.mesh.state_machine.transition(n2, NodeState.QUARANTINED, reason="test")

        # Route around B
        path = self.mesh.reroute(a_id, c_id, [DataCategory.IDENTITY])
        assert b_id not in path
        assert path == [a_id, c_id]

    def test_flag_unknown_source_raises(self):
        """Flagging from unregistered source raises ValueError."""
        with pytest.raises(ValueError, match="not registered"):
            self.mesh.flag_node("unknown", "target", SignalType.SILENT_NODE)

    def test_healing_non_quarantined_fails(self):
        """Cannot start healing on a non-quarantined node."""
        node = self._register_node("node-001")
        result = self.mesh.begin_healing(node.node_id.uuid)
        assert result.success is False

    def test_get_healing_results(self):
        self._register_node("node-001")
        n2 = self._register_node("node-002")
        n3 = self._register_node("node-003")

        # Quarantine node-003
        self.mesh.state_machine.transition(n3, NodeState.SUSPECT, reason="flag")
        self.mesh.state_machine.transition(n3, NodeState.QUARANTINED, reason="consensus")

        # Begin healing
        self.mesh.begin_healing(n3.node_id.uuid)

        results = self.mesh.get_healing_results(n3.node_id.uuid)
        assert len(results) == 1
        assert results[0].new_state == NodeState.HEALING