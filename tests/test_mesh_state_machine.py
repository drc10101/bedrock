"""Tests for Mesh State Machine."""

import pytest
from bedrock.identity.node import Node, NodeID, NodeState
from bedrock.mesh.state_machine import MeshStateMachine


class TestMeshStateMachine:
    """Test node state transitions."""

    def _make_node(self, state=NodeState.ACTIVE):
        return Node(node_id=NodeID.generate(), name="test-node", state=state)

    def test_active_to_suspect(self):
        sm = MeshStateMachine()
        node = self._make_node(NodeState.ACTIVE)
        result = sm.transition(node, NodeState.SUSPECT, reason="1 flag")
        assert result.state == NodeState.SUSPECT

    def test_active_to_revoked(self):
        sm = MeshStateMachine()
        node = self._make_node(NodeState.ACTIVE)
        result = sm.transition(node, NodeState.REVOKED, reason="admin decision")
        assert result.state == NodeState.REVOKED

    def test_suspect_to_quarantined(self):
        sm = MeshStateMachine()
        node = self._make_node(NodeState.SUSPECT)
        result = sm.transition(node, NodeState.QUARANTINED, reason="2 flags consensus")
        assert result.state == NodeState.QUARANTINED

    def test_suspect_to_active(self):
        sm = MeshStateMachine()
        node = self._make_node(NodeState.SUSPECT)
        result = sm.transition(node, NodeState.ACTIVE, reason="flag expired")
        assert result.state == NodeState.ACTIVE

    def test_quarantined_to_healing(self):
        sm = MeshStateMachine()
        node = self._make_node(NodeState.QUARANTINED)
        result = sm.transition(node, NodeState.HEALING, reason="re-attestation passed")
        assert result.state == NodeState.HEALING

    def test_healing_to_active(self):
        sm = MeshStateMachine()
        node = self._make_node(NodeState.HEALING)
        result = sm.transition(node, NodeState.ACTIVE, reason="healing period elapsed")
        assert result.state == NodeState.ACTIVE

    def test_invalid_transition_active_to_healing(self):
        sm = MeshStateMachine()
        node = self._make_node(NodeState.ACTIVE)
        with pytest.raises(ValueError, match="Invalid transition"):
            sm.transition(node, NodeState.HEALING)

    def test_invalid_transition_revoked_to_anything(self):
        sm = MeshStateMachine()
        node = self._make_node(NodeState.REVOKED)
        with pytest.raises(ValueError, match="Invalid transition"):
            sm.transition(node, NodeState.ACTIVE)

    def test_can_promote_to_active_healing_node(self):
        sm = MeshStateMachine()
        node = self._make_node(NodeState.HEALING)
        assert sm.can_promote_to_active(node) is True

    def test_cannot_promote_active_node(self):
        sm = MeshStateMachine()
        node = self._make_node(NodeState.ACTIVE)
        assert sm.can_promote_to_active(node) is False