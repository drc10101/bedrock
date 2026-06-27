"""Tests for Node identity model."""

from bedrock.identity.node import Node, NodeID, NodeState


class TestNodeID:
    """Test NodeID generation."""

    def test_generate_creates_uuid(self):
        node_id = NodeID.generate()
        assert node_id.uuid is not None
        assert len(node_id.uuid) > 0

    def test_generate_creates_timestamp(self):
        node_id = NodeID.generate()
        assert node_id.created_at is not None


class TestNode:
    """Test Node trust states and capability methods."""

    def _make_node(self, state=NodeState.ACTIVE):
        node_id = NodeID.generate()
        return Node(
            node_id=node_id,
            name="test-node",
            state=state,
        )

    def test_active_node_can_route(self):
        node = self._make_node(NodeState.ACTIVE)
        assert node.can_route() is True
        assert node.can_decrypt() is True
        assert node.can_relay() is True

    def test_suspect_node_can_route(self):
        node = self._make_node(NodeState.SUSPECT)
        assert node.can_route() is True
        assert node.can_decrypt() is True
        assert node.can_relay() is True

    def test_quarantined_node_cannot_route(self):
        node = self._make_node(NodeState.QUARANTINED)
        assert node.can_route() is False
        assert node.can_decrypt() is False
        assert node.can_relay() is False

    def test_healing_node_can_relay_only(self):
        node = self._make_node(NodeState.HEALING)
        assert node.can_route() is False
        assert node.can_decrypt() is False
        assert node.can_relay() is True

    def test_revoked_node_cannot_do_anything(self):
        node = self._make_node(NodeState.REVOKED)
        assert node.can_route() is False
        assert node.can_decrypt() is False
        assert node.can_relay() is False

    def test_flag_recording(self):
        node = self._make_node()
        node.flag("neighbor-1", "credential_stuffing")
        node.flag("neighbor-2", "unusual_volume")
        assert node.flag_count() == 2

    def test_flag_deduplication(self):
        node = self._make_node()
        node.flag("neighbor-1", "credential_stuffing")
        node.flag("neighbor-1", "unusual_volume")
        assert node.flag_count() == 1