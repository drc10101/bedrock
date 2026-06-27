"""Tests for Identity Fabric — Node Registration (B-105)."""

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from bedrock.identity.node import Node, NodeID, NodeState
from bedrock.identity.registration import (
    NodeRegistry, RegistrationError, StateTransitionError, VALID_TRANSITIONS,
)


class TestNodeID:
    """Test cryptographic node identity generation."""

    def test_generate_creates_uuid(self):
        node_id = NodeID.generate()
        assert node_id.uuid is not None
        assert len(node_id.uuid) == 36  # UUID format

    def test_generate_creates_public_key(self):
        node_id = NodeID.generate()
        assert len(node_id.public_key) == 32  # ed25519 public key is 32 bytes

    def test_generate_with_existing_private_key(self):
        private_key = Ed25519PrivateKey.generate()
        node_id = NodeID.generate(private_key=private_key)
        expected_pub = private_key.public_key().public_bytes_raw()
        assert node_id.public_key == expected_pub

    def test_unique_ids(self):
        """Each generation creates a unique UUID and key pair."""
        id1 = NodeID.generate()
        id2 = NodeID.generate()
        assert id1.uuid != id2.uuid
        assert id1.public_key != id2.public_key

    def test_public_key_hex(self):
        node_id = NodeID.generate()
        hex_str = node_id.public_key_hex()
        assert len(hex_str) == 64  # 32 bytes = 64 hex chars

    def test_fingerprint(self):
        node_id = NodeID.generate()
        fp = node_id.fingerprint()
        assert len(fp) == 16  # First 16 hex chars
        assert fp == node_id.public_key.hex()[:16]

    def test_created_at_is_utc(self):
        node_id = NodeID.generate()
        assert node_id.created_at is not None
        assert node_id.created_at.tzinfo is not None


class TestNode:
    """Test Node data model and state checks."""

    def _make_node(self, state=NodeState.ACTIVE):
        node_id = NodeID.generate()
        return Node(node_id=node_id, name="test-node", state=state)

    def test_active_node_can_route(self):
        node = self._make_node(NodeState.ACTIVE)
        assert node.can_route() is True
        assert node.can_relay() is True
        assert node.can_decrypt() is True

    def test_suspect_node_can_route(self):
        node = self._make_node(NodeState.SUSPECT)
        assert node.can_route() is True
        assert node.can_relay() is True
        assert node.can_decrypt() is True

    def test_quarantined_node_cannot_route(self):
        node = self._make_node(NodeState.QUARANTINED)
        assert node.can_route() is False
        assert node.can_relay() is False
        assert node.can_decrypt() is False

    def test_healing_node_can_relay_only(self):
        node = self._make_node(NodeState.HEALING)
        assert node.can_route() is False
        assert node.can_relay() is True
        assert node.can_decrypt() is False

    def test_revoked_node_cannot_do_anything(self):
        node = self._make_node(NodeState.REVOKED)
        assert node.can_route() is False
        assert node.can_relay() is False
        assert node.can_decrypt() is False

    def test_flag_recording(self):
        node = self._make_node()
        node.flag("neighbor-1", "suspicious traffic")
        assert node.flag_count() == 1

    def test_flag_deduplication(self):
        node = self._make_node()
        node.flag("neighbor-1", "suspicious traffic")
        node.flag("neighbor-1", "more suspicious traffic")
        node.flag("neighbor-2", "unusual pattern")
        assert node.flag_count() == 2  # neighbor-1 counted once

    def test_heartbeat(self):
        node = self._make_node()
        assert node.last_heartbeat is None
        assert node.is_healthy() is False  # No heartbeat yet

        node.update_heartbeat()
        assert node.last_heartbeat is not None
        assert node.is_healthy() is True

    def test_metadata(self):
        node_id = NodeID.generate()
        node = Node(
            node_id=node_id,
            name="iot-sensor-01",
            node_type="iot",
            metadata={"location": "warehouse-3", "firmware": "v2.1.0"},
        )
        assert node.metadata["location"] == "warehouse-3"
        assert node.node_type == "iot"


class TestNodeRegistry:
    """Test node registration, lookup, and state transitions."""

    def setup_method(self):
        self.registry = NodeRegistry()

    def test_register_node(self):
        node = self.registry.register(name="server-01", node_type="server")
        assert node.name == "server-01"
        assert node.node_type == "server"
        assert node.state == NodeState.ACTIVE
        assert len(node.node_id.uuid) == 36
        assert len(node.node_id.public_key) == 32

    def test_register_with_metadata(self):
        node = self.registry.register(
            name="iot-sensor-01",
            node_type="iot",
            metadata={"location": "warehouse-3"},
        )
        assert node.metadata["location"] == "warehouse-3"

    def test_register_duplicate_name_raises(self):
        self.registry.register(name="server-01")
        with pytest.raises(RegistrationError, match="already registered"):
            self.registry.register(name="server-01")

    def test_register_with_existing_private_key(self):
        private_key = Ed25519PrivateKey.generate()
        node = self.registry.register(name="server-01", private_key=private_key)
        expected_pub = private_key.public_key().public_bytes_raw()
        assert node.node_id.public_key == expected_pub

    def test_get_by_uuid(self):
        node = self.registry.register(name="server-01")
        found = self.registry.get(node.node_id.uuid)
        assert found is node

    def test_get_by_name(self):
        node = self.registry.register(name="server-01")
        found = self.registry.get_by_name("server-01")
        assert found is node

    def test_get_by_public_key(self):
        node = self.registry.register(name="server-01")
        found = self.registry.get_by_public_key(node.node_id.public_key)
        assert found is node

    def test_get_nonexistent(self):
        assert self.registry.get("nonexistent") is None
        assert self.registry.get_by_name("nonexistent") is None
        assert self.registry.get_by_public_key(b"\x00" * 32) is None

    def test_list_all_nodes(self):
        self.registry.register(name="server-01", node_type="server")
        self.registry.register(name="iot-01", node_type="iot")
        self.registry.register(name="gateway-01", node_type="gateway")
        all_nodes = self.registry.list_nodes()
        assert len(all_nodes) == 3

    def test_list_nodes_by_state(self):
        n1 = self.registry.register(name="server-01")
        n2 = self.registry.register(name="server-02")
        self.registry.transition(n2.node_id.uuid, NodeState.SUSPECT, reason="flagged")
        active = self.registry.list_nodes(state=NodeState.ACTIVE)
        suspect = self.registry.list_nodes(state=NodeState.SUSPECT)
        assert len(active) == 1
        assert len(suspect) == 1

    def test_list_nodes_by_type(self):
        self.registry.register(name="server-01", node_type="server")
        self.registry.register(name="iot-01", node_type="iot")
        self.registry.register(name="gateway-01", node_type="gateway")
        servers = self.registry.list_nodes(node_type="server")
        assert len(servers) == 1
        assert servers[0].name == "server-01"

    def test_count(self):
        self.registry.register(name="server-01")
        self.registry.register(name="server-02")
        self.registry.register(name="server-03")
        assert self.registry.count() == 3

    def test_count_by_state(self):
        n1 = self.registry.register(name="server-01")
        n2 = self.registry.register(name="server-02")
        self.registry.transition(n2.node_id.uuid, NodeState.SUSPECT, reason="test")
        assert self.registry.count(NodeState.ACTIVE) == 1
        assert self.registry.count(NodeState.SUSPECT) == 1

    def test_verify_identity(self):
        node = self.registry.register(name="server-01")
        assert self.registry.verify_identity(node.node_id.uuid, node.node_id.public_key) is True
        assert self.registry.verify_identity(node.node_id.uuid, b"\x00" * 32) is False
        assert self.registry.verify_identity("nonexistent", node.node_id.public_key) is False

    def test_heartbeat(self):
        node = self.registry.register(name="server-01")
        updated = self.registry.heartbeat(node.node_id.uuid)
        assert updated.last_heartbeat is not None

    def test_heartbeat_nonexistent(self):
        with pytest.raises(KeyError):
            self.registry.heartbeat("nonexistent")

    def test_unregister(self):
        node = self.registry.register(name="server-01")
        uuid = node.node_id.uuid
        self.registry.unregister(uuid)
        assert self.registry.get(uuid) is None
        assert self.registry.get_by_name("server-01") is None

    def test_unregister_nonexistent(self):
        with pytest.raises(KeyError):
            self.registry.unregister("nonexistent")

    def test_convenience_queries(self):
        n1 = self.registry.register(name="active-01")
        n2 = self.registry.register(name="suspect-01")
        n3 = self.registry.register(name="quarantined-01")
        n4 = self.registry.register(name="healing-01")
        n5 = self.registry.register(name="revoked-01")

        # Follow valid state machine paths
        self.registry.transition(n2.node_id.uuid, NodeState.SUSPECT)
        self.registry.transition(n3.node_id.uuid, NodeState.SUSPECT)
        self.registry.transition(n3.node_id.uuid, NodeState.QUARANTINED)
        self.registry.transition(n4.node_id.uuid, NodeState.SUSPECT)
        self.registry.transition(n4.node_id.uuid, NodeState.QUARANTINED)
        self.registry.transition(n4.node_id.uuid, NodeState.HEALING)
        self.registry.transition(n5.node_id.uuid, NodeState.REVOKED)

        assert len(self.registry.get_active_nodes()) == 1
        assert len(self.registry.get_suspect_nodes()) == 1
        assert len(self.registry.get_quarantined_nodes()) == 1
        assert len(self.registry.get_healing_nodes()) == 1
        assert len(self.registry.get_revoked_nodes()) == 1


class TestStateTransitions:
    """Test Self-Healing Mesh state transitions."""

    def setup_method(self):
        self.registry = NodeRegistry()
        self.node = self.registry.register(name="test-node")

    def test_active_to_suspect(self):
        updated = self.registry.transition(
            self.node.node_id.uuid, NodeState.SUSPECT, reason="neighbor flagged"
        )
        assert updated.state == NodeState.SUSPECT

    def test_active_to_revoked(self):
        updated = self.registry.transition(
            self.node.node_id.uuid, NodeState.REVOKED, reason="compromised"
        )
        assert updated.state == NodeState.REVOKED

    def test_active_to_quarantined_invalid(self):
        with pytest.raises(StateTransitionError, match="Invalid transition"):
            self.registry.transition(
                self.node.node_id.uuid, NodeState.QUARANTINED
            )

    def test_suspect_to_quarantined(self):
        self.registry.transition(self.node.node_id.uuid, NodeState.SUSPECT)
        updated = self.registry.transition(
            self.node.node_id.uuid, NodeState.QUARANTINED, reason="attestation failed"
        )
        assert updated.state == NodeState.QUARANTINED

    def test_suspect_to_active(self):
        """Node recovers from suspect state."""
        self.registry.transition(self.node.node_id.uuid, NodeState.SUSPECT)
        updated = self.registry.transition(
            self.node.node_id.uuid, NodeState.ACTIVE, reason="false alarm"
        )
        assert updated.state == NodeState.ACTIVE

    def test_quarantined_to_healing(self):
        self.registry.transition(self.node.node_id.uuid, NodeState.SUSPECT)
        self.registry.transition(self.node.node_id.uuid, NodeState.QUARANTINED)
        updated = self.registry.transition(
            self.node.node_id.uuid, NodeState.HEALING, reason="re-attesting"
        )
        assert updated.state == NodeState.HEALING

    def test_healing_to_active(self):
        """Node successfully re-attests and returns to active."""
        self.registry.transition(self.node.node_id.uuid, NodeState.SUSPECT)
        self.registry.transition(self.node.node_id.uuid, NodeState.QUARANTINED)
        self.registry.transition(self.node.node_id.uuid, NodeState.HEALING)
        updated = self.registry.transition(
            self.node.node_id.uuid, NodeState.ACTIVE, reason="re-attestation passed"
        )
        assert updated.state == NodeState.ACTIVE

    def test_healing_to_quarantined(self):
        """Re-attestation fails, node goes back to quarantine."""
        self.registry.transition(self.node.node_id.uuid, NodeState.SUSPECT)
        self.registry.transition(self.node.node_id.uuid, NodeState.QUARANTINED)
        self.registry.transition(self.node.node_id.uuid, NodeState.HEALING)
        updated = self.registry.transition(
            self.node.node_id.uuid, NodeState.QUARANTINED, reason="re-attestation failed"
        )
        assert updated.state == NodeState.QUARANTINED

    def test_revoked_is_terminal(self):
        """Once revoked, a node cannot transition to any other state."""
        self.registry.transition(self.node.node_id.uuid, NodeState.REVOKED)
        for state in NodeState:
            if state == NodeState.REVOKED:
                continue
            with pytest.raises(StateTransitionError, match="Invalid transition"):
                self.registry.transition(self.node.node_id.uuid, state)

    def test_transition_nonexistent_node(self):
        with pytest.raises(KeyError):
            self.registry.transition("nonexistent", NodeState.SUSPECT)

    def test_valid_transitions_completeness(self):
        """Verify every state has defined transitions."""
        for state in NodeState:
            assert state in VALID_TRANSITIONS

    def test_full_mesh_lifecycle(self):
        """ACTIVE → SUSPECT → QUARANTINED → HEALING → ACTIVE (happy path)."""
        uuid = self.node.node_id.uuid

        # Neighbor flags node
        self.registry.transition(uuid, NodeState.SUSPECT, reason="anomalous traffic")
        assert self.node.state == NodeState.SUSPECT

        # Consensus quarantines node
        self.registry.transition(uuid, NodeState.QUARANTINED, reason="attestation failed")
        assert self.node.state == NodeState.QUARANTINED

        # Node starts re-attestation
        self.registry.transition(uuid, NodeState.HEALING, reason="re-attesting")
        assert self.node.state == NodeState.HEALING

        # Re-attestation passes
        self.registry.transition(uuid, NodeState.ACTIVE, reason="re-attestation passed")
        assert self.node.state == NodeState.ACTIVE


class TestRegistrationIntegration:
    """Integration tests combining registration with other components."""

    def test_multiple_node_types(self):
        registry = NodeRegistry()
        server = registry.register(name="api-server-01", node_type="server")
        container = registry.register(name="pod-web-01", node_type="container")
        iot = registry.register(name="temp-sensor-01", node_type="iot")
        gateway = registry.register(name="lb-01", node_type="gateway")

        assert len(registry.list_nodes()) == 4
        assert len(registry.list_nodes(node_type="server")) == 1
        assert len(registry.list_nodes(node_type="container")) == 1
        assert len(registry.list_nodes(node_type="iot")) == 1
        assert len(registry.list_nodes(node_type="gateway")) == 1

    def test_node_flagging_triggers_suspect(self):
        """Simulate the mesh consensus pattern: 3 neighbors flag → suspect."""
        registry = NodeRegistry()
        node = registry.register(name="target-node")

        # Three neighbors flag the node
        node.flag("neighbor-1", "anomalous traffic pattern")
        node.flag("neighbor-2", "unexpected outbound connection")
        node.flag("neighbor-3", "failed health check")

        assert node.flag_count() == 3
        # In the real mesh, consensus threshold would trigger transition
        registry.transition(node.node_id.uuid, NodeState.SUSPECT, reason="3 neighbor flags")
        assert node.state == NodeState.SUSPECT

    def test_node_identity_verification(self):
        """Verify that identity checks prevent spoofing."""
        registry = NodeRegistry()
        node = registry.register(name="legit-server")

        # Correct identity passes
        assert registry.verify_identity(
            node.node_id.uuid, node.node_id.public_key
        ) is True

        # Wrong public key fails
        fake_key = Ed25519PrivateKey.generate().public_key().public_bytes_raw()
        assert registry.verify_identity(node.node_id.uuid, fake_key) is False

        # Wrong UUID fails
        assert registry.verify_identity("fake-uuid", node.node_id.public_key) is False