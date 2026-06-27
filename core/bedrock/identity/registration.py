"""
Node registration and registry.

Node registration is the first step in the identity lifecycle:
Registration → Attestation → Certificate Issuance → Capability Scoping → Active

The NodeRegistry tracks all nodes, their states, and their capabilities.
It enforces that every node has a unique cryptographic identity and
valid state transitions.

Trade Secret — InFill Systems, LLC.
"""

import uuid
from datetime import datetime, timezone
from typing import Dict, List, Optional, Set

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from bedrock.identity.node import Node, NodeID, NodeState


# Valid state transitions in the Self-Healing Mesh
VALID_TRANSITIONS = {
    NodeState.ACTIVE: {NodeState.SUSPECT, NodeState.REVOKED},
    NodeState.SUSPECT: {NodeState.QUARANTINED, NodeState.ACTIVE, NodeState.REVOKED},
    NodeState.QUARANTINED: {NodeState.HEALING, NodeState.REVOKED},
    NodeState.HEALING: {NodeState.ACTIVE, NodeState.QUARANTINED, NodeState.REVOKED},
    NodeState.REVOKED: set(),  # Terminal state
}


class RegistrationError(Exception):
    """Raised when node registration fails."""
    pass


class StateTransitionError(Exception):
    """Raised when an invalid state transition is attempted."""
    pass


class NodeRegistry:
    """Central registry for all nodes in a Bedrock network.

    The registry is the source of truth for:
    - Which nodes exist and their current state
    - Node identity (UUID + public key)
    - Capability assignments
    - State transitions in the Self-Healing Mesh

    In production, this would be backed by a persistent store (SQLCipher).
    This implementation uses in-memory storage for the core library.
    """

    def __init__(self):
        self._nodes: Dict[str, Node] = {}  # uuid -> Node
        self._public_keys: Dict[bytes, str] = {}  # public_key -> uuid (enforce uniqueness)
        self._names: Dict[str, str] = {}  # name -> uuid (enforce uniqueness)

    def register(self, name: str, node_type: str = "server",
                 private_key: Optional[Ed25519PrivateKey] = None,
                 metadata: Optional[dict] = None) -> Node:
        """Register a new node in the network.

        Generates a new cryptographic identity (UUID v7 + ed25519 key pair)
        and adds the node to the registry in ACTIVE state.

        Args:
            name: Human-readable node name (must be unique)
            node_type: Type of node (server, container, iot, gateway, client)
            private_key: Optional pre-generated key. If None, generates a new one.
            metadata: Optional key-value pairs for extensibility

        Returns:
            The newly registered Node

        Raises:
            RegistrationError: If name is already taken
        """
        if name in self._names:
            raise RegistrationError(f"Node name '{name}' is already registered")

        node_id = NodeID.generate(private_key=private_key)

        # Enforce public key uniqueness
        if node_id.public_key in self._public_keys:
            raise RegistrationError(
                f"Public key collision for node '{name}'. "
                f"Already registered to '{self._public_keys[node_id.public_key]}'."
            )

        node = Node(
            node_id=node_id,
            name=name,
            node_type=node_type,
            state=NodeState.ACTIVE,
            metadata=metadata or {},
        )

        self._nodes[node_id.uuid] = node
        self._public_keys[node_id.public_key] = node_id.uuid
        self._names[name] = node_id.uuid

        return node

    def get(self, uuid: str) -> Optional[Node]:
        """Look up a node by its UUID.

        Returns None if not found.
        """
        return self._nodes.get(uuid)

    def get_by_name(self, name: str) -> Optional[Node]:
        """Look up a node by its human-readable name.

        Returns None if not found.
        """
        uuid = self._names.get(name)
        if uuid is None:
            return None
        return self._nodes.get(uuid)

    def get_by_public_key(self, public_key: bytes) -> Optional[Node]:
        """Look up a node by its ed25519 public key.

        Returns None if not found.
        """
        uuid = self._public_keys.get(public_key)
        if uuid is None:
            return None
        return self._nodes.get(uuid)

    def list_nodes(self, state: Optional[NodeState] = None,
                   node_type: Optional[str] = None) -> List[Node]:
        """List nodes, optionally filtered by state or type.

        Args:
            state: Filter by node state (e.g., ACTIVE, SUSPECT)
            node_type: Filter by node type (e.g., "server", "iot")

        Returns:
            List of matching nodes
        """
        nodes = list(self._nodes.values())
        if state is not None:
            nodes = [n for n in nodes if n.state == state]
        if node_type is not None:
            nodes = [n for n in nodes if n.node_type == node_type]
        return nodes

    def count(self, state: Optional[NodeState] = None) -> int:
        """Count nodes, optionally filtered by state."""
        if state is None:
            return len(self._nodes)
        return sum(1 for n in self._nodes.values() if n.state == state)

    def transition(self, uuid: str, new_state: NodeState, reason: str = "") -> Node:
        """Transition a node to a new state in the Self-Healing Mesh.

        Enforces valid state transitions:
        - ACTIVE → SUSPECT, REVOKED
        - SUSPECT → QUARANTINED, ACTIVE, REVOKED
        - QUARANTINED → HEALING, REVOKED
        - HEALING → ACTIVE, QUARANTINED, REVOKED
        - REVOKED → (terminal, no transitions)

        Args:
            uuid: Node UUID
            new_state: Target state
            reason: Human-readable reason for the transition

        Returns:
            The updated Node

        Raises:
            KeyError: If node not found
            StateTransitionError: If the transition is invalid
        """
        node = self._nodes.get(uuid)
        if node is None:
            raise KeyError(f"Node '{uuid}' not found")

        current = node.state
        if new_state not in VALID_TRANSITIONS.get(current, set()):
            raise StateTransitionError(
                f"Invalid transition: {current.value} → {new_state.value}. "
                f"Allowed transitions from {current.value}: "
                f"{', '.join(s.value for s in VALID_TRANSITIONS[current])}"
            )

        node.state = new_state
        return node

    def unregister(self, uuid: str) -> None:
        """Remove a node from the registry.

        In production, this would trigger audit chain entries,
        certificate revocation, and key rotation.

        Args:
            uuid: Node UUID to remove

        Raises:
            KeyError: If node not found
        """
        node = self._nodes.get(uuid)
        if node is None:
            raise KeyError(f"Node '{uuid}' not found")

        # Clean up indexes
        del self._nodes[uuid]
        self._public_keys.pop(node.node_id.public_key, None)
        self._names.pop(node.name, None)

    def verify_identity(self, uuid: str, public_key: bytes) -> bool:
        """Verify that a UUID and public key match a registered node.

        Used to authenticate nodes claiming a specific identity.
        """
        node = self._nodes.get(uuid)
        if node is None:
            return False
        return node.node_id.public_key == public_key

    def heartbeat(self, uuid: str) -> Node:
        """Record a heartbeat from a node.

        Args:
            uuid: Node UUID

        Returns:
            The updated Node

        Raises:
            KeyError: If node not found
        """
        node = self._nodes.get(uuid)
        if node is None:
            raise KeyError(f"Node '{uuid}' not found")
        node.update_heartbeat()
        return node

    def get_active_nodes(self) -> List[Node]:
        """Get all nodes in ACTIVE state."""
        return self.list_nodes(state=NodeState.ACTIVE)

    def get_suspect_nodes(self) -> List[Node]:
        """Get all nodes in SUSPECT state."""
        return self.list_nodes(state=NodeState.SUSPECT)

    def get_quarantined_nodes(self) -> List[Node]:
        """Get all nodes in QUARANTINED state."""
        return self.list_nodes(state=NodeState.QUARANTINED)

    def get_healing_nodes(self) -> List[Node]:
        """Get all nodes in HEALING state."""
        return self.list_nodes(state=NodeState.HEALING)

    def get_revoked_nodes(self) -> List[Node]:
        """Get all nodes in REVOKED state."""
        return self.list_nodes(state=NodeState.REVOKED)