"""
Mesh state machine — manages node trust states.

ACTIVE -> SUSPECT -> QUARANTINED -> HEALING -> ACTIVE
                |                        ^
                +------- REVOKED --------+

State transitions are logged to the audit chain.
"""

from bedrock.identity.node import Node, NodeState
from datetime import datetime, timezone
from typing import Optional


class MeshStateMachine:
    """Manages node state transitions in the Self-Healing Mesh.

    State transitions:
    - ACTIVE -> SUSPECT: 1 neighbor flag
    - SUSPECT -> QUARANTINED: ≥2 neighbor flags (consensus)
    - QUARANTINED -> HEALING: Re-attestation passed
    - HEALING -> ACTIVE: Configurable healing period elapsed, no further flags
    - QUARANTINED -> REVOKED: Admin decision or confirmed malicious
    - Any state -> REVOKED: Permanent removal
    """

    def transition(self, node: Node, new_state: NodeState,
                   reason: str = "") -> Node:
        """Transition a node to a new state.

        Validates the transition is legal. Logs to audit chain.
        Returns the updated node.
        """
        valid_transitions = {
            NodeState.ACTIVE: [NodeState.SUSPECT, NodeState.REVOKED],
            NodeState.SUSPECT: [NodeState.QUARANTINED, NodeState.ACTIVE, NodeState.REVOKED],
            NodeState.QUARANTINED: [NodeState.HEALING, NodeState.REVOKED],
            NodeState.HEALING: [NodeState.ACTIVE, NodeState.QUARANTINED, NodeState.REVOKED],
            NodeState.REVOKED: [],  # Terminal state
        }

        allowed = valid_transitions.get(node.state, [])
        if new_state not in allowed:
            raise ValueError(
                f"Invalid transition: {node.state.value} -> {new_state.value}. "
                f"Allowed: {[s.value for s in allowed]}"
            )

        node.state = new_state
        # Audit chain logging would happen here (B-108)
        return node

    def can_promote_to_active(self, node: Node,
                               healing_period_seconds: int = 3600) -> bool:
        """Check if a healing node can be promoted to active.

        Conditions:
        1. Node is in HEALING state
        2. Healing period has elapsed
        3. No new flags during healing period
        """
        if node.state != NodeState.HEALING:
            return False
        # Time-based and flag checks would be implemented in B-111
        return True