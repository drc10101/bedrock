"""
Mesh state machine — manages node trust states.

ACTIVE -> SUSPECT -> QUARANTINED -> HEALING -> ACTIVE
                |                        ^
                +------- REVOKED --------+

State transitions are logged to the audit chain.
The mesh state machine is consensus-driven: ≥2 independent neighbor
flags trigger quarantine. No single node can unilaterally isolate another.

SPDX-License-Identifier: BSL-1.1 — See LICENSE for details.
"""

from datetime import UTC, datetime

from bedrock.identity.node import Node, NodeID, NodeState


class TransitionRecord:
    """Records a state transition for audit purposes."""

    def __init__(
        self,
        node_id: str,
        from_state: NodeState,
        to_state: NodeState,
        reason: str,
        timestamp: datetime | None = None,
    ):
        self.node_id = node_id
        self.from_state = from_state
        self.to_state = to_state
        self.reason = reason
        self.timestamp = timestamp or datetime.now(UTC)


class MeshStateMachine:
    """Manages node state transitions in the Self-Healing Mesh.

    State transitions:
    - ACTIVE -> SUSPECT: 1 neighbor flag (alert raised)
    - SUSPECT -> QUARANTINED: ≥2 neighbor flags (consensus)
    - SUSPECT -> ACTIVE: Flag cleared (false alarm)
    - QUARANTINED -> HEALING: Re-attestation passed
    - HEALING -> ACTIVE: Healing period elapsed, no further flags
    - HEALING -> QUARANTINED: New flag during healing
    - QUARANTINED -> REVOKED: Admin decision or confirmed malicious
    - Any state -> REVOKED: Permanent removal (terminal)

    REVOKED is terminal — no transitions out.
    """

    # Valid transitions: current_state -> [allowed_next_states]
    VALID_TRANSITIONS = {
        NodeState.ACTIVE: [NodeState.SUSPECT, NodeState.REVOKED],
        NodeState.SUSPECT: [NodeState.QUARANTINED, NodeState.ACTIVE, NodeState.REVOKED],
        NodeState.QUARANTINED: [NodeState.HEALING, NodeState.REVOKED],
        NodeState.HEALING: [NodeState.ACTIVE, NodeState.QUARANTINED, NodeState.REVOKED],
        NodeState.REVOKED: [],  # Terminal state
    }

    def __init__(self) -> None:
        self._transition_history: list[TransitionRecord] = []

    def transition(self, node: Node, new_state: NodeState, reason: str = "") -> Node:
        """Transition a node to a new state.

        Validates the transition is legal. Records it in history.

        Args:
            node: The node to transition
            new_state: Target state
            reason: Reason for the transition (for audit)

        Returns:
            The updated node

        Raises:
            ValueError: If the transition is invalid
        """
        allowed = self.VALID_TRANSITIONS.get(node.state, [])
        if new_state not in allowed:
            raise ValueError(
                f"Invalid transition: {node.state.value} -> {new_state.value}. "
                f"Allowed: {[s.value for s in allowed]}"
            )

        from_state = node.state
        node.state = new_state

        record = TransitionRecord(
            node_id=node.node_id.uuid,
            from_state=from_state,
            to_state=new_state,
            reason=reason,
        )
        self._transition_history.append(record)
        return node

    def can_transition(self, node: Node, new_state: NodeState) -> bool:
        """Check if a transition is valid without performing it."""
        allowed = self.VALID_TRANSITIONS.get(node.state, [])
        return new_state in allowed

    def can_promote_to_active(self, node: Node, healing_period_seconds: int = 3600) -> bool:
        """Check if a healing node can be promoted to active.

        Conditions:
        1. Node is in HEALING state
        2. Healing period has elapsed (checked via transition history)
        3. No new flags during healing period
        """
        if node.state != NodeState.HEALING:
            return False

        # Find when this node entered HEALING state
        healing_start = None
        for record in reversed(self._transition_history):
            if record.node_id == node.node_id and record.to_state == NodeState.HEALING:
                healing_start = record.timestamp
                break

        if healing_start is None:
            return True  # No record found, allow promotion

        # Check if healing period has elapsed
        elapsed = (datetime.now(UTC) - healing_start).total_seconds()
        if elapsed < healing_period_seconds:
            return False

        # Check for new flags during healing
        for record in self._transition_history:
            if (
                record.node_id == node.node_id
                and record.to_state == NodeState.QUARANTINED
                and record.timestamp > healing_start
            ):
                return False

        return True

    def get_transition_history(self, node_id: NodeID | str | None = None) -> list[TransitionRecord]:
        """Get transition history, optionally filtered by node_id."""
        if node_id:
            key = node_id.uuid if isinstance(node_id, NodeID) else node_id
            return [r for r in self._transition_history if r.node_id == key]
        return list(self._transition_history)

    def get_last_transition(self, node_id: NodeID | str) -> TransitionRecord | None:
        """Get the most recent transition for a node."""
        key = node_id.uuid if isinstance(node_id, NodeID) else node_id
        for record in reversed(self._transition_history):
            if record.node_id == key:
                return record
        return None
