"""
Self-Healing Mesh orchestrator.

Coordinates the attack detector, state machine, and router to provide
distributed attack detection, consensus-based node isolation, automatic
rerouting, and healing protocols.

The healing lifecycle:
1. DETECT: AttackDetector on each node observes suspicious behavior
2. FLAG: DetectionSignal is created and reported to the mesh
3. CONSENSUS: ≥2 independent flags trigger quarantine
4. ISOLATE: Node is transitioned to QUARANTINED, routes recalculated
5. HEAL: Node passes re-attestation, enters HEALING state
6. RESTORE: After healing period with no new flags, node returns to ACTIVE

SPDX-License-Identifier: BSL-1.1 — See LICENSE for details.
"""

from datetime import datetime, timezone, timedelta
from typing import Dict, List, Optional, Set

from bedrock.identity.node import Node, NodeState
from bedrock.identity.capabilities import CapabilityScope, DataCategory
from bedrock.mesh.detector import AttackDetector, DetectionSignal, SignalType
from bedrock.mesh.state_machine import MeshStateMachine
from bedrock.mesh.router import MeshRouter


class HealingResult:
    """Result of a healing attempt."""
    def __init__(self, node_id: str, success: bool, reason: str,
                 new_state: NodeState, timestamp: Optional[datetime] = None):
        self.node_id = node_id
        self.success = success
        self.reason = reason
        self.new_state = new_state
        self.timestamp = timestamp or datetime.now(timezone.utc)


class SelfHealingMesh:
    """Orchestrates the Self-Healing Mesh.

    Coordinates:
    - AttackDetector instances on each node
    - MeshStateMachine for node lifecycle management
    - MeshRouter for capability-scoped path calculation

    The mesh operates without a central orchestrator in production,
    but this class provides the coordination logic that each node runs.
    """

    def __init__(self, consensus_threshold: int = 2,
                 healing_period_seconds: int = 3600):
        self.consensus_threshold = consensus_threshold
        self.healing_period_seconds = healing_period_seconds
        self.state_machine = MeshStateMachine()
        self.router = MeshRouter()
        self._detectors: Dict[str, AttackDetector] = {}  # node_id -> detector
        self._nodes: Dict[str, Node] = {}
        self._healing_results: List[HealingResult] = []

    def register_node(self, node: Node, scope: Optional[CapabilityScope] = None) -> None:
        """Register a node and its detector with the mesh.

        Args:
            node: The node to register
            scope: Optional capability scope for routing
        """
        key = node.node_id.uuid
        self._nodes[key] = node
        self._detectors[key] = AttackDetector(node_id=key)
        if scope:
            self.router.register_scope(key, scope)

    def unregister_node(self, node_id: str) -> None:
        """Remove a node from the mesh."""
        self._nodes.pop(node_id, None)
        self._detectors.pop(node_id, None)

    def add_neighbor(self, node_id: str, neighbor_id: str) -> None:
        """Register a neighbor relationship in the mesh topology."""
        self.router.register_neighbor(node_id, neighbor_id)

    def remove_neighbor(self, node_id: str, neighbor_id: str) -> None:
        """Remove a neighbor relationship from the mesh topology."""
        self.router.remove_neighbor(node_id, neighbor_id)

    def flag_node(self, source_node_id: str, target_node_id: str,
                  signal_type: SignalType, details: Optional[dict] = None) -> DetectionSignal:
        """Flag a node from a source detector.

        Args:
            source_node_id: Node reporting the flag
            target_node_id: Node being flagged
            signal_type: Type of attack signal
            details: Signal-specific details

        Returns:
            The created DetectionSignal
        """
        if source_node_id not in self._detectors:
            raise ValueError(f"Source node {source_node_id} not registered in mesh")

        signal = self._detectors[source_node_id].detect(
            signal_type=signal_type,
            target_node_id=target_node_id,
            details=details or {},
        )
        return signal

    def check_consensus(self, node_id: str) -> bool:
        """Check if enough independent flags exist to quarantine a node.

        Collects flags from all detectors targeting the node.
        Returns True if ≥consensus_threshold unique sources have flagged it.
        """
        unique_flaggers: Set[str] = set()
        for detector in self._detectors.values():
            flags = detector.get_flags_for_node(node_id)
            for flag in flags:
                unique_flaggers.add(flag.source_node_id)

        return len(unique_flaggers) >= self.consensus_threshold

    def process_flags(self) -> List[str]:
        """Process all flags and quarantine nodes that reach consensus.

        Returns:
            List of node IDs that were quarantined
        """
        quarantined = []

        for node_id in list(self._nodes.keys()):
            if node_id not in self._nodes:
                continue
            node = self._nodes[node_id]
            if node.state != NodeState.ACTIVE and node.state != NodeState.SUSPECT:
                continue

            if self.check_consensus(node_id):
                try:
                    # First flag transitions ACTIVE -> SUSPECT
                    if node.state == NodeState.ACTIVE:
                        self.state_machine.transition(
                            node, NodeState.SUSPECT,
                            reason=f"Consensus: {self.consensus_threshold}+ flags"
                        )
                    # Second flag transitions SUSPECT -> QUARANTINED
                    elif node.state == NodeState.SUSPECT:
                        self.state_machine.transition(
                            node, NodeState.QUARANTINED,
                            reason=f"Consensus: {self.consensus_threshold}+ flags"
                        )
                    quarantined.append(node_id)
                except ValueError:
                    pass  # Invalid transition, skip

        return quarantined

    def begin_healing(self, node_id: str, reason: str = "Re-attestation passed") -> HealingResult:
        """Begin the healing process for a quarantined node.

        Transitions QUARANTINED -> HEALING.
        """
        if node_id not in self._nodes:
            raise ValueError(f"Node {node_id} not registered in mesh")

        node = self._nodes[node_id]
        if node.state != NodeState.QUARANTINED:
            return HealingResult(
                node_id=node_id, success=False,
                reason=f"Node is in {node.state.value} state, not QUARANTINED",
                new_state=node.state,
            )

        try:
            self.state_machine.transition(node, NodeState.HEALING, reason=reason)
            result = HealingResult(
                node_id=node_id, success=True,
                reason=reason, new_state=NodeState.HEALING,
            )
        except ValueError as e:
            result = HealingResult(
                node_id=node_id, success=False,
                reason=str(e), new_state=node.state,
            )

        self._healing_results.append(result)
        return result

    def complete_healing(self, node_id: str) -> HealingResult:
        """Complete healing and promote a node back to ACTIVE.

        Checks that:
        1. Node is in HEALING state
        2. Healing period has elapsed
        3. No new flags during healing period
        """
        if node_id not in self._nodes:
            raise ValueError(f"Node {node_id} not registered in mesh")

        node = self._nodes[node_id]

        if node.state != NodeState.HEALING:
            return HealingResult(
                node_id=node_id, success=False,
                reason=f"Node is in {node.state.value} state, not HEALING",
                new_state=node.state,
            )

        if not self.state_machine.can_promote_to_active(
                node, self.healing_period_seconds):
            return HealingResult(
                node_id=node_id, success=False,
                reason="Healing period not elapsed or new flags detected",
                new_state=node.state,
            )

        # Clear flags for this node across all detectors
        for detector in self._detectors.values():
            detector.clear_signals(node_id)

        try:
            self.state_machine.transition(node, NodeState.ACTIVE,
                                          reason="Healing complete")
            result = HealingResult(
                node_id=node_id, success=True,
                reason="Healing complete", new_state=NodeState.ACTIVE,
            )
        except ValueError as e:
            result = HealingResult(
                node_id=node_id, success=False,
                reason=str(e), new_state=node.state,
            )

        self._healing_results.append(result)
        return result

    def revoke_node(self, node_id: str, reason: str = "Admin decision") -> Node:
        """Revoke a node permanently.

        REVOKED is terminal — no transitions out.
        """
        if node_id not in self._nodes:
            raise ValueError(f"Node {node_id} not registered in mesh")

        node = self._nodes[node_id]
        self.state_machine.transition(node, NodeState.REVOKED, reason=reason)

        # Remove from routing topology
        neighbors = list(self.router.get_neighbors(node_id))
        for neighbor_id in neighbors:
            self.router.remove_neighbor(node_id, neighbor_id)

        return node

    def reroute(self, source_id: str, target_id: str,
                data_categories: List[DataCategory],
                exclude_path: Optional[List[str]] = None) -> List[str]:
        """Find a route through the mesh, optionally avoiding a failed path.

        Args:
            source_id: Source node ID
            target_id: Target node ID
            data_categories: Required data categories
            exclude_path: Previous path to avoid (for alternate routing)

        Returns:
            Ordered list of node IDs forming the path, or empty list
        """
        if exclude_path:
            return self.router.find_alternate_path(
                source_id, target_id, data_categories,
                self._nodes, exclude_path
            )
        return self.router.find_path(
            source_id, target_id, data_categories, self._nodes
        )

    def get_node(self, node_id: str) -> Optional[Node]:
        """Get a node by ID."""
        return self._nodes.get(node_id)

    def get_all_nodes(self) -> Dict[str, Node]:
        """Get all registered nodes."""
        return dict(self._nodes)

    def get_detector(self, node_id: str) -> Optional[AttackDetector]:
        """Get the detector for a node."""
        return self._detectors.get(node_id)

    def get_healing_results(self, node_id: Optional[str] = None) -> List[HealingResult]:
        """Get healing results, optionally filtered by node_id."""
        if node_id:
            return [r for r in self._healing_results if r.node_id == node_id]
        return list(self._healing_results)