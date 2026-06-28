"""
Attack detection heuristics for the Self-Healing Mesh.

Each node runs a lightweight local detector that observes its own traffic
and neighbor behavior. Detection is distributed and consensus-driven.
No central orchestrator required.

Signal types:
- CREDENTIAL_STUFFING: >N failed auth attempts in T seconds
- LATERAL_MOVEMENT: Node requesting outside its capability scope
- UNUSUAL_VOLUME: Outbound volume >X stddev from baseline
- ATTESTATION_FAILURE: Boot hash mismatch
- PATH_ANOMALY: Traffic rerouted through unexpected intermediaries
- CERTIFICATE_ANOMALY: Expired, revoked, or unsigned certificate
- AAD_MISMATCH: Decryption AAD doesn't match encryption AAD
- SILENT_NODE: No heartbeat for T seconds

SPDX-License-Identifier: BSL-1.1 — See LICENSE for details.
"""

from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import Enum


class SignalType(Enum):
    """Types of attack signals a node can detect."""

    CREDENTIAL_STUFFING = "credential_stuffing"
    LATERAL_MOVEMENT = "lateral_movement"
    UNUSUAL_VOLUME = "unusual_volume"
    ATTESTATION_FAILURE = "attestation_failure"
    PATH_ANOMALY = "path_anomaly"
    CERTIFICATE_ANOMALY = "certificate_anomaly"
    AAD_MISMATCH = "aad_mismatch"
    SILENT_NODE = "silent_node"


@dataclass
class DetectionSignal:
    """A single detection event from a node's local detector."""

    signal_type: SignalType
    source_node_id: str  # Node that detected the signal
    target_node_id: str  # Node being flagged
    details: dict = field(default_factory=dict)
    timestamp: datetime = field(default_factory=lambda: datetime.now(UTC))

    def __post_init__(self) -> None:
        if self.details is None:
            self.details = {}


class AttackDetector:
    """Local attack detector running on every node.

    Monitors neighbor traffic and behavior. Flags suspicious nodes.
    A single flag raises an alert; ≥2 flags from independent neighbors
    triggers quarantine via the MeshStateMachine.

    Each node in the mesh runs its own AttackDetector instance.
    When it observes suspicious behavior from a neighbor, it creates
    a DetectionSignal. The SelfHealingMesh collects signals from all
    nodes and determines consensus.

    Thresholds are configurable per signal type:
    - CREDENTIAL_STUFFING: >5 failed auth attempts in 60 seconds
    - LATERAL_MOVEMENT: Any request outside scope
    - UNUSUAL_VOLUME: >3 stddev from baseline
    - SILENT_NODE: No heartbeat for 300 seconds
    """

    # Default detection thresholds
    DEFAULT_THRESHOLDS: dict[SignalType, dict[str, int | float]] = {
        SignalType.CREDENTIAL_STUFFING: {"max_failures": 5, "window_seconds": 60},
        SignalType.LATERAL_MOVEMENT: {"max_scope_violations": 1},
        SignalType.UNUSUAL_VOLUME: {"stddev_threshold": 3.0},
        SignalType.ATTESTATION_FAILURE: {"max_failures": 1},
        SignalType.PATH_ANOMALY: {"max_anomalies": 2, "window_seconds": 300},
        SignalType.CERTIFICATE_ANOMALY: {"max_anomalies": 1},
        SignalType.AAD_MISMATCH: {"max_mismatches": 1},
        SignalType.SILENT_NODE: {"timeout_seconds": 300},
    }

    def __init__(self, node_id: str, thresholds: dict[SignalType, dict] | None = None):
        self.node_id = node_id
        self.thresholds = thresholds or self.DEFAULT_THRESHOLDS.copy()
        self._signals: list[DetectionSignal] = []

    def detect(
        self, signal_type: SignalType, target_node_id: str, details: dict | None = None
    ) -> DetectionSignal:
        """Record a detection signal against a node.

        Args:
            signal_type: Type of attack signal detected
            target_node_id: Node being flagged
            details: Signal-specific details

        Returns:
            The created DetectionSignal
        """
        signal = DetectionSignal(
            signal_type=signal_type,
            source_node_id=self.node_id,
            target_node_id=target_node_id,
            details=details or {},
        )
        self._signals.append(signal)
        return signal

    def get_flags_for_node(self, node_id: str) -> list[DetectionSignal]:
        """Get all signals from this detector targeting a specific node."""
        return [s for s in self._signals if s.target_node_id == node_id]

    def should_isolate(self, node_id: str, consensus_threshold: int = 2) -> bool:
        """Determine if a node should be quarantined.

        Returns True if ≥consensus_threshold unique sources have flagged the node.
        This is called by the mesh orchestrator, which collects signals
        from all nodes.

        Args:
            node_id: The node to check
            consensus_threshold: Minimum number of independent flaggers required
        """
        unique_flaggers: set[str] = set()
        for s in self._signals:
            if s.target_node_id == node_id:
                unique_flaggers.add(s.source_node_id)
        return len(unique_flaggers) >= consensus_threshold

    def get_all_signals(self) -> list[DetectionSignal]:
        """Get all signals from this detector."""
        return list(self._signals)

    def clear_signals(self, node_id: str | None = None) -> int:
        """Clear signals, optionally filtered by target node.

        Returns:
            Number of signals cleared
        """
        if node_id:
            original_count = len(self._signals)
            self._signals = [s for s in self._signals if s.target_node_id != node_id]
            return original_count - len(self._signals)
        else:
            count = len(self._signals)
            self._signals = []
            return count
