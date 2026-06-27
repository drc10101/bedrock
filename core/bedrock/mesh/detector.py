"""
Attack detection heuristics for the Self-Healing Mesh.

Each node runs a lightweight local detector that observes its own traffic
and neighbor behavior. Detection is distributed and consensus-driven.
No central orchestrator required.
"""

from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from typing import List, Optional


class SignalType(Enum):
    """Types of attack signals a node can detect."""
    CREDENTIAL_STUFFING = "credential_stuffing"  # >N failed auth attempts in T seconds
    LATERAL_MOVEMENT = "lateral_movement"          # Node requesting outside its capability scope
    UNUSUAL_VOLUME = "unusual_volume"              # Outbound volume >X stddev from baseline
    ATTESTATION_FAILURE = "attestation_failure"    # Boot hash mismatch
    PATH_ANOMALY = "path_anomaly"                  # Traffic rerouted through unexpected intermediaries
    CERTIFICATE_ANOMALY = "certificate_anomaly"    # Expired, revoked, or unsigned certificate
    AAD_MISMATCH = "aad_mismatch"                  # Decryption AAD doesn't match encryption AAD
    SILENT_NODE = "silent_node"                     # No heartbeat for T seconds


@dataclass
class DetectionSignal:
    """A single detection event from a node's local detector."""
    signal_type: SignalType
    source_node_id: str      # Node that detected the signal
    target_node_id: str      # Node being flagged
    details: dict            # Signal-specific details (threshold, baseline, etc.)
    timestamp: datetime = None

    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = datetime.now(timezone.utc)


class AttackDetector:
    """Local attack detector running on every node.

    Monitors neighbor traffic and behavior. Flags suspicious nodes.
    A single flag raises an alert; ≥2 flags from independent neighbors
    triggers quarantine via the MeshStateMachine.
    """

    def __init__(self, config=None):
        self._config = config
        self._signals: List[DetectionSignal] = []

    def detect(self, signal_type: SignalType, target_node_id: str,
               details: dict = None) -> DetectionSignal:
        """Record a detection signal against a node."""
        signal = DetectionSignal(
            signal_type=signal_type,
            source_node_id="",  # Will be populated by the node running this detector
            target_node_id=target_node_id,
            details=details or {},
        )
        self._signals.append(signal)
        return signal

    def get_flags_for_node(self, node_id: str) -> List[DetectionSignal]:
        """Get all signals targeting a specific node."""
        return [s for s in self._signals if s.target_node_id == node_id]

    def should_isolate(self, node_id: str, consensus_threshold: int = 2) -> bool:
        """Determine if a node should be quarantined.

        Returns True if ≥consensus_threshold unique neighbors have flagged the node.
        """
        unique_flaggers = {s.source_node_id for s in self.get_flags_for_node(node_id)}
        return len(unique_flaggers) >= consensus_threshold