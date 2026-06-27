"""
Bedrock Self-Healing Mesh.

Distributed attack detection, consensus-based node isolation,
automatic rerouting, healing protocol, node state machine.

Every node monitors its neighbors. When ≥2 neighbors flag a node,
it's quarantined. Traffic reroutes through healthy nodes.
Quarantined nodes can heal through re-attestation.

Integration: MeshIntegrator coordinates mesh state changes across
Bedrock subsystems (certificates, audit, access control, consent).

Trade Secret — InFill Systems, LLC.
"""

from bedrock.mesh.detector import AttackDetector, DetectionSignal, SignalType
from bedrock.mesh.state_machine import MeshStateMachine, TransitionRecord
from bedrock.mesh.router import MeshRouter
from bedrock.mesh.healing import SelfHealingMesh, HealingResult
from bedrock.mesh.integration import MeshIntegrator, MeshEvent

__all__ = [
    "AttackDetector", "DetectionSignal", "SignalType",
    "MeshStateMachine", "TransitionRecord",
    "MeshRouter",
    "SelfHealingMesh", "HealingResult",
    "MeshIntegrator", "MeshEvent",
]