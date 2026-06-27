"""
Bedrock Self-Healing Mesh.

Distributed attack detection, consensus-based node isolation,
automatic rerouting, healing protocol, node state machine.

Every node monitors its neighbors. When ≥2 neighbors flag a node,
it's quarantined. Traffic reroutes through healthy nodes.
Quarantined nodes can heal through re-attestation.

Trade Secret — InFill Systems, LLC.
"""

from bedrock.mesh.detector import AttackDetector
from bedrock.mesh.state_machine import MeshStateMachine
from bedrock.mesh.router import MeshRouter

__all__ = [
    "AttackDetector",
    "MeshStateMachine",
    "MeshRouter",
]