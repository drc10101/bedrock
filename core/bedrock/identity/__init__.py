"""
Bedrock Identity Fabric.

Node registration, attestation, certificate lifecycle, and capability scoping.
Every node on the network is a cryptographic identity.

Trade Secret — InFill Systems, LLC.
"""

from bedrock.identity.node import Node, NodeID, NodeState
from bedrock.identity.registration import NodeRegistry, RegistrationError, StateTransitionError
from bedrock.identity.attestation import (
    AttestationManager, AttestationClaim, AttestationResult,
    AttestationStatus, AttestationPolicy, BaselineEntry, compute_state_hash,
)
from bedrock.identity.capabilities import CapabilityScope, DataCategory

__all__ = [
    "Node",
    "NodeID",
    "NodeState",
    "NodeRegistry",
    "RegistrationError",
    "StateTransitionError",
    "AttestationManager",
    "AttestationClaim",
    "AttestationResult",
    "AttestationStatus",
    "AttestationPolicy",
    "BaselineEntry",
    "compute_state_hash",
    "CapabilityScope",
    "DataCategory",
]