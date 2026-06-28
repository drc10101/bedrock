"""
Bedrock Identity Fabric.

Node registration, attestation, certificate lifecycle, and capability scoping.
Every node on the network is a cryptographic identity.

SPDX-License-Identifier: BSL-1.1 — See LICENSE for details.
"""

from bedrock.identity.attestation import (
    AttestationClaim,
    AttestationManager,
    AttestationPolicy,
    AttestationResult,
    AttestationStatus,
    BaselineEntry,
    compute_state_hash,
)
from bedrock.identity.capabilities import CapabilityScope, DataCategory
from bedrock.identity.certificates import (
    NODE_LIMITS,
    Certificate,
    CertificateManager,
    CertificateStatus,
    LicenseExceededError,
    LicenseTier,
)
from bedrock.identity.node import Node, NodeID, NodeState
from bedrock.identity.registration import NodeRegistry, RegistrationError, StateTransitionError

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
    "CertificateManager",
    "Certificate",
    "CertificateStatus",
    "LicenseTier",
    "LicenseExceededError",
    "NODE_LIMITS",
    "CapabilityScope",
    "DataCategory",
]
