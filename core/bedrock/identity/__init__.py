"""
Bedrock Identity Fabric.

Node registration, attestation, certificate lifecycle, and capability scoping.
Every node on the network is a cryptographic identity.

Trade Secret — InFill Systems, LLC.
"""

from bedrock.identity.node import Node, NodeID
from bedrock.identity.attestation import AttestationManager
from bedrock.identity.certificates import CertificateManager
from bedrock.identity.capabilities import CapabilityScope

__all__ = [
    "Node",
    "NodeID",
    "AttestationManager",
    "CertificateManager",
    "CapabilityScope",
]