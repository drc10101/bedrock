"""
Identity SDK module — Node registration, certificates, capability scoping.

Wraps bedrock.identity with developer-friendly defaults.

Trade Secret — InFill Systems, LLC. All rights reserved.
"""

from typing import List, Optional

from bedrock.identity.node import Node, NodeID, NodeState
from bedrock.identity.registration import NodeRegistry
from bedrock.identity.certificates import (
    Certificate, CertificateManager, CertificateStatus, LicenseTier,
)
from bedrock.identity.attestation import AttestationManager
from bedrock.identity.capabilities import CapabilityScope, DataCategory


class IdentityModule:
    """SDK module for identity management.

    Provides a simplified API for:
    - Node registration and identity management
    - Certificate lifecycle (issue, renew, revoke)
    - Capability scoping (what a node can access)
    - Attestation baselines
    """

    def __init__(
        self,
        registry: NodeRegistry,
        cert_manager: CertificateManager,
        attestation: AttestationManager,
        mode: str = "developer",
    ):
        self._registry = registry
        self._cert_manager = cert_manager
        self._attestation = attestation
        self._mode = mode

    def register(self, name: str) -> Node:
        """Register a new node in the Bedrock network.

        Args:
            name: Human-readable node name (e.g., "patient-api-server").

        Returns:
            The newly registered Node with a cryptographic identity.

        Raises:
            RegistrationError: If registration fails (e.g., license limit).
        """
        return self._registry.register(name=name)

    def unregister(self, node_id: str) -> bool:
        """Remove a node (right to be forgotten).

        Permanently removes the node's identity from the registry.
        All data encrypted under this identity becomes unrecoverable.

        Args:
            node_id: The UUID of the node to unregister.

        Returns:
            True if the node was found and removed.
        """
        node = self._registry.get(node_id)
        if node is None:
            return False
        self._registry.unregister(node_id)
        return True

    def get(self, node_id: str) -> Optional[Node]:
        """Look up a node by its UUID.

        Args:
            node_id: The UUID of the node.

        Returns:
            The Node object, or None if not found.
        """
        return self._registry.get(node_id)

    def issue_certificate(
        self,
        node_uuid: str,
        node_name: str,
        public_key_hash: str,
    ) -> Certificate:
        """Issue a certificate for a node.

        In developer mode, certificates are self-signed with 24-hour TTL.
        In production mode, certificates are CA-signed with configurable TTL.

        Args:
            node_uuid: The node's UUID.
            node_name: The node's human-readable name.
            public_key_hash: SHA-256 hash of the node's public key.

        Returns:
            The issued Certificate.

        Raises:
            LicenseExceededError: If the license tier's node limit is reached.
        """
        return self._cert_manager.issue_certificate(
            node_uuid=node_uuid,
            node_name=node_name,
            public_key_hash=public_key_hash,
        )

    def revoke_certificate(self, node_uuid: str, reason: str = "") -> Certificate:
        """Revoke a node's certificate immediately.

        Used when a node is quarantined by the Self-Healing Mesh.
        The serial number is added to the CRL for distribution.

        Args:
            node_uuid: The node whose certificate to revoke.
            reason: Reason for revocation.

        Returns:
            The revoked Certificate with updated status.
        """
        return self._cert_manager.revoke_certificate(
            node_uuid=node_uuid,
            reason=reason,
        )

    def register_baseline(
        self,
        node_type: str,
        version: str,
        baseline_hash: str,
    ) -> None:
        """Register an attestation baseline for a node type.

        Baselines define the known-good state that nodes must match
        during boot-time attestation.

        Args:
            node_type: The node type identifier (e.g., "edge-gateway").
            version: Software version string (e.g., "1.0.0").
            baseline_hash: SHA-256 hash of the expected binary state.
        """
        self._attestation.register_baseline(
            node_type=node_type,
            version=version,
            baseline_hash=baseline_hash,
        )

    def create_scope(
        self,
        node_id: str,
        categories: List[str],
    ) -> CapabilityScope:
        """Create a capability scope for a node.

        Scopes define what categories of data a node can access.
        This is the enforcement mechanism for data separation.

        Args:
            node_id: The node's UUID.
            categories: List of DataCategory values (e.g., ["IDENTITY", "MEDICAL"]).

        Returns:
            A CapabilityScope bound to the node.
        """
        data_categories = [DataCategory(c) for c in categories]
        return CapabilityScope(node_id=node_id, categories=data_categories)