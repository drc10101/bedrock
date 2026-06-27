"""
Transport SDK module — TLS config, E2EE messaging, mesh networking.

Wraps bedrock.transport and bedrock.mesh with developer-friendly defaults.

Trade Secret — InFill Systems, LLC. All rights reserved.
"""

from typing import List, Optional

from bedrock.transport.security import (
    TransportLayer, TLSConfig, TLSVersion, DowngradeStatus,
    RateLimitConfig, RateLimitResult,
)
from bedrock.mesh.healing import SelfHealingMesh
from bedrock.mesh.detector import SignalType
from bedrock.identity.node import Node, NodeID, NodeState
from bedrock.identity.capabilities import CapabilityScope, DataCategory


class TransportModule:
    """SDK module for transport and mesh networking.

    Provides a simplified API for:
    - TLS configuration and downgrade detection
    - Rate limiting
    - Self-healing mesh operations (flag nodes, consensus, healing)
    - Mesh routing with capability-scope awareness
    """

    def __init__(self, transport: TransportLayer, mesh: SelfHealingMesh):
        self._transport = transport
        self._mesh = mesh

    def configure_tls(
        self,
        mode: str = "developer",
        cert_path: str = "",
        key_path: str = "",
        ca_cert_path: str = "",
    ) -> TLSConfig:
        """Configure TLS for the transport layer.

        Args:
            mode: "developer" (TLS 1.2 minimum, self-signed) or "production"
                (TLS 1.3 minimum, CA-signed).
            cert_path: Path to server certificate.
            key_path: Path to server private key.
            ca_cert_path: Path to CA certificate (production only).

        Returns:
            The configured TLSConfig.
        """
        min_version = TLSVersion.TLS_1_2 if mode == "developer" else TLSVersion.TLS_1_3
        return self._transport.configure_tls(
            cert_path=cert_path,
            key_path=key_path,
            ca_cert_path=ca_cert_path,
            min_version=min_version,
            verify_client=(mode == "production"),
        )

    def detect_downgrade(self, headers: dict) -> str:
        """Detect TLS downgrade attacks from request headers.

        Checks for:
        - x-forwarded-proto indicating plain HTTP
        - x-tls-version below configured minimum

        Args:
            headers: HTTP request headers (use lowercase keys).

        Returns:
            "secure", "downgrade", or "unknown".
        """
        status = self._transport.detect_downgrade(headers)
        return status.value

    def check_rate_limit(self, key: str) -> str:
        """Check rate limit for a node or IP.

        Args:
            key: Node UUID or IP address.

        Returns:
            "allowed", "throttled", or "blocked".
        """
        result = self._transport.check_rate_limit(key)
        return result.value

    def register_mesh_node(
        self,
        name: str,
        categories: Optional[List[str]] = None,
    ) -> Node:
        """Register a new node in the mesh network.

        Args:
            name: Human-readable node name.
            categories: Data categories this node can handle.

        Returns:
            The newly registered Node.
        """
        node = Node(
            node_id=NodeID.generate(),
            name=name,
            state=NodeState.ACTIVE,
        )
        scope = None
        if categories:
            data_cats = [DataCategory(c) for c in categories]
            scope = CapabilityScope(
                node_id=node.node_id.uuid,
                categories=data_cats,
            )
        self._mesh.register_node(node, scope)
        return node

    def flag_node(
        self,
        source_id: str,
        target_id: str,
        signal_type: str,
        details: Optional[dict] = None,
    ) -> None:
        """Flag a node for suspicious behavior in the mesh.

        When enough observers flag a node (≥ consensus_threshold),
        the mesh initiates isolation procedures.

        Args:
            source_id: UUID of the observing node.
            target_id: UUID of the node being flagged.
            signal_type: Type of attack signal detected.
                One of: "credential_stuffing", "unusual_volume",
                "port_scan", "brute_force", "privilege_escalation",
                "attestation_failure", "silent_node", "man_in_the_middle".
            details: Optional dict with additional context.
        """
        signal = SignalType(signal_type)
        self._mesh.flag_node(source_id, target_id, signal, details=details)

    def check_consensus(self, node_id: str) -> bool:
        """Check if enough observers have flagged a node for isolation.

        Args:
            node_id: UUID of the node to check.

        Returns:
            True if consensus threshold is reached.
        """
        return self._mesh.check_consensus(node_id)

    def process_flags(self) -> List[str]:
        """Process pending flags and transition node states.

        Nodes with sufficient flags transition from ACTIVE to SUSPECT.
        Suspect nodes with additional flags transition to QUARANTINED.

        Returns:
            List of node UUIDs that were quarantined.
        """
        return self._mesh.process_flags()

    def begin_healing(self, node_id: str, reason: str = "") -> dict:
        """Begin healing a quarantined node.

        Transitions QUARANTINED → HEALING. The node must pass
        re-attestation before it can return to ACTIVE.

        Args:
            node_id: UUID of the node to heal.
            reason: Reason for initiating healing.

        Returns:
            Dict with "success", "reason", and "new_state" keys.
        """
        result = self._mesh.begin_healing(node_id, reason=reason)
        return {
            "success": result.success,
            "reason": result.reason,
            "new_state": result.new_state.value,
        }

    def complete_healing(self, node_id: str) -> dict:
        """Complete healing and restore a node to ACTIVE.

        Only works after the healing period has elapsed and no new
        flags have been raised during healing.

        Args:
            node_id: UUID of the node to restore.

        Returns:
            Dict with "success", "reason", and "new_state" keys.
        """
        result = self._mesh.complete_healing(node_id)
        return {
            "success": result.success,
            "reason": result.reason,
            "new_state": result.new_state.value,
        }

    def reroute(
        self,
        source_id: str,
        destination_id: str,
        categories: List[str],
    ) -> List[str]:
        """Find an alternate path that avoids quarantined nodes.

        Args:
            source_id: UUID of the source node.
            destination_id: UUID of the destination node.
            categories: Data categories the path must support.

        Returns:
            Ordered list of node UUIDs forming the path.
        """
        data_categories = [DataCategory(c) for c in categories]
        return self._mesh.reroute(source_id, destination_id, data_categories)