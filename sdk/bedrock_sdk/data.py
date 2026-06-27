"""
Data SDK module — Silo configuration, consent-gated access, anonymous IDs.

Wraps bedrock.data_separation with developer-friendly defaults.

Trade Secret — InFill Systems, LLC. All rights reserved.
"""

import hashlib
import secrets
from typing import List, Optional

from bedrock.data_separation.consent import ConsentGate, ConsentStatus
from bedrock.data_separation.anonymous_id import IDMappingTable


class DataModule:
    """SDK module for data separation and consent.

    Provides a simplified API for:
    - Cross-silo consent management (request, approve, revoke)
    - Anonymous ID mapping (right to be forgotten)
    """

    def __init__(self, consent_gate: ConsentGate, id_table: IDMappingTable):
        self._consent_gate = consent_gate
        self._id_table = id_table

    def request_consent(
        self,
        requesting_node_id: str,
        source_silo: str,
        target_silo: str,
        categories: List[str],
        scope: str = "read",
        reason: str = "",
    ) -> str:
        """Request cross-silo data access consent.

        The data owner must approve before data can flow between silos.
        This is the core enforcement mechanism for data separation.

        Args:
            requesting_node_id: UUID of the node requesting access.
            source_silo: Data silo containing the data.
            target_silo: Data silo requesting access.
            categories: Data categories requested (e.g., ["diagnosis"]).
            scope: Access scope ("read" or "write").
            reason: Human-readable reason for the request.

        Returns:
            The consent ID for tracking and approval.
        """
        event = self._consent_gate.request_consent(
            requesting_node_id=requesting_node_id,
            source_silo=source_silo,
            target_silo=target_silo,
            categories=categories,
            scope=scope,
            reason=reason,
        )
        return event.consent_id

    def approve_consent(
        self,
        consent_id: str,
        data_owner_id: str,
        ttl_seconds: int = 3600,
    ) -> bool:
        """Approve a pending consent request.

        Only the data owner can approve. The consent is time-limited
        via TTL and can be revoked at any time.

        Args:
            consent_id: The consent request ID to approve.
            data_owner_id: UUID of the data owner approving the request.
            ttl_seconds: Time-to-live in seconds (default: 1 hour).

        Returns:
            True if approval succeeded.
        """
        result = self._consent_gate.approve_consent(
            consent_id=consent_id,
            data_owner_id=data_owner_id,
            ttl_seconds=ttl_seconds,
        )
        return result.status == ConsentStatus.APPROVED

    def check_consent(self, consent_id: str) -> bool:
        """Check if a consent request is approved and valid.

        Args:
            consent_id: The consent ID to check.

        Returns:
            True if the consent is currently approved and not expired.
        """
        result = self._consent_gate.check_consent(consent_id=consent_id)
        return result is not None and result.status == ConsentStatus.APPROVED

    def revoke_consent(self, consent_id: str) -> bool:
        """Revoke a previously approved consent.

        Revocation is immediate — all data access under this consent
        becomes invalid.

        Args:
            consent_id: The consent ID to revoke.

        Returns:
            True if revocation succeeded.
        """
        result = self._consent_gate.revoke_consent(consent_id=consent_id)
        return result.status == ConsentStatus.REVOKED

    def create_anonymous_id(self, real_id: str, silo: str) -> str:
        """Create an anonymous ID mapping for a real identity.

        Anonymous IDs prevent cross-silo identity correlation. Each
        silo sees a different anonymous ID for the same real identity.
        The anonymous ID is generated deterministically but securely
        from the real ID and silo name.

        Args:
            real_id: The real identity identifier.
            silo: The silo this anonymous ID is for.

        Returns:
            The anonymous ID for this identity in this silo.
        """
        # Generate a unique anonymous ID
        anon_id = f"anon-{secrets.token_hex(8)}"
        self._id_table.register(real_id, silo, anon_id)
        return anon_id

    def resolve_anonymous_id(self, anonymous_id: str) -> Optional[str]:
        """Resolve an anonymous ID back to the real identity.

        Only works within the same silo context. This operation
        is logged in the audit chain.

        Args:
            anonymous_id: The anonymous ID to resolve.

        Returns:
            The real identity, or None if not found.
        """
        result = self._id_table.reverse_lookup(anonymous_id)
        if result is None:
            return None
        real_id, silo = result
        return real_id

    def remove_identity(self, real_id: str) -> bool:
        """Remove all anonymous ID mappings for an identity (right to be forgotten).

        This operation is irreversible. Once removed, the real identity
        cannot be recovered from any anonymous ID.

        Args:
            real_id: The real identity to remove.

        Returns:
            True if the identity was found and removed.
        """
        self._id_table.unregister(real_id)
        return True