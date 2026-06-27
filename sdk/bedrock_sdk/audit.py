"""
Audit SDK module — Write events, verify integrity, export for compliance.

Wraps bedrock.audit.chain with developer-friendly defaults.

Trade Secret — InFill Systems, LLC. All rights reserved.
"""

from typing import List, Optional, Dict

from bedrock.audit.chain import AuditChain


class AuditModule:
    """SDK module for audit chain operations.

    Provides a simplified API for:
    - Logging events to the tamper-evident audit chain
    - Verifying chain integrity
    - Querying events by action, actor, or silo
    - Exporting for compliance
    """

    def __init__(self, chain: AuditChain):
        self._chain = chain

    def log(
        self,
        action: str,
        actor_id: str,
        target_id: str,
        silo: str,
        details: Optional[Dict] = None,
    ) -> str:
        """Log an event to the audit chain.

        Every meaningful operation in Bedrock should be logged:
        node registration, encryption, consent changes, data access,
        certificate lifecycle, mesh events, etc.

        The chain is tamper-evident — each entry's hash includes the
        previous entry's hash, forming a linked chain. Any modification
        breaks verification.

        Args:
            action: What happened. Use dot notation (e.g., "field.encrypt",
                "consent.approve", "node.register").
            actor_id: Who did it (node UUID or user ID).
            target_id: What was acted upon (record ID, node UUID, etc.).
            silo: Which data silo this relates to.
            details: Optional dict with additional context.

        Returns:
            The entry hash for reference.
        """
        entry = self._chain.append(
            action=action,
            actor_id=actor_id,
            target_id=target_id,
            silo=silo,
            details=details,
        )
        return entry.entry_hash

    def verify(self) -> bool:
        """Verify the entire audit chain integrity.

        Checks that every entry's hash is consistent with the previous
        entry's hash. Any tampering, deletion, or insertion breaks the
        chain.

        Returns:
            True if the chain is intact and unmodified.
        """
        return self._chain.verify()

    def query(
        self,
        action: Optional[str] = None,
        actor_id: Optional[str] = None,
        silo: Optional[str] = None,
        limit: int = 100,
    ) -> List[Dict]:
        """Query audit entries by action, actor, or silo.

        Args:
            action: Filter by action type (e.g., "field.encrypt").
            actor_id: Filter by actor UUID.
            silo: Filter by data silo.
            limit: Maximum entries to return (default: 100).

        Returns:
            List of matching entries as dicts.
        """
        entries = self._chain.query(
            action=action,
            actor_id=actor_id,
            silo=silo,
            limit=limit,
        )

        return [
            {
                "timestamp": e.timestamp.isoformat(),
                "action": e.action,
                "actor_id": e.actor_id,
                "target_id": e.target_id,
                "silo": e.silo,
                "details": e.details,
                "hash": e.entry_hash,
            }
            for e in entries
        ]

    def export_chain(self) -> str:
        """Export the entire audit chain for compliance.

        Returns:
            JSONL string of all chain entries.
        """
        return self._chain.export()

    def head_hash(self) -> str:
        """Get the current head hash of the chain.

        Useful for verifying chain continuity across distributed nodes.

        Returns:
            The SHA-256 hex hash of the most recent entry.
        """
        return self._chain.head_hash

    def tail_hash(self) -> str:
        """Get the genesis hash of the chain.

        Returns:
            The SHA-256 hex hash of the first entry.
        """
        return self._chain.tail_hash