"""
Audit chain — SHA-256 hash chain logging.

Each entry includes the hash of the previous entry, creating a
tamper-evident chain. Any modification to a past entry invalidates
all subsequent hashes.

6-year retention. Exportable for compliance (HIPAA, SOC 2, PCI-DSS).
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional


@dataclass
class AuditEntry:
    """A single entry in the audit chain.

    Hash = SHA-256(prev_hash + entry_data)
    """
    timestamp: datetime
    action: str          # e.g., "node.register", "field.encrypt", "consent.approve"
    actor_id: str        # Node ID or user ID that performed the action
    target_id: str       # What was acted upon (record ID, node ID, etc.)
    silo: str            # Which silo this action relates to
    details: dict = field(default_factory=dict)  # Arbitrary key-value details
    prev_hash: str = ""  # SHA-256 hash of the previous entry
    entry_hash: str = "" # SHA-256 hash of this entry (computed on append)


class AuditChain:
    """Append-only SHA-256 hash chain.

    Verification: re-hash every entry and confirm the chain is unbroken.
    Tamper detection: any modified entry breaks all subsequent hashes.
    """

    def append(self, action: str, actor_id: str, target_id: str,
               silo: str, details: dict = None) -> AuditEntry:
        """Append a new entry to the audit chain."""
        raise NotImplementedError("B-108: Audit Chain")

    def verify(self) -> bool:
        """Verify the entire chain is unbroken. Returns True if valid."""
        raise NotImplementedError("B-108: Audit Chain")

    def export(self, start_date: Optional[datetime] = None,
               end_date: Optional[datetime] = None,
               format: str = "jsonl") -> str:
        """Export audit chain entries for compliance."""
        raise NotImplementedError("B-108: Audit Chain")