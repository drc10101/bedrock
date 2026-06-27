"""
Consent-gated cross-silo access.

Data does not flow between silos without explicit, time-limited consent
from the data owner. This is the PIR/ePRR pattern generalized.
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional
from enum import Enum


class ConsentStatus(Enum):
    PENDING = "pending"
    APPROVED = "approved"
    DENIED = "denied"
    EXPIRED = "expired"
    REVOKED = "revoked"


@dataclass
class ConsentEvent:
    """An explicit, time-limited approval from a data owner for scoped data access.

    Pattern from InFill: Patient approves medical record request (ePRR) and
    personal info request (PIR) separately. In Bedrock, this generalizes to
    any data owner approving any scoped data access.
    """
    consent_id: str
    data_owner_id: str          # Anonymous ID of the data owner
    requesting_node_id: str     # Node requesting access
    source_silo: str            # Silo being requested
    target_silo: str            # Silo requesting the data
    categories: list            # Specific data categories approved
    scope: str                  # "read", "write", "consent"
    status: ConsentStatus = ConsentStatus.PENDING
    reason: str = ""
    approved_at: Optional[datetime] = None
    expires_at: Optional[datetime] = None
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def is_valid(self) -> bool:
        """Check if this consent event is currently valid."""
        if self.status != ConsentStatus.APPROVED:
            return False
        if self.expires_at and datetime.now(timezone.utc) > self.expires_at:
            return False
        return True


class ConsentGate:
    """Manages consent-gated cross-silo data access.

    The data owner must explicitly approve. No cross-silo access without consent.
    """

    def request_consent(self, requesting_node_id: str, source_silo: str,
                        target_silo: str, categories: list, reason: str) -> ConsentEvent:
        """Request consent for cross-silo data access."""
        raise NotImplementedError("B-104: Data Separation Layer")

    def approve_consent(self, consent_id: str, data_owner_id: str,
                        ttl_seconds: int = 3600) -> ConsentEvent:
        """Data owner approves a consent request with a time limit."""
        raise NotImplementedError("B-104: Data Separation Layer")

    def deny_consent(self, consent_id: str, data_owner_id: str,
                     reason: str = "") -> ConsentEvent:
        """Data owner denies a consent request."""
        raise NotImplementedError("B-104: Data Separation Layer")

    def check_consent(self, consent_id: str) -> Optional[ConsentEvent]:
        """Check if a consent event is valid (approved and not expired)."""
        raise NotImplementedError("B-104: Data Separation Layer")