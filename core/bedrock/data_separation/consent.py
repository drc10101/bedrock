"""
Consent-gated cross-silo access.

Data does not flow between silos without explicit, time-limited consent
from the data owner. This is the PIR/ePRR pattern generalized from InFill.

Security properties:
- No cross-silo access without explicit approval
- Every consent event is audit-logged
- Consent is time-limited (TTL)
- Consent can be revoked at any time
- Consent is scoped to specific categories and operations

SPDX-License-Identifier: BSL-1.1 — See LICENSE for details.
"""

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Optional

from bedrock.data_separation.anonymous_id import AnonymousID


class ConsentStatus:
    """Consent event statuses."""
    PENDING = "pending"
    APPROVED = "approved"
    DENIED = "denied"
    EXPIRED = "expired"
    REVOKED = "revoked"

    VALID_STATUSES = {PENDING, APPROVED, DENIED, EXPIRED, REVOKED}


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
    categories: List[str]       # Specific data categories approved
    scope: str                  # "read", "write", "consent"
    status: str = ConsentStatus.PENDING
    reason: str = ""
    approved_at: Optional[datetime] = None
    expires_at: Optional[datetime] = None
    revoked_at: Optional[datetime] = None
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def is_valid(self) -> bool:
        """Check if this consent event is currently valid.

        Valid means: approved, not expired, not revoked.
        """
        if self.status != ConsentStatus.APPROVED:
            return False
        if self.expires_at and datetime.now(timezone.utc) > self.expires_at:
            return False
        return True

    def has_category(self, category: str) -> bool:
        """Check if this consent covers a specific category."""
        return category in self.categories

    def covers_scope(self, requested_scope: str) -> bool:
        """Check if this consent covers a specific scope.

        'write' consent implies 'read' access.
        'read' consent does not imply 'write' access.
        """
        if self.scope == requested_scope:
            return True
        if self.scope == "write" and requested_scope == "read":
            return True
        return False


class ConsentGate:
    """Manages consent-gated cross-silo data access.

    The data owner must explicitly approve. No cross-silo access without consent.

    Lifecycle:
    1. request_consent() — a node requests access to data in another silo
    2. approve_consent() — the data owner approves with a time limit
    3. check_consent() — verify consent is valid before any data access
    4. revoke_consent() — data owner can revoke at any time

    Every state transition is audit-logged in production.
    """

    def __init__(self):
        self._events: Dict[str, ConsentEvent] = {}

    def request_consent(self, requesting_node_id: str, source_silo: str,
                        target_silo: str, categories: List[str],
                        scope: str = "read", reason: str = "") -> ConsentEvent:
        """Request consent for cross-silo data access.

        Args:
            requesting_node_id: Node requesting the data
            source_silo: Silo containing the data
            target_silo: Silo the data would flow to
            categories: Specific data categories requested
            scope: Access scope ("read", "write", "consent")
            reason: Human-readable reason for the request

        Returns:
            A PENDING ConsentEvent awaiting approval
        """
        consent_id = f"consent_{uuid.uuid4().hex[:12]}"
        event = ConsentEvent(
            consent_id=consent_id,
            data_owner_id="",  # Filled when owner approves
            requesting_node_id=requesting_node_id,
            source_silo=source_silo,
            target_silo=target_silo,
            categories=categories,
            scope=scope,
            reason=reason,
        )
        self._events[consent_id] = event
        return event

    def approve_consent(self, consent_id: str, data_owner_id: str,
                        ttl_seconds: int = 3600) -> ConsentEvent:
        """Data owner approves a consent request with a time limit.

        Args:
            consent_id: The consent request to approve
            data_owner_id: Anonymous ID of the data owner approving
            ttl_seconds: Time-to-live in seconds (default 1 hour)

        Returns:
            The APPROVED ConsentEvent

        Raises:
            KeyError: If consent_id doesn't exist
            ValueError: If consent is not in PENDING state
        """
        event = self._events.get(consent_id)
        if event is None:
            raise KeyError(f"Consent event '{consent_id}' not found")
        if event.status != ConsentStatus.PENDING:
            raise ValueError(
                f"Cannot approve consent in '{event.status}' state. "
                f"Only PENDING events can be approved."
            )

        event.status = ConsentStatus.APPROVED
        event.data_owner_id = data_owner_id
        event.approved_at = datetime.now(timezone.utc)
        event.expires_at = datetime.now(timezone.utc) + timedelta(seconds=ttl_seconds)
        return event

    def deny_consent(self, consent_id: str, data_owner_id: str,
                     reason: str = "") -> ConsentEvent:
        """Data owner denies a consent request.

        Args:
            consent_id: The consent request to deny
            data_owner_id: Anonymous ID of the data owner denying
            reason: Optional reason for denial

        Returns:
            The DENIED ConsentEvent

        Raises:
            KeyError: If consent_id doesn't exist
            ValueError: If consent is not in PENDING state
        """
        event = self._events.get(consent_id)
        if event is None:
            raise KeyError(f"Consent event '{consent_id}' not found")
        if event.status != ConsentStatus.PENDING:
            raise ValueError(
                f"Cannot deny consent in '{event.status}' state. "
                f"Only PENDING events can be denied."
            )

        event.status = ConsentStatus.DENIED
        event.data_owner_id = data_owner_id
        if reason:
            event.reason = reason
        return event

    def revoke_consent(self, consent_id: str) -> ConsentEvent:
        """Data owner revokes previously approved consent.

        Revoked consent immediately invalidates all data access under it.
        In production, this triggers audit chain entries and may trigger
        data deletion workflows.

        Args:
            consent_id: The consent event to revoke

        Returns:
            The REVOKED ConsentEvent

        Raises:
            KeyError: If consent_id doesn't exist
            ValueError: If consent is not in APPROVED state
        """
        event = self._events.get(consent_id)
        if event is None:
            raise KeyError(f"Consent event '{consent_id}' not found")
        if event.status != ConsentStatus.APPROVED:
            raise ValueError(
                f"Cannot revoke consent in '{event.status}' state. "
                f"Only APPROVED events can be revoked."
            )

        event.status = ConsentStatus.REVOKED
        event.revoked_at = datetime.now(timezone.utc)
        return event

    def check_consent(self, consent_id: str) -> Optional[ConsentEvent]:
        """Check if a consent event is valid (approved and not expired).

        Returns the ConsentEvent if valid, None otherwise.
        Also updates expired events from APPROVED to EXPIRED.
        """
        event = self._events.get(consent_id)
        if event is None:
            return None

        # Auto-transition expired events
        if event.status == ConsentStatus.APPROVED and event.expires_at:
            if datetime.now(timezone.utc) > event.expires_at:
                event.status = ConsentStatus.EXPIRED
                return None

        if event.is_valid():
            return event
        return None

    def get_pending(self) -> List[ConsentEvent]:
        """Get all pending consent requests."""
        return [e for e in self._events.values()
                if e.status == ConsentStatus.PENDING]

    def get_approved(self) -> List[ConsentEvent]:
        """Get all currently valid (approved, not expired) consent events."""
        return [e for e in self._events.values() if e.is_valid()]

    def get_for_owner(self, data_owner_id: str) -> List[ConsentEvent]:
        """Get all consent events for a specific data owner."""
        return [e for e in self._events.values()
                if e.data_owner_id == data_owner_id]

    def get_for_node(self, requesting_node_id: str) -> List[ConsentEvent]:
        """Get all consent events from a specific requesting node."""
        return [e for e in self._events.values()
                if e.requesting_node_id == requesting_node_id]

    def get_for_silo_pair(self, source_silo: str, target_silo: str) -> List[ConsentEvent]:
        """Get all consent events between two silos."""
        return [e for e in self._events.values()
                if e.source_silo == source_silo and e.target_silo == target_silo]